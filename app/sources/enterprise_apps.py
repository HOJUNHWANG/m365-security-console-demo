import asyncio
import os
from datetime import datetime, timezone

from ..graph_client import graph_get
from .. import signin_cache
from ._i18n import finding

BETA = "https://graph.microsoft.com/beta"

MS_TENANTS = {
    "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
    "72f988bf-86f1-41af-91ab-2d7cd011db47",
    "cdc5aeea-15c5-4db6-b079-fcadd2505dc2",
}
MS_PUBLISHER = "Microsoft Corporation"

OWN_TENANT = os.environ.get("TENANT_ID", "")

LOGIN_SCOPES = {"openid", "profile", "email", "offline_access", "User.Read"}

DATA_SCOPE_PREFIXES = (
    "Mail.", "Files.", "Sites.", "AllSites.", "MyFiles.", "Directory.", "Chat.", "ChannelMessage.",
    "Channel.", "Notes.", "Contacts.", "Calendars.", "OnlineMeeting", "MailboxItem.",
    "MailboxFolder.", "MailboxSettings.", "eDiscovery.", "User.ReadWrite", "User.Read.All",
    "User.ReadBasic.All", "Group.", "Application.", "RoleManagement.", "Policy.",
    "UserAuthenticationMethod.", "BitlockerKey.", "Device.", "DeviceManagement",
)

LEGACY_PROTOCOL_SCOPES = {
    "EAS.AccessAsUser.All", "EWS.AccessAsUser.All", "IMAP.AccessAsUser.All",
    "POP.AccessAsUser.All", "SMTP.Send",
}

WRITE_MARKERS = ("ReadWrite", "FullControl", "full_access", "ManageAsApp", "ManageIdentities",
                 "Impersonation", ".Write", ".Create", ".Delete")
READ_MARKERS = (".Read.All", ".ReadBasic", ".Read.Shared")

UNUSED_DAYS = int(os.environ.get("APP_UNUSED_DAYS", "7"))

GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"


def _now():
    return datetime.now(timezone.utc)


def _parse(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


def _age_days(ts):
    d = _parse(ts)
    return None if d is None else max((_now() - d).days, 0)


def _is_data_scope(s):
    return s not in LOGIN_SCOPES and any(s.startswith(p) for p in DATA_SCOPE_PREFIXES)


def _owner(sp):
    o = sp.get("appOwnerOrganizationId")
    if o in MS_TENANTS or (sp.get("verifiedPublisher") or {}).get("displayName") == MS_PUBLISHER:
        return "microsoft"
    if o == OWN_TENANT:
        return "own"
    return "thirdParty"


def _is_write(name: str) -> bool:
    if not name:
        return False
    if any(m in name for m in READ_MARKERS) or name.endswith(".Read"):
        return "ReadWrite" in name
    return any(m in name for m in WRITE_MARKERS)


def _writes(names):
    return sorted({n for n in names if _is_write(n)})


async def _pages(path, params=None):
    out = []
    d = await graph_get(path, params=params)
    while True:
        out.extend(d.get("value", []))
        nxt = d.get("@odata.nextLink")
        if not nxt:
            return out
        d = await graph_get(nxt)


async def _no_permission_request(rows) -> set:
    inert = set()
    for a in rows:
        app_id = a.get("appId")
        if not app_id:
            continue
        try:
            apps = await _pages("/applications", {
                "$filter": f"appId eq '{app_id}'",
                "$select": "id,appId,requiredResourceAccess"})
        except Exception:
            continue
        if len(apps) != 1:
            continue
        if not (apps[0].get("requiredResourceAccess") or []):
            inert.add(a["id"])
    return inert


async def _pending_requests():
    try:
        reqs = await _pages(f"{BETA}/identityGovernance/appConsent/appConsentRequests")
    except Exception:
        return None
    out = []
    for r in reqs:
        item = {"appId": r.get("appId"), "appDisplayName": r.get("appDisplayName"),
                "id": r.get("id"), "requesters": []}
        try:
            urs = await _pages(f"{BETA}/identityGovernance/appConsent/appConsentRequests/"
                               f"{r['id']}/userConsentRequests")
        except Exception:
            urs = []
        for u in urs:
            created = u.get("createdDateTime")
            item["requesters"].append({
                "status": u.get("status"),
                "reason": u.get("reason"),
                "createdDateTime": created,
                "ageDays": _age_days(created),
            })
        ages = [x["ageDays"] for x in item["requesters"] if x["ageDays"] is not None]
        item["ageDays"] = max(ages) if ages else None
        item["openCount"] = len([x for x in item["requesters"]
                                 if (x["status"] or "").lower() == "inprogress"])
        out.append(item)
    return out


async def _resource_roles(resource_id, cache, sem):
    if resource_id in cache:
        return cache[resource_id]
    async with sem:
        try:
            d = await graph_get(f"/servicePrincipals/{resource_id}",
                                params={"$select": "displayName,appRoles"})
            cache[resource_id] = {r["id"]: (r.get("value") or r.get("displayName"))
                                  for r in d.get("appRoles", [])}
        except Exception:
            cache[resource_id] = {}
    return cache[resource_id]


async def _app_only(sp_id, cache, sem):
    async with sem:
        try:
            v = (await graph_get(f"/servicePrincipals/{sp_id}/appRoleAssignments")).get("value", [])
        except Exception:
            return None
    out, unresolved = [], 0
    for a in v:
        names = await _resource_roles(a.get("resourceId"), cache, sem)
        name = names.get(a.get("appRoleId"))
        if not name:
            name = f"{a.get('resourceDisplayName') or 'unknown resource'}: (unnamed role)"
            unresolved += 1
        else:
            res = a.get("resourceDisplayName") or ""
            if res and res != "Microsoft Graph":
                name = f"{res}: {name}"
        out.append(name)
    return sorted(out), unresolved


async def fetch() -> dict:
    sps = await _pages("/servicePrincipals", {
        "$select": "id,appId,displayName,appRoleAssignmentRequired,accountEnabled,signInAudience,"
                   "verifiedPublisher,servicePrincipalType,appOwnerOrganizationId,"
                   "preferredSingleSignOnMode,tags",
        "$top": 999})
    by_oid = {s["id"]: s for s in sps}

    grants = await _pages("/oauth2PermissionGrants", {"$top": 999})

    agg = {}
    for g in grants:
        cid = g.get("clientId")
        if not cid:
            continue
        e = agg.setdefault(cid, {"scopes": set(), "allPrincipals": False, "userConsents": 0})
        e["scopes"] |= set((g.get("scope") or "").split())
        if g.get("consentType") == "AllPrincipals":
            e["allPrincipals"] = True
        else:
            e["userConsents"] += 1

    sem = asyncio.Semaphore(6)
    role_cache = {}
    candidates = [s for s in sps if _owner(s) != "microsoft"]
    results = await asyncio.gather(*(_app_only(s["id"], role_cache, sem) for s in candidates))
    app_only, unresolved_total = {}, 0
    for s, res in zip(candidates, results):
        if not res:
            continue
        names, unresolved = res
        if names:
            app_only[s["id"]] = names
            unresolved_total += unresolved

    seen = {}
    signin_window_ok = True
    try:
        signins, _ = await signin_cache.get_interactive()
        for r in signins or []:
            aid = r.get("appId")
            ts = r.get("createdDateTime")
            if aid and ts and (aid not in seen or ts > seen[aid]):
                seen[aid] = ts
    except Exception:
        signin_window_ok = False

    apps = []
    for oid, e in agg.items():
        sp = by_oid.get(oid)
        if not sp:
            continue
        scopes = sorted(e["scopes"])
        data = sorted(s for s in scopes if _is_data_scope(s))
        legacy = sorted(s for s in scopes if s in LEGACY_PROTOCOL_SCOPES)
        gated = bool(sp.get("appRoleAssignmentRequired"))
        owner = _owner(sp)
        last = seen.get(sp.get("appId"))
        apps.append({
            "id": oid,
            "appId": sp.get("appId"),
            "name": sp.get("displayName"),
            "owner": owner,
            "gated": gated,
            "enabled": sp.get("accountEnabled"),
            "allPrincipals": e["allPrincipals"],
            "userConsents": e["userConsents"],
            "signInAudience": sp.get("signInAudience"),
            "personalAccounts": "PersonalMicrosoftAccount" in (sp.get("signInAudience") or ""),
            "publisher": (sp.get("verifiedPublisher") or {}).get("displayName"),
            "scopes": scopes,
            "dataScopes": data,
            "legacyProtocolScopes": legacy,
            "appOnlyPermissions": app_only.get(oid, []),
            "appOnlyWrites": _writes(app_only.get(oid, [])),
            "lastSignIn": last,
        })

    for sp in candidates:
        if sp["id"] in agg or sp["id"] not in app_only:
            continue
        names = app_only[sp["id"]]
        apps.append({
            "id": sp["id"], "appId": sp.get("appId"), "name": sp.get("displayName"),
            "owner": _owner(sp), "gated": bool(sp.get("appRoleAssignmentRequired")),
            "enabled": sp.get("accountEnabled"), "allPrincipals": False, "userConsents": 0,
            "signInAudience": sp.get("signInAudience"),
            "personalAccounts": "PersonalMicrosoftAccount" in (sp.get("signInAudience") or ""),
            "publisher": (sp.get("verifiedPublisher") or {}).get("displayName"),
            "scopes": [], "dataScopes": [], "legacyProtocolScopes": [],
            "appOnlyPermissions": names, "appOnlyWrites": _writes(names),
            "lastSignIn": seen.get(sp.get("appId")),
        })

    sso_modes = {"saml", "password", "oidc"}
    sso = []
    for sp in sps:
        mode = (sp.get("preferredSingleSignOnMode") or "").lower()
        tags = sp.get("tags") or []
        is_sso = mode in sso_modes or any("CustomSingleSignOnApplication" in t for t in tags)
        if not is_sso:
            continue
        oid = sp["id"]
        sso.append({
            "id": oid,
            "appId": sp.get("appId"),
            "name": sp.get("displayName"),
            "owner": _owner(sp),
            "mode": mode or "custom",
            "gated": bool(sp.get("appRoleAssignmentRequired")),
            "enabled": sp.get("accountEnabled"),
            "publisher": (sp.get("verifiedPublisher") or {}).get("displayName"),
            "signInAudience": sp.get("signInAudience"),
            "dataScopes": next((a["dataScopes"] for a in apps if a["id"] == oid), []),
            "inConsentList": any(a["id"] == oid for a in apps),
            "assigned": None,
            "assignedLive": None,
            "lastSignIn": seen.get(sp.get("appId")),
        })

    async def _assigned(row):
        try:
            rows = await _pages(f"/servicePrincipals/{row['id']}/appRoleAssignedTo", {"$top": 999})
        except Exception:
            return
        row["assigned"] = len(rows)
        row["assignedGroups"] = len([r for r in rows if r.get("principalType") == "Group"])

    await asyncio.gather(*[_assigned(r) for r in sso])

    sso_ungated = [a for a in sso if not a["gated"] and a["enabled"]]

    listed_ids = {a["id"] for a in apps} | {a["id"] for a in sso}
    ms_excluded = [sp for sp in sps
                   if _owner(sp) == "microsoft"
                   and sp.get("servicePrincipalType") != "ManagedIdentity"]
    ms_excluded_active = sorted(
        [{"id": sp["id"], "appId": sp.get("appId"), "name": sp.get("displayName"),
          "enabled": bool(sp.get("accountEnabled")),
          "gated": bool(sp.get("appRoleAssignmentRequired")),
          "scopes": sorted(agg[sp["id"]]["scopes"]),
          "allPrincipals": agg[sp["id"]]["allPrincipals"],
          "userConsents": agg[sp["id"]]["userConsents"]}
         for sp in ms_excluded if sp["id"] in agg],
        key=lambda a: (-len(a["scopes"]), (a["name"] or "").lower()))

    nonms_all = [sp for sp in sps
                 if _owner(sp) != "microsoft"
                 and sp.get("servicePrincipalType") != "ManagedIdentity"]
    unconsented_all = [{
        "id": sp["id"],
        "appId": sp.get("appId"),
        "name": sp.get("displayName"),
        "owner": _owner(sp),
        "enabled": bool(sp.get("accountEnabled")),
        "gated": bool(sp.get("appRoleAssignmentRequired")),
        "publisher": (sp.get("verifiedPublisher") or {}).get("displayName"),
        "signInAudience": sp.get("signInAudience"),
        "personalAccounts": "PersonalMicrosoftAccount" in (sp.get("signInAudience") or ""),
        "lastSignIn": seen.get(sp.get("appId")),
    } for sp in sps
        if _owner(sp) != "microsoft"
        and sp.get("servicePrincipalType") != "ManagedIdentity"
        and sp["id"] not in listed_ids]

    unconsented = sorted(
        [a for a in unconsented_all if a["enabled"]],
        key=lambda a: (a["gated"], bool(a["publisher"]), (a["name"] or "").lower()))
    unconsented_off = [a for a in unconsented_all if not a["enabled"]]
    unconsented_open = [a for a in unconsented if not a["gated"]]

    inert_ids = await _no_permission_request(
        [a for a in unconsented_open if a["owner"] == "own"])
    unconsented_inert = [a for a in unconsented_open if a["id"] in inert_ids]
    for a in unconsented_inert:
        a["inert"] = True
        a["inertReason"] = "요청 권한 0 · 동의 0 — 접근 경로 없음 (플랫폼 자동 생성 가능)"
    unconsented_open = [a for a in unconsented_open if a["id"] not in inert_ids]
    unconsented_unverified = [a for a in unconsented_open if not a["publisher"]]

    third = [a for a in apps if a["owner"] == "thirdParty"]

    ungated = [a for a in apps if not a["gated"] and a["enabled"]]
    ungated_tenant = [a for a in ungated if a["allPrincipals"]]

    ungated_data_3p = [a for a in ungated_tenant if a["dataScopes"] and a["owner"] == "thirdParty"]
    ungated_data_own = [a for a in ungated_tenant if a["dataScopes"] and a["owner"] == "own"]

    apponly = [a for a in apps if a["appOnlyPermissions"]]
    apponly_write_3p = [a for a in apponly if a["appOnlyWrites"] and a["owner"] == "thirdParty"]
    legacy_apps = [a for a in apps if a["legacyProtocolScopes"] and a["owner"] != "microsoft"]
    unverified = [a for a in third if not a["publisher"]]
    personal = [a for a in third if a["personalAccounts"]]

    unused = ([a for a in third
               if not a["lastSignIn"] and not a["appOnlyPermissions"] and a["dataScopes"]]
              if signin_window_ok else [])

    pending_all = await _pending_requests()
    if pending_all is None:
        pending, pending_closed = None, None
    else:
        pending = [p for p in pending_all if p.get("openCount")]
        pending_closed = len(pending_all) - len(pending)

    def by_name(rows):
        return sorted(rows, key=lambda a: (a.get("name") or "").lower())

    findings = []

    if unresolved_total:
        findings.append(finding(
            "med",
            en=f"{unresolved_total} application permission(s) could not be resolved to a name even "
               f"after asking the resource that publishes them, so they are not classified as "
               f"reading or writing. An unnamed permission is unknown, not harmless.",
            ko=f"애플리케이션 권한 {unresolved_total}건은 권한을 발행한 리소스에 물어봐도 이름을 "
               f"확인하지 못해 읽기/쓰기로 분류하지 못했습니다. **이름을 모르는 권한은 무해한 것이 "
               f"아니라 알 수 없는 것입니다.**"))

    if sso_ungated:
        names = ", ".join(a["name"] or "?" for a in by_name(sso_ungated))
        findings.append(finding(
            "high",
            en=f"{len(sso_ungated)} single sign-on app(s) have NO assignment gate: {names}. "
               f"An SSO app carries no OAuth scope - what crosses is identity - so its only "
               f"control is the gate. Without it every employee can sign in to that SaaS with "
               f"their work account, and offboarding an account no longer reliably removes "
               f"access on the vendor side.",
            ko=f"SSO 앱 {len(sso_ungated)}개에 **할당 게이트가 없습니다**: {names}. SSO 앱은 "
               f"OAuth 스코프가 없어서 — 넘어가는 것이 데이터가 아니라 신원입니다 — "
               f"**게이트가 유일한 통제 수단입니다.** 없으면 전 직원이 회사 계정으로 그 SaaS 에 "
               f"로그인할 수 있고, 계정을 꺼도 저쪽 접근이 확실히 끊긴다고 말할 수 없게 됩니다."))
    elif sso:
        findings.append(finding(
            "info",
            en=f"{len(sso)} single sign-on app(s) present, all with an assignment gate. "
               f"SSO apps hold no OAuth consent, so a consent-based inventory does not see them "
               f"at all - they are counted here separately for that reason. Their risk axis is "
               f"the assignment list, not the scope list.",
            ko=f"SSO 앱 {len(sso)}개가 있고 **전부 할당 게이트가 걸려 있습니다.** SSO 앱은 OAuth "
               f"동의를 갖지 않으므로 동의 기반 재고에는 아예 나타나지 않습니다 — 그래서 여기서 "
               f"따로 셉니다. 이 앱들의 위험 축은 스코프가 아니라 **할당 명단**입니다."))

    if apponly_write_3p:
        names = ", ".join(a["name"] or "?" for a in by_name(apponly_write_3p))
        findings.append(finding(
            "high",
            en=f"{len(apponly_write_3p)} third-party app(s) hold application (app-only) permissions "
               f"that WRITE: {names}. App-only runs with no signed-in user, so Conditional Access "
               f"never evaluates it, nothing appears in interactive sign-in logs, and it keeps "
               f"working after everyone who approved it has left. Confirm each is still contracted "
               f"and still needs write.",
            ko=f"타사 앱 {len(apponly_write_3p)}개가 **쓰기 가능한 애플리케이션(앱 전용) 권한**을 "
               f"갖고 있습니다: {names}. 앱 전용은 로그인한 사용자가 없으므로 Conditional Access 가 "
               f"평가되지 않고, 대화형 사인인 로그에도 남지 않으며, 승인한 사람이 모두 떠나도 계속 "
               f"동작합니다. 각각 계약이 유효한지, 쓰기가 아직 필요한지 확인하십시오."))

    if ungated_data_3p:
        names = ", ".join(a["name"] or "?" for a in by_name(ungated_data_3p))
        findings.append(finding(
            "high",
            en=f"{len(ungated_data_3p)} third-party app(s) have tenant-wide consent with NO assignment "
               f"gate and "
               f"reach company content: {names}. Every employee can connect these with their work "
               f"account. Fix is one command per app - "
               f"scripts/Approve-EnterpriseApp.ps1 -DisplayName '<app>' -AppRole <role> -Apply "
               f"puts the gate up and limits access to a group.",
            ko=f"타사 앱 {len(ungated_data_3p)}개가 **게이트 없이 테넌트 전체 동의**를 가진 채 회사 콘텐츠에 "
               f"접근합니다: {names}. 전 직원이 회사 계정으로 연결할 수 있습니다. 앱당 명령 하나로 "
               f"고칩니다 - scripts/Approve-EnterpriseApp.ps1 -DisplayName '<앱>' -AppRole <역할> "
               f"-Apply 가 게이트를 세우고 그룹으로 제한합니다."))

    if ungated_data_own:
        names = ", ".join(a["name"] or "?" for a in by_name(ungated_data_own))
        findings.append(finding(
            "med",
            en=f"{len(ungated_data_own)} app(s) built in this tenant hold tenant-wide consent to "
               f"company content with no gate: {names}. A script's own app registration is as "
               f"reachable as a vendor's - anyone in the tenant can ask for a token for it.",
            ko=f"이 테넌트에서 만든 앱 {len(ungated_data_own)}개가 게이트 없이 회사 콘텐츠에 대한 "
               f"테넌트 전체 동의를 갖고 있습니다: {names}. 자체 스크립트의 앱 등록도 벤더 앱과 "
               f"똑같이 접근 가능합니다 - 테넌트 안의 누구나 그 앱으로 토큰을 요청할 수 있습니다."))

    ungated_login = [a for a in ungated
                     if not a["dataScopes"] and a["owner"] != "microsoft"]
    if ungated_login:
        findings.append(finding(
            "med",
            en=f"{len(ungated_login)} more app(s) have tenant-wide consent with no gate, but only "
               f"sign-in scopes. Lower priority: they identify the user, they do not read content.",
            ko=f"게이트 없이 테넌트 전체 동의된 앱이 {len(ungated_login)}개 더 있지만 로그인 스코프뿐"
               f"입니다. 사용자를 식별할 뿐 콘텐츠를 읽지 않으므로 우선순위는 낮습니다."))

    if pending is None:
        findings.append(finding(
            "med",
            en="The admin consent request queue could not be read (beta endpoint). Treat it as "
               "unknown, not empty - a pending request is one portal click away from tenant-wide "
               "consent. Check Enterprise applications > Admin consent requests by hand.",
            ko="관리자 동의 요청 큐를 읽지 못했습니다(beta 엔드포인트). **비어 있음이 아니라 '알 수 "
               "없음' 으로 보십시오** - 대기 중인 요청은 포털 클릭 한 번이면 테넌트 전체 동의가 "
               "됩니다. Enterprise applications > Admin consent requests 를 직접 확인하십시오."))
    elif pending:
        oldest = max((p.get("ageDays") or 0) for p in pending)
        names = ", ".join(p.get("appDisplayName") or "?" for p in pending)
        findings.append(finding(
            "med",
            en=f"{len(pending)} admin consent request(s) pending, oldest {oldest} day(s): {names}. "
               f"A pending request is a live hazard: the portal's 'Review permissions and consent' "
               f"button grants everything the vendor asked for, tenant-wide, in one click. Approve "
               f"through scripts/Approve-EnterpriseApp.ps1 and then Deny the queue item - "
               f"Deny closes the ticket without touching access. Block is a different button and "
               f"disables the app.",
            ko=f"관리자 동의 요청 {len(pending)}건이 대기 중이고 가장 오래된 것이 {oldest}일 "
               f"됐습니다: {names}. 대기 중인 요청은 살아 있는 위험입니다 - 포털의 'Review "
               f"permissions and consent' 버튼은 벤더가 요청한 것을 **한 번에 테넌트 전체로** "
               f"부여합니다. scripts/Approve-EnterpriseApp.ps1 로 승인한 뒤 큐 항목은 Deny 로 "
               f"닫으십시오. Deny 는 접근에 영향을 주지 않습니다. **Block 은 다른 버튼이고 앱 자체를 "
               f"비활성화합니다.**"))

    if legacy_apps:
        names = ", ".join(f"{a['name'] or '?'}({'·'.join(a['legacyProtocolScopes'])})"
                          for a in by_name(legacy_apps))
        findings.append(finding(
            "med",
            en=f"{len(legacy_apps)} app(s) hold IMAP/POP/SMTP/EAS/EWS scopes: {names}. These ride "
               f"on modern auth, so a CA policy that blocks legacy authentication does not stop them - blocking legacy "
               f"authentication and allowing these scopes are not the same control.",
            ko=f"앱 {len(legacy_apps)}개가 IMAP/POP/SMTP/EAS/EWS 스코프를 갖고 있습니다: {names}. 이들은 "
               f"최신 인증 위에서 동작하므로 **레거시 인증 차단 CA 정책으로 막히지 않습니다** - 레거시 "
               f"인증 차단과 이 스코프 허용은 서로 다른 통제입니다."))

    if unused:
        findings.append(finding(
            "low",
            en=f"{len(unused)} third-party app(s) can read company content but had no "
               f"**interactive** sign-in in the last {UNUSED_DAYS} days. ⛔ This is NOT 'unused'. "
               f"An app holding offline_access keeps reading on a refresh token with no new "
               f"interactive sign-in, and an Outlook add-in produces no sign-in log at all. "
               f"An app can show 0 interactive and hundreds of non-interactive sign-ins in the "
               f"same window. Before deciding, check "
               f"beta/auditLogs/signIns with signInEventTypes eq 'nonInteractiveUser' AND ask the "
               f"users - the add-in axis is measurable by nothing else.",
            ko=f"타사 앱 {len(unused)}개가 회사 콘텐츠를 읽을 수 있는데 최근 {UNUSED_DAYS}일간 "
               f"**대화형** 사인인이 없었습니다. ⛔ 이것은 **'안 쓴다' 가 아닙니다.** "
               f"`offline_access` 를 가진 앱은 리프레시 토큰으로 새 로그인 없이 계속 읽고, "
               f"Outlook 애드인은 **사인인 로그를 아예 남기지 않습니다.** "
               f"같은 기간에 대화형 0건 · 비대화형 **수백 건**인 앱도 있습니다. 결정 전에 "
               f"`beta/auditLogs/signIns` 의 `signInEventTypes eq 'nonInteractiveUser'` 를 "
               f"보고, **사용자에게 물어보십시오** — 애드인 축은 다른 어떤 것으로도 측정되지 "
               f"않습니다."))

    if personal:
        findings.append(finding(
            "low",
            en=f"{len(personal)} third-party app(s) also accept personal Microsoft accounts. "
               f"Blocking the work account does not close the vendor off - an employee can sign up "
               f"with a personal address and the company data still goes there. That is a policy "
               f"question, not something Entra can enforce.",
            ko=f"타사 앱 {len(personal)}개가 개인 Microsoft 계정도 받습니다. 회사 계정을 막아도 "
               f"벤더가 닫히지 않습니다 - 직원이 개인 주소로 가입하면 회사 데이터는 그대로 "
               f"넘어갑니다. Entra 로 강제할 수 있는 것이 아니라 **정책의 문제**입니다."))

    if unconsented_open:
        names = ", ".join((a["name"] or "?") for a in unconsented_open[:6])
        more = f" (+{len(unconsented_open) - 6})" if len(unconsented_open) > 6 else ""
        findings.append(finding(
            "med",
            en=f"{len(unconsented_open)} third-party service principal(s) are enabled with no "
               f"assignment gate and no consent at all: {names}{more}. A consent-based inventory "
               f"cannot see them, because there is nothing granted to see. Where self-service consent "
               f"is off, these are mostly sign-in attempts that stopped at the approval wall - "
               f"ask what they are before deciding. The risk is one admin click away: approving the "
               f"queue item consents tenant-wide while the gate is still off."
               + (f" ({len(unconsented_inert)} more excluded: they request no permissions at all, "
                  f"so there is nothing to act on - some are re-created automatically by the "
                  f"platform and cannot be deleted.)" if unconsented_inert else ""),
            ko=f"제3자 서비스 주체 {len(unconsented_open)}개가 **동의도 게이트도 없이 활성** "
               f"상태입니다: {names}{more}. 부여된 것이 없어서 **동의 기반 재고에는 보이지 "
               f"않습니다.** 사용자 자체 동의가 꺼져 있다면 대부분 승인 벽에서 "
               f"멈춘 로그인 시도입니다 — 막기 전에 무엇인지 물어보십시오. 위험은 관리자 클릭 "
               f"하나 거리입니다: 큐에서 승인하면 **게이트가 없는 채로** 테넌트 전체 동의가 "
               f"들어갑니다."
               + (f" (요청 권한이 0개여서 조치 대상이 아닌 {len(unconsented_inert)}개는 위 "
                  f"숫자에서 뺐습니다 — 일부는 플랫폼이 자동으로 다시 만들어 **삭제할 수 "
                  f"없습니다**.)" if unconsented_inert else "")))

    if unconsented_inert and not unconsented_open:
        names = ", ".join((a["name"] or "?") for a in unconsented_inert[:6])
        more = f" (+{len(unconsented_inert) - 6})" if len(unconsented_inert) > 6 else ""
        findings.append(finding(
            "info",
            en=f"{len(unconsented_inert)} enabled service principal(s) have no consent and no "
               f"assignment gate, but request no permissions at all, so they are not on the "
               f"action list: {names}{more}. Some are re-created automatically by the platform "
               f"within hours of being deleted (for example P2P Server, re-created by Azure ESTS "
               f"Service). Deleting them is not a fix; leave them.",
            ko=f"동의도 게이트도 없이 활성인 서비스 주체 {len(unconsented_inert)}개가 있지만 "
               f"**요청 권한이 0개**라 조치 대상이 아닙니다: {names}{more}. 일부는 플랫폼이 "
               f"자동으로 다시 만듭니다 — 예를 들어 `P2P Server` 는 지워도 몇 시간 안에 "
               f"`Azure ESTS Service` 가 다시 만듭니다. **지우는 것은 해결이 "
               f"아닙니다 — 그대로 두십시오.**"))

    if unconsented_unverified:
        findings.append(finding(
            "low",
            en=f"{len(unconsented_unverified)} of those have no verified publisher. An unverified "
               f"publisher is not proof of anything by itself, but paired with a name nobody in IT "
               f"recognises it is the first thing to check - including when it was added and by whom.",
            ko=f"그중 {len(unconsented_unverified)}개는 **발행자가 검증되지 않았습니다.** 미검증 "
               f"자체가 증거는 아니지만, IT 가 모르는 이름과 겹치면 가장 먼저 확인할 것입니다 — "
               f"언제 누가 추가했는지까지."))

    if not findings:
        findings.append(finding(
            "ok",
            en="Every consented app is gated or first-party, nothing holds writing app-only "
               "permissions, and the consent queue is empty.",
            ko="동의된 앱이 모두 게이트가 있거나 자체/Microsoft 앱이고, 쓰기 앱 전용 권한을 가진 것이 "
               "없으며, 동의 요청 큐도 비어 있습니다."))

    order = {"high": 0, "med": 1, "low": 2, "ok": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 9))

    return {
        "available": True,
        "ungatedDataApps": by_name(ungated_data_3p),
        "ungatedOwnApps": by_name(ungated_data_own),
        "unusedApps": by_name(unused),
        "note": "Delegated scopes are a ceiling bounded by the signed-in user's own rights; "
                "application (app-only) permissions are not bounded by anyone. The two are counted "
                "separately on purpose and must not be added together. The unused list is based on "
                "INTERACTIVE sign-ins, so apps that run app-only are excluded from it rather than "
                "reported as unused.",
        "totalServicePrincipals": len(sps),
        "thirdPartyCount": len([s for s in sps if _owner(s) == "thirdParty"]),
        "ownCount": len([s for s in sps if _owner(s) == "own"]),
        "consentedCount": len(apps),
        "grantCount": len(grants),
        "unusedDays": UNUSED_DAYS,
        "signInWindowAvailable": signin_window_ok,
        "apps": by_name(apps),
        "ungated": by_name(ungated),
        "ungatedDataCount": len(ungated_data_3p),
        "ungatedCount": len(ungated),
        "ungatedTenantWideCount": len(ungated_tenant),
        "unconsented": unconsented,
        "unconsentedCount": len(unconsented),
        "unconsentedOpenCount": len(unconsented_open),
        "unconsentedInert": unconsented_inert,
        "unconsentedInertCount": len(unconsented_inert),
        "unconsentedUnverifiedCount": len(unconsented_unverified),
        "unconsentedOffCount": len(unconsented_off),
        "msExcludedCount": len(ms_excluded),
        "msExcludedActive": ms_excluded_active,
        "msExcludedActiveCount": len(ms_excluded_active),
        "nonMsTotal": len(nonms_all),
        "nonMsListed": len(nonms_all) - len(unconsented_all),
        "thirdPartyListedCount": len(third) + len([a for a in sso if a["owner"] == "thirdParty"]),
        "unconsentedOwnCount": len([a for a in unconsented if a["owner"] == "own"]),
        "unconsentedNote": "Built from service principals, not from consent records - the other "
                           "three buckets all start from something granted, so an app with nothing "
                           "granted is invisible to them. Self-service consent is off in this "
                           "tenant, so most of these are sign-in attempts that stopped at the "
                           "approval wall: a list to ask about, not a list to revoke from.",
        "appOnly": by_name(apponly),
        "appOnlyCount": len(apponly),
        "appOnlyWriteCount": len(apponly_write_3p),
        "appOnlyUnresolved": unresolved_total,
        "legacyProtocolApps": by_name(legacy_apps),
        "unverifiedCount": len(unverified),
        "personalAccountCount": len(personal),
        "unusedCount": len(unused),
        "ssoApps": by_name(sso),
        "ssoCount": len(sso),
        "ssoUngated": by_name(sso_ungated),
        "ssoUngatedCount": len(sso_ungated),
        "ssoNote": "SSO apps carry no OAuth scopes - what crosses is identity, not data - so a "
                   "consent-based inventory cannot see them at all. They are listed separately "
                   "because their risk axis is the assignment gate, not the scope list.",
        "pendingRequests": pending,
        "pendingCount": None if pending is None else len(pending),
        "pendingClosedCount": pending_closed,
        "findings": findings,
    }
