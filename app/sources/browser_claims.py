import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from .. import signin_cache
from ..graph_client import graph_get
from ._i18n import finding

_BETA = "https://graph.microsoft.com/beta"

WINDOW_DAYS = 7
MAX_SIGNINS = 8000
PAGE_SIZE = 1000

PILOT_GROUP = os.environ.get("PILOT_GROUP_NAME", "CA-Pilot-Users")
DIAG = os.environ.get("BROWSER_CLAIMS_DIAG") == "1"

EXTENSION_NAME = "Microsoft Single Sign On"
EXTENSION_ID = "ppnbnpeolgkicgegkbkbjmhlideopiji"

NATIVE_BROWSERS = ("edge", "internet explorer", "ie")

FIXABLE_BROWSERS = ("chrome", "opera")

_OS_TO_PLATFORM = (
    ("windowsphone", "windowsPhone"),
    ("windows", "windows"),
    ("ios", "iOS"),
    ("ipados", "iOS"),
    ("macos", "macOS"),
    ("mac os", "macOS"),
    ("os x", "macOS"),
    ("android", "android"),
    ("linux", "linux"),
    ("ubuntu", "linux"),
    ("debian", "linux"),
    ("fedora", "linux"),
)


async def _pages(url, params=None, cap=20000):
    out = []
    data = await graph_get(url, params=params)
    while True:
        out.extend(data.get("value", []))
        nxt = data.get("@odata.nextLink")
        if not nxt or len(out) >= cap:
            break
        data = await graph_get(nxt)
    return out


async def _optional(url, params=None, cap=20000):
    try:
        return await _pages(url, params, cap)
    except Exception:
        return []


def _family(browser: str) -> str:
    b = (browser or "").strip()
    if not b:
        return ""
    low = b.lower()
    for name in ("edge", "chrome", "firefox", "safari", "opera", "internet explorer", "ie"):
        if name in low:
            return {"ie": "Internet Explorer", "internet explorer": "Internet Explorer"}.get(
                name, name.capitalize())
    return b.split()[0]


def _is_native(family: str) -> bool:
    fl = (family or "").lower()
    return any(n in fl for n in NATIVE_BROWSERS)


def _needs_extension(family: str) -> bool:
    fl = (family or "").lower()
    return bool(fl) and not _is_native(fl) and any(n in fl for n in FIXABLE_BROWSERS)


def _unfixable(family: str) -> bool:
    fl = (family or "").lower()
    return bool(fl) and not _is_native(fl) and not _needs_extension(fl)


def _platform_of(os_name: str) -> str | None:
    low = (os_name or "").strip().lower()
    if not low:
        return None
    for needle, token in _OS_TO_PLATFORM:
        if low.startswith(needle) or needle in low:
            return token
    return None


async def _device_policy_platforms() -> tuple[set | None, list]:
    try:
        pols = (await graph_get("/identity/conditionalAccess/policies")).get("value") or []
    except Exception:
        return None, []

    names, platforms, unbounded = [], set(), False
    for p in pols:
        if p.get("state") == "disabled":
            continue
        cond = p.get("conditions") or {}
        grants = set((p.get("grantControls") or {}).get("builtInControls") or [])
        rule = ((cond.get("devices") or {}).get("deviceFilter") or {}).get("rule") or ""
        if not (grants & {"compliantDevice", "domainJoinedDevice"} or "device." in rule):
            continue
        names.append(p.get("displayName"))
        plat = cond.get("platforms") or {}
        inc = [x for x in (plat.get("includePlatforms") or []) if x]
        exc = {x for x in (plat.get("excludePlatforms") or []) if x}
        if not inc or "all" in inc:
            unbounded = True
        else:
            platforms |= {x for x in inc if x not in exc}
    if unbounded or not names:
        return None, names
    return platforms, names


async def fetch() -> dict:
    signins, _ = await signin_cache.get_interactive()

    pilot: dict[str, str] = {}
    groups = await _optional("/groups", {"$filter": f"displayName eq '{PILOT_GROUP}'",
                                         "$select": "id,displayName"})
    if groups:
        members = await _optional(f"/groups/{groups[0]['id']}/members",
                                  {"$select": "id,userPrincipalName", "$top": "999"})
        pilot = {(m.get("id") or "").lower(): m.get("userPrincipalName")
                 for m in members if m.get("id")}
    pilot_ids = set(pilot)

    editions_by_user: dict[str, set] = defaultdict(set)
    managed = await _optional(f"{_BETA}/deviceManagement/managedDevices",
                              {"$select": "id,deviceName,userPrincipalName,skuFamily,operatingSystem",
                               "$top": "100"})
    for m in managed:
        upn = (m.get("userPrincipalName") or "").lower()
        if upn and m.get("skuFamily"):
            editions_by_user[upn].add(m["skuFamily"])

    scope_platforms, scope_policies = await _device_policy_platforms()

    per_user: dict[str, dict] = {}
    fam_totals: Counter = Counter()
    fam_claims: Counter = Counter()
    out_of_scope: Counter = Counter()
    unknown_platform = 0

    for r in signins:
        dd = r.get("deviceDetail") or {}
        fam = _family(dd.get("browser"))
        if not fam:
            continue
        if scope_platforms is not None:
            plat = _platform_of(dd.get("operatingSystem"))
            if plat is None:
                unknown_platform += 1
            elif plat not in scope_platforms:
                out_of_scope[plat] += 1
                continue
        uid = (r.get("userId") or "").lower()
        upn = r.get("userPrincipalName") or "(unknown)"
        has = bool(dd.get("deviceId"))
        ts = r.get("createdDateTime") or ""

        fam_totals[fam] += 1
        if has:
            fam_claims[fam] += 1

        u = per_user.setdefault(uid or upn, {
            "user": upn, "userId": uid or None,
            "browsers": {}, "total": 0, "claim": 0,
        })
        u["total"] += 1
        u["claim"] += 1 if has else 0
        b = u["browsers"].setdefault(fam, {
            "total": 0, "claim": 0, "lastClaim": None, "lastNoClaim": None, "devices": set(),
        })
        b["total"] += 1
        if has:
            b["claim"] += 1
            if ts > (b["lastClaim"] or ""):
                b["lastClaim"] = ts
            if dd.get("displayName"):
                b["devices"].add(dd["displayName"])
        else:
            if ts > (b["lastNoClaim"] or ""):
                b["lastNoClaim"] = ts

    rows = []
    for key, u in per_user.items():
        needing = {f: b for f, b in u["browsers"].items() if _needs_extension(f)}
        n_total = sum(b["total"] for b in needing.values())
        n_claim = sum(b["claim"] for b in needing.values())
        last_claim = max((b["lastClaim"] or "") for b in needing.values()) if needing else ""
        last_no = max((b["lastNoClaim"] or "") for b in needing.values()) if needing else ""

        if not needing:
            status = "nativeOnly"
        elif n_claim == 0:
            status = "missing"
        elif n_claim == n_total:
            status = "ok"
        elif last_claim and last_claim > last_no:
            status = "ok"
        else:
            status = "partial"

        upn = u["user"]
        eds = sorted(editions_by_user.get(upn.lower(), set()))
        rows.append({
            "user": upn,
            "inPilot": (u["userId"] or "") in pilot_ids if pilot_ids else None,
            "status": status,
            "editions": eds,
            "autoDeployable": bool(eds) and all(e == "Pro" for e in eds),
            "needTotal": n_total, "needClaim": n_claim,
            "needClaimPct": round(100 * n_claim / n_total) if n_total else None,
            "unfixableTotal": sum(b["total"] for f, b in u["browsers"].items() if _unfixable(f)),
            "unfixableBrowsers": sorted(f for f in u["browsers"] if _unfixable(f)),
            "lastClaim": last_claim or None,
            "lastNoClaim": last_no or None,
            "browsers": [
                {"browser": f, "total": b["total"], "claim": b["claim"],
                 "needsExtension": _needs_extension(f), "unfixable": _unfixable(f),
                 "devices": sorted(b["devices"])[:4],
                 "lastClaim": b["lastClaim"], "lastNoClaim": b["lastNoClaim"]}
                for f, b in sorted(u["browsers"].items(), key=lambda kv: -kv[1]["total"])
            ],
        })

    seen_upns = {(r.get("user") or "").lower() for r in rows}
    for uid, upn in pilot.items():
        if (upn or "").lower() in seen_upns:
            continue
        eds = sorted(editions_by_user.get((upn or "").lower(), set()))
        rows.append({
            "user": upn, "inPilot": True, "status": "noData", "editions": eds,
            "autoDeployable": bool(eds) and all(e == "Pro" for e in eds),
            "needTotal": 0, "needClaim": 0, "needClaimPct": None,
            "unfixableTotal": 0, "unfixableBrowsers": [],
            "lastClaim": None, "lastNoClaim": None, "browsers": [],
        })

    _rank = {"missing": 0, "partial": 1, "noData": 2, "ok": 3, "nativeOnly": 4}
    rows.sort(key=lambda r: (r["inPilot"] is False, _rank.get(r["status"], 9), -r["needTotal"]))

    if not DIAG:
        for r in rows:
            r.pop("browsers", None)

    scoped = [r for r in rows if r["inPilot"] is not False]
    missing = [r for r in scoped if r["status"] == "missing"]
    partial = [r for r in scoped if r["status"] == "partial"]
    done = [r for r in scoped if r["status"] == "ok"]
    native = [r for r in scoped if r["status"] == "nativeOnly"]
    missing_auto = [r for r in missing if r["autoDeployable"]]
    missing_manual = [r for r in missing if not r["autoDeployable"]]

    unseen = 0
    if pilot_ids:
        seen_ids = {(u.get("userId") or "") for u in per_user.values()}
        unseen = len([1 for pid in pilot_ids if pid not in seen_ids])

    ext_total = sum(v for f, v in fam_totals.items() if _needs_extension(f))
    ext_claim = sum(v for f, v in fam_claims.items() if _needs_extension(f))
    unfix_total = sum(v for f, v in fam_totals.items() if _unfixable(f))
    unfix_claim = sum(v for f, v in fam_claims.items() if _unfixable(f))
    unfix_browsers = sorted(f for f in fam_totals if _unfixable(f))

    findings = []
    if missing_manual:
        findings.append(finding(
            "high",
            en=f"{len(missing_manual)} in-scope user(s) have not produced a single claim-bearing "
               f"non-Edge browser sign-in in {WINDOW_DAYS} days. If the device-filter CA is "
               f"enforced now, these users are blocked in that browser. Send them "
               f"docs/chrome-sso-extension-guide.md (install, restart Chrome, then SIGN OUT and "
               f"back in - the claim is only recorded on a real trip to login.microsoftonline.com).",
            ko=f"범위 안 사용자 {len(missing_manual)}명이 {WINDOW_DAYS}일 동안 클레임을 실은 "
               "비-Edge 브라우저 사인인을 한 번도 만들지 않았습니다. device filter CA 를 지금 "
               "enforce 로 올리면 이들은 그 브라우저에서 막힙니다. "
               "docs/chrome-sso-extension-guide.md 를 보내십시오 (설치 → Chrome 재시작 → "
               "로그아웃 후 다시 로그인. 클레임은 login.microsoftonline.com 까지 실제로 갔을 때만 "
               "기록됩니다)."))
    if missing_auto:
        findings.append(finding(
            "high",
            en=f"{len(missing_auto)} user(s) whose devices are all Windows Pro still show no "
               f"device claim. Pro is supposed to get the extension automatically from the "
               f"Intune Chrome profile, so this points at the PROFILE, not the user - check the "
               f"profile's assignment and the device's last check-in.",
            ko=f"기기가 전부 Windows Pro 인데도 기기 클레임이 없는 사용자 {len(missing_auto)}명. "
               "Pro 는 Intune Chrome 프로필에서 확장을 자동으로 받게 돼 있으므로, 이건 사람이 "
               "아니라 **프로필**을 가리킵니다 - 프로필 할당과 그 기기의 마지막 체크인을 "
               "확인하십시오."))
    if partial:
        findings.append(finding(
            "med",
            en=f"{len(partial)} user(s) have SOME claim-bearing sign-ins but their most recent "
               f"one still had none - usually a second machine without the extension, or an "
               f"incognito window (extensions are off in incognito by default). Check which "
               f"device, do not re-install.",
            ko=f"클레임을 실은 사인인이 **있기는 한데** 가장 최근 것에는 없는 사용자 "
               f"{len(partial)}명. 대개 확장이 없는 두 번째 기기이거나 시크릿 창입니다"
               "(시크릿에서는 확장이 기본으로 꺼집니다). 다시 설치하지 말고 어느 기기인지 "
               "확인하십시오."))
    if unseen:
        findings.append(finding(
            "med",
            en=f"{unseen} pilot member(s) had no browser sign-in in the window, so their "
               f"extension state is UNKNOWN, not ready. Do not treat the rollout as complete "
               f"until they appear here.",
            ko=f"구간 안에 브라우저 사인인이 없던 파일럿 구성원 {unseen}명. 확장 상태가 "
               "'준비됨' 이 아니라 **알 수 없음**입니다. 이들이 여기 나타나기 전까지는 배포가 "
               "끝났다고 보지 마십시오."))
    if unfix_total and unfix_claim == 0:
        _plats = ', '.join(sorted(scope_platforms)) if scope_platforms else 'all platforms'
        _plats_ko = ', '.join(sorted(scope_platforms)) if scope_platforms else '모든 플랫폼'
        findings.append(finding(
            "med",
            en=f"{unfix_total} IN-SCOPE sign-in(s) came from {', '.join(unfix_browsers)} - "
               f"browsers with no SSO extension available, so they can never send a device "
               f"claim, yet the device policies do evaluate this platform ({_plats}). "
               f"Installing something will not fix these: either narrow the policy's platform "
               f"condition or move the traffic to a managed app.",
            ko=f"범위 **안**의 사인인 {unfix_total}건이 {', '.join(unfix_browsers)} 에서 왔습니다 - "
               "SSO 확장 자체가 없는 브라우저라 기기 클레임을 보낼 방법이 없는데, 기기 정책은 "
               f"이 플랫폼({_plats_ko})을 평가합니다. 무엇을 설치해도 해결되지 않습니다: 정책의 "
               "플랫폼 조건을 좁히거나, 그 트래픽을 관리되는 앱으로 옮기십시오."))
    home = sum(1 for m in managed if m.get("skuFamily") == "Home")
    if home:
        findings.append(finding(
            "low",
            en=f"{home} enrolled device(s) run Windows Home, where Intune ADMX ingestion is "
               f"rejected (0x86000013) - the extension cannot be pushed there and manual "
               f"install stays a permanent step in the device-onboarding SOP.",
            ko=f"등록 기기 {home}대가 Windows Home 입니다. Home 에서는 Intune ADMX 수집이 "
               "거부되므로(0x86000013) 확장을 밀어 넣을 수 없고, 수동 설치가 기기 온보딩 "
               "절차의 상시 단계로 남습니다."))

    return {
        "available": True,
        "signinData": signin_cache.stale_info(),
        "windowDays": WINDOW_DAYS,
        "extensionName": EXTENSION_NAME,
        "extensionId": EXTENSION_ID,
        "pilotGroup": PILOT_GROUP if pilot_ids else None,
        "pilotMemberCount": len(pilot_ids) or None,
        "truncated": len(signins) >= MAX_SIGNINS,
        "scopePlatforms": sorted(scope_platforms) if scope_platforms is not None else None,
        "scopePolicies": scope_policies,
        "outOfScopeSignins": sum(out_of_scope.values()),
        "outOfScopeByPlatform": dict(out_of_scope),
        "unknownPlatformSignins": unknown_platform,
        "extBrowserSignins": ext_total,
        "extBrowserClaims": ext_claim,
        "extClaimPct": round(100 * ext_claim / ext_total) if ext_total else None,
        "unfixableSignins": unfix_total,
        "unfixableClaims": unfix_claim,
        "unfixableBrowsers": unfix_browsers,
        "byBrowser": [
            {"browser": f, "total": t, "claim": fam_claims.get(f, 0),
             "pct": round(100 * fam_claims.get(f, 0) / t) if t else 0,
             "needsExtension": _needs_extension(f), "unfixable": _unfixable(f)}
            for f, t in fam_totals.most_common()
        ],
        "readyCount": len(done),
        "missingCount": len(missing),
        "missingManualCount": len(missing_manual),
        "missingAutoCount": len(missing_auto),
        "partialCount": len(partial),
        "nativeOnlyCount": len(native),
        "unseenPilotCount": unseen,
        "users": rows,
        "findings": findings,
        "findingCount": len(findings),
        "highFindingCount": sum(1 for f in findings if f["severity"] == "high"),
    }
