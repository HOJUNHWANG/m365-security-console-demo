from datetime import datetime, timezone

from ..config import settings
from ..graph_client import graph_get
from ._i18n import finding

_BETA = "https://graph.microsoft.com/beta/deviceManagement"
_APPS = "https://graph.microsoft.com/beta/deviceAppManagement"
_V1 = "https://graph.microsoft.com/v1.0"
RECENT_DAYS = 7

_P = "device_vendor_msft_policy_config_"
_EDGE = _P + "microsoft_edge~policy~microsoft_edge"
_OD = _P + "onedrivengscv2~policy~onedrivengsc"
_ADMX_FILTER = "Windows-Pro-Devices"


def _tenant():
    return settings.tenant_id


BASELINE = [
    {"name": "DisableFileSyncNGSC", "kind": "catalog", "why": "OneDrive PC sync block",
     "assign": [f"include:allLicensedUsers|filter:{_ADMX_FILTER}"],
     "settings": [
         ("Block syncing for listed tenants", _OD + "_blocktenantlist", _OD + "_blocktenantlist_1"),
         ("Listed tenant = this tenant", _OD + "_blocktenantlist_blocktenantlistbox", lambda: [_tenant()]),
         ("Block personal OneDrive sync", "user_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_disablepersonalsync",
          "user_vendor_msft_policy_config_onedrivengscv2~policy~onedrivengsc_disablepersonalsync_1"),
     ]},
    {"name": "Endpoint-Protection-Baseline", "kind": "catalog", "why": "Defender onboarding",
     "assign": ["include:SG-Endpoint-Pilot", "exclude:SG-Endpoint-Offboard"],
     "settings": [
         ("Onboarding = Auto from connector", "device_vendor_msft_windowsadvancedthreatprotection_configurationtype",
          "device_vendor_msft_windowsadvancedthreatprotection_configurationtype_autofromconnector"),
     ]},
    {"name": "Contoso-Pro-Edge", "kind": "catalog", "why": "Edge phishing protection",
     "assign": [f"include:CA-Pilot-Users|filter:{_ADMX_FILTER}"],
     "settings": [
         ("SmartScreen on", _EDGE + "~smartscreen_smartscreenenabled", _EDGE + "~smartscreen_smartscreenenabled_1"),
         ("No bypass of site warnings", _EDGE + "~smartscreen_preventsmartscreenpromptoverride",
          _EDGE + "~smartscreen_preventsmartscreenpromptoverride_1"),
         ("No bypass of download warnings", _EDGE + "~smartscreen_preventsmartscreenpromptoverrideforfiles",
          _EDGE + "~smartscreen_preventsmartscreenpromptoverrideforfiles_1"),
         ("InPrivate disabled", _EDGE + "_inprivatemodeavailability_inprivatemodeavailability",
          _EDGE + "_inprivatemodeavailability_inprivatemodeavailability_1"),
     ]},
    {"name": "Contoso-Pro-ScreenLock", "kind": "catalog", "why": "Lock after 30 min idle (the operations log · 11-11 900s -> 1800s)",
     "assign": [f"include:CA-Pilot-Users|filter:{_ADMX_FILTER}"],
     "settings": [
         ("Idle lock (seconds)", _P + "localpoliciessecurityoptions_interactivelogon_machineinactivitylimit_v2", 1800),
     ]},
    {"name": "Contoso-Pro-LsaProtection", "kind": "catalog", "why": "LSA protection pinned on (on by default; 11-11 pilot -> all Pro)",
     "assign": [f"include:CA-Pilot-Users|filter:{_ADMX_FILTER}"],
     "settings": [
         ("LSA protected, no UEFI lock", _P + "localsecurityauthority_configurelsaprotectedprocess",
          _P + "localsecurityauthority_configurelsaprotectedprocess_2"),
     ]},
    {"name": "Browser-SSO-Extension", "kind": "admx", "why": "Chrome SSO extension + phishing protection",
     "assign": [f"include:CA-Pilot-Users|filter:{_ADMX_FILTER}"],
     "settings": [
         ("Force-install Microsoft SSO extension", "00000901-1111-4222-8333-000000000901",
          ["ppnbnpeolgkicgegkbkbjmhlideopiji;https://clients2.google.com/service/update2/crx"]),
         ("Safe Browsing = standard", "00000902-1111-4222-8333-000000000902", "1"),
         ("No proceeding past Safe Browsing warnings", "00000903-1111-4222-8333-000000000903", None),
         ("Incognito disabled", "00000904-1111-4222-8333-000000000904", "1"),
     ]},
    {"name": "Contoso-WU-Ring", "kind": "ring", "why": "Windows update ring",
     "assign": ["include:allDevices"],
     "settings": [
         ("Quality deferral (days)", "qualityUpdatesDeferralPeriodInDays", 3),
         ("Quality deadline (days)", "deadlineForQualityUpdatesInDays", 5),
         ("Restart grace (days)", "deadlineGracePeriodInDays", 2),
         ("Feature deferral (days)", "featureUpdatesDeferralPeriodInDays", 60),
         ("Feature deadline (days)", "deadlineForFeatureUpdatesInDays", 7),
         ("User pause", "userPauseAccess", "disabled"),
         ("Quality updates paused", "qualityUpdatesPaused", False),
         ("Feature updates paused", "featureUpdatesPaused", False),
     ]},
    {"name": "AppProtection-iOS-Pilot", "kind": "mam", "platform": "ios", "why": "iOS app protection",
     "assign": ["include:SG-AppProtection-Pilot"],
     "settings": [
         ("Disabled account -> wipe", "appActionIfUnableToAuthenticateUser", "wipe"),
         ("Offline wipe after", "periodOfflineBeforeWipeIsEnforced", "P35D"),
         ("App PIN required", "pinRequired", True),
         ("Save As blocked", "saveAsBlocked", True),
         ("Send data to", "allowedOutboundDataTransferDestinations", "managedApps"),
     ]},
    {"name": "AppProtection-Android-Pilot", "kind": "mam", "platform": "android", "why": "Android app protection",
     "assign": ["include:SG-AppProtection-Pilot"],
     "settings": [
         ("Disabled account -> wipe", "appActionIfUnableToAuthenticateUser", "wipe"),
         ("Offline wipe after", "periodOfflineBeforeWipeIsEnforced", "P35D"),
         ("App PIN required", "pinRequired", True),
         ("Save As blocked", "saveAsBlocked", True),
         ("Send data to", "allowedOutboundDataTransferDestinations", "managedApps"),
         ("App data encrypted", "encryptAppData", True),
     ]},
]


def flatten_instance(inst: dict, out: dict) -> dict:
    sid = inst.get("settingDefinitionId")
    if "choiceSettingValue" in inst:
        cv = inst["choiceSettingValue"] or {}
        out[sid] = cv.get("value")
        for c in cv.get("children") or []:
            flatten_instance(c, out)
    elif "simpleSettingValue" in inst:
        out[sid] = (inst["simpleSettingValue"] or {}).get("value")
    elif "simpleSettingCollectionValue" in inst:
        out[sid] = [v.get("value") for v in inst["simpleSettingCollectionValue"] or []]
    elif "choiceSettingCollectionValue" in inst:
        out[sid] = [v.get("value") for v in inst["choiceSettingCollectionValue"] or []]
    elif "groupSettingCollectionValue" in inst:
        for g in inst["groupSettingCollectionValue"] or []:
            for c in g.get("children") or []:
                flatten_instance(c, out)
    return out


def assignment_keys(assignments: list, group_names: dict, filter_names: dict) -> list:
    out = []
    for a in assignments or []:
        tg = a.get("target") or {}
        typ = str(tg.get("@odata.type", "")).split(".")[-1]
        mode = "exclude" if typ.startswith("exclusion") else "include"
        if typ == "allDevicesAssignmentTarget":
            who = "allDevices"
        elif typ == "allLicensedUsersAssignmentTarget":
            who = "allLicensedUsers"
        else:
            gid = tg.get("groupId")
            who = group_names.get(gid, gid or "?")
        key = f"{mode}:{who}"
        fid = tg.get("deviceAndAppManagementAssignmentFilterId")
        if fid and tg.get("deviceAndAppManagementAssignmentFilterType", "include") != "none":
            key += f"|filter:{filter_names.get(fid, fid)}"
        out.append(key)
    return sorted(out)


def _show(v):
    if isinstance(v, str):
        for p in (_P, "user_vendor_msft_policy_config_", "device_vendor_msft_"):
            if v.startswith(p):
                v = v[len(p):]
        return v.split("~")[-1]
    return v


def compare(spec: dict, actual_values: dict, actual_assign: list) -> list:
    problems = []
    for label, key, exp in spec["settings"]:
        if callable(exp):
            exp = exp()
        if key not in actual_values:
            problems.append({"label": label, "expected": _show(exp), "actual": None, "kind": "missing"})
            continue
        got = actual_values[key]
        if got != exp:
            problems.append({"label": label, "expected": _show(exp), "actual": _show(got), "kind": "changed"})
    want = sorted(spec["assign"])
    if actual_assign != want:
        problems.append({"label": "Assignment", "expected": " · ".join(want),
                         "actual": " · ".join(actual_assign) or "—", "kind": "changed"})
    return problems


def _recent(ts, now) -> bool:
    try:
        t = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return (now - t).days < RECENT_DAYS
    except (TypeError, ValueError):
        return False


def build_findings(items: list) -> list:
    bad = [i for i in items if i["status"] in ("changed", "missing")]
    unk = [i for i in items if i["status"] == "unknown"]
    out = []
    if bad:
        names = " · ".join(i["name"] for i in bad)
        out.append(finding(
            "med",
            en=f"{len(bad)} Intune policy(ies) differ from the recorded baseline: {names}. If the change "
               "was deliberate, update the baseline in app/sources/intune_baseline.py; if not, put it back.",
            ko=f"Intune 정책 {len(bad)}개가 기록된 기준과 다릅니다: {names}. 일부러 바꾼 것이면 "
               "app/sources/intune_baseline.py 의 기준을 같이 고치고, 아니면 되돌리십시오."))
    if unk:
        out.append(finding(
            "low",
            en=f"Could not read {len(unk)} policy(ies): {' · '.join(i['name'] for i in unk)} - state unknown, not 'fine'.",
            ko=f"정책 {len(unk)}개를 읽지 못했습니다: {' · '.join(i['name'] for i in unk)} — '정상' 이 아니라 '모름' 입니다."))
    return out


async def _pages(url, params=None):
    out = []
    d = await graph_get(url, params=params)
    while True:
        out.extend(d.get("value", []))
        nxt = d.get("@odata.nextLink")
        if not nxt:
            return out
        d = await graph_get(nxt)


async def _admx_values(cid: str) -> dict:
    vals = {}
    for v in await _pages(f"{_BETA}/groupPolicyConfigurations/{cid}/definitionValues",
                          {"$expand": "definition($select=id)"}):
        did = (v.get("definition") or {}).get("id")
        if not v.get("enabled"):
            vals[did] = "disabled"
            continue
        pv = await _pages(f"{_BETA}/groupPolicyConfigurations/{cid}/definitionValues/{v['id']}/presentationValues")
        if not pv:
            vals[did] = None
        elif pv[0].get("values") is not None:
            vals[did] = [x.get("name") for x in pv[0]["values"]]
        else:
            vals[did] = pv[0].get("value")
    return vals


async def fetch() -> dict:
    now = datetime.now(timezone.utc)
    group_names, filter_names = {}, {}

    async def gname(gid):
        if gid and gid not in group_names:
            try:
                g = await graph_get(f"{_V1}/groups/{gid}", params={"$select": "displayName"})
                group_names[gid] = g.get("displayName") or gid
            except Exception:
                group_names[gid] = gid

    try:
        for f in await _pages(f"{_BETA}/assignmentFilters", {"$select": "id,displayName"}):
            filter_names[f["id"]] = f.get("displayName")
    except Exception:
        pass

    lists = {}
    errors = {}
    for kind, url, params in (
        ("catalog", f"{_BETA}/configurationPolicies", {"$select": "id,name,lastModifiedDateTime", "$expand": "assignments"}),
        ("admx", f"{_BETA}/groupPolicyConfigurations", {"$expand": "assignments"}),
        ("ring", f"{_BETA}/deviceConfigurations", {"$expand": "assignments"}),
        ("ios", f"{_APPS}/iosManagedAppProtections", {"$expand": "assignments"}),
        ("android", f"{_APPS}/androidManagedAppProtections", {"$expand": "assignments"}),
    ):
        try:
            lists[kind] = await _pages(url, params)
        except PermissionError:
            errors[kind] = "403"
        except Exception as e:
            errors[kind] = type(e).__name__

    items = []
    for spec in BASELINE:
        kind = spec["platform"] if spec["kind"] == "mam" else spec["kind"]
        item = {"name": spec["name"], "kind": spec["kind"], "why": spec["why"], "problems": [],
                "lastModified": None, "recent": False, "assign": []}
        if kind in errors:
            item.update(status="unknown", error=errors[kind])
            items.append(item)
            continue
        nm = "displayName" if kind in ("admx", "ring", "ios", "android") else "name"
        found = [p for p in lists.get(kind, []) if p.get(nm) == spec["name"]]
        if not found:
            item["status"] = "missing"
            items.append(item)
            continue
        p = found[0]
        asg = []
        try:
            for a in p.get("assignments") or []:
                await gname((a.get("target") or {}).get("groupId"))
            asg = assignment_keys(p.get("assignments"), group_names, filter_names)
            if spec["kind"] == "catalog":
                vals = {}
                for s in await _pages(f"{_BETA}/configurationPolicies/{p['id']}/settings"):
                    flatten_instance(s.get("settingInstance") or {}, vals)
            elif spec["kind"] == "admx":
                vals = await _admx_values(p["id"])
            else:
                vals = p
            item["problems"] = compare(spec, vals, asg)
            item["status"] = "changed" if item["problems"] else "ok"
            if len(found) > 1:
                item["problems"].append({"label": "Duplicate name", "expected": "1", "actual": str(len(found)), "kind": "changed"})
                item["status"] = "changed"
        except PermissionError:
            item["status"], item["error"] = "unknown", "403"
        except Exception as e:
            item["status"], item["error"] = "unknown", type(e).__name__
        item["lastModified"] = p.get("lastModifiedDateTime")
        item["recent"] = _recent(p.get("lastModifiedDateTime"), now)
        item["assign"] = asg
        items.append(item)

    return {
        "available": True,
        "items": items,
        "okCount": sum(1 for i in items if i["status"] == "ok"),
        "driftCount": sum(1 for i in items if i["status"] in ("changed", "missing")),
        "unknownCount": sum(1 for i in items if i["status"] == "unknown"),
        "findings": build_findings(items),
    }
