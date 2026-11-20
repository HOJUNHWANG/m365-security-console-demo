from datetime import datetime, timedelta, timezone

from ..graph_client import graph_get
from ._i18n import finding, unavailable

_STALE_DAYS = 14
_LIST_CAP = 200
_POLICY_PATHS = (
    ("/deviceAppManagement/iosManagedAppProtections", "iOS"),
    ("/deviceAppManagement/androidManagedAppProtections", "Android"),
)


def _parse(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except Exception:
        return None


_APP_ID_KEYS = ("bundleId", "packageId", "windowsAppId")


def app_identifier_str(a) -> str:
    if isinstance(a, str):
        return a
    if not isinstance(a, dict):
        return ""
    for k in _APP_ID_KEYS:
        if a.get(k):
            return str(a[k])
    for k, v in a.items():
        if not k.startswith("@") and isinstance(v, str) and v:
            return v
    return str(a.get("@odata.type") or "").split(".")[-1]


def _app_id(r) -> str:
    return app_identifier_str(r.get("appIdentifier"))


def _mobile_app_id(r) -> str:
    a = r.get("appIdentifier")
    if not isinstance(a, dict):
        return ""
    return a.get("bundleId") or a.get("packageId") or ""


def devices_per_user(rows: list, people: dict) -> list:
    by = {}
    for r in rows:
        if not _mobile_app_id(r).startswith("com.microsoft.") or not r.get("deviceTag") or not r.get("userId"):
            continue
        d = by.setdefault(r["userId"], {}).setdefault(r["deviceTag"], {
            "type": r.get("deviceType") or r.get("deviceName") or "?", "os": r.get("platformVersion"),
            "created": None, "lastSync": None, "apps": set()})
        d["apps"].add(_mobile_app_id(r).split(".")[-1])
        c, s = r.get("createdDateTime"), r.get("lastSyncDateTime")
        if c and (not d["created"] or c < d["created"]):
            d["created"] = c
        if s and (not d["lastSync"] or s > d["lastSync"]):
            d["lastSync"] = s
            d["os"] = r.get("platformVersion") or d["os"]
    out = []
    for uid, tags in by.items():
        if len(tags) < 2:
            continue
        devs = sorted(tags.values(), key=lambda d: d["created"] or "")
        newest_created = _parse(devs[-1]["created"])
        replaced = False
        if newest_created and len(devs) == 2:
            old_sync = _parse(devs[0]["lastSync"])
            replaced = bool(old_sync and (old_sync - newest_created).days < 1)
        out.append({
            "user": people.get(uid) or (uid or "")[:8] + "…",
            "count": len(devs),
            "likelyReplaced": replaced,
            "devices": [{"type": d["type"], "os": d["os"], "created": (d["created"] or "")[:10],
                         "lastSync": (d["lastSync"] or "")[:10], "apps": sorted(d["apps"])} for d in devs],
        })
    out.sort(key=lambda x: (x["likelyReplaced"], -x["count"], x["user"]))
    return out


_BETA_REGS = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppRegistrations"

_ENFORCE_HOLD = None
_ENFORCE_PLAN = {"noticeSent": "2026-01-05", "enforceOn": "2026-01-20",
                 "policy": "CA11 - Require app protection for mobile", "ref": "",
                 "missingAtNotice": 12}
_WARN_DAYS_BEFORE = 7


def enforce_plan(plan, now) -> dict | None:
    if not plan:
        return None
    try:
        d = datetime.fromisoformat(plan["enforceOn"]).date()
    except (KeyError, ValueError):
        return None
    left = (d - now.date()).days
    return {**plan, "daysLeft": left, "warnDaysBefore": _WARN_DAYS_BEFORE,
            "warnFrom": (d - timedelta(days=_WARN_DAYS_BEFORE)).isoformat(),
            "warning": left <= _WARN_DAYS_BEFORE}


def _latest_mobile(rows: list, people: dict) -> dict:
    latest = {}
    for r in rows:
        app = _mobile_app_id(r).lower()
        kind = "outlook" if "outlook" in app else "teams" if "teams" in app else None
        if not kind or not r.get("userId"):
            continue
        if people and r["userId"] not in people:
            continue
        k = (r["userId"], kind)
        if k not in latest or (r.get("lastSyncDateTime") or "") > (latest[k].get("lastSyncDateTime") or ""):
            latest[k] = r
    return latest


_STATUS_ORDER = {"register": 0, "reopen": 1, "idle": 2, "none": 3, "ready": 4}


def people_status(rows: list, people: dict, ios_owners, now=None, active_days: int = _STALE_DAYS) -> list:
    now = now or datetime.now(timezone.utc)
    latest = _latest_mobile(rows, people)
    per = {}
    for (uid, kind), r in latest.items():
        per.setdefault(uid, {})[kind] = r
    out = []
    for uid in (people or {u for u, _ in latest}):
        apps = per.get(uid, {})
        cell, plats, last, gap_active, gap_any = {}, set(), "", False, False
        for kind in ("outlook", "teams"):
            r = apps.get(kind)
            if not r:
                cell[kind] = None
                continue
            plats.add("iOS" if "ios" in (r.get("@odata.type") or "").lower() else "Android")
            has = bool(r.get("azureADDeviceId"))
            cell[kind] = "id" if has else "noId"
            sync = r.get("lastSyncDateTime") or ""
            last = max(last, sync)
            if not has:
                gap_any = True
                ts = _parse(sync)
                gap_active = gap_active or bool(ts and (now - ts).days < active_days)
        dev = None if ios_owners is None else (uid in ios_owners)
        if not apps:
            st = "none"
        elif gap_active:
            st = "reopen" if dev else "register"
        elif gap_any:
            st = "idle"
        else:
            st = "ready"
        out.append({"user": (people or {}).get(uid) or (uid or "")[:8] + "…", "status": st,
                     "platform": " · ".join(sorted(plats)), "outlook": cell["outlook"], "teams": cell["teams"],
                     "iosDeviceInTenant": dev, "lastUsed": last or None})
    out.sort(key=lambda x: (_STATUS_ORDER[x["status"]], x["user"].lower()))
    return out[:_LIST_CAP]


def device_id_gaps(rows: list, people: dict, now=None, active_days: int = _STALE_DAYS) -> dict:
    now = now or datetime.now(timezone.utc)
    latest = _latest_mobile(rows, people)
    by_plat = {}
    missing, missing_active = set(), set()
    for (uid, kind), r in latest.items():
        plat = "iOS" if "ios" in (r.get("@odata.type") or "").lower() else "Android"
        has = bool(r.get("azureADDeviceId"))
        c = by_plat.setdefault(f"{plat} {kind}", {"withId": 0, "withoutId": 0})
        c["withId" if has else "withoutId"] += 1
        if not has:
            missing.add(uid)
            ts = _parse(r.get("lastSyncDateTime"))
            if ts and (now - ts).days < active_days:
                missing_active.add(uid)
    return {
        "measured": bool(latest),
        "people": len({u for u, _ in latest}),
        "missingPeople": len(missing),
        "missingActivePeople": len(missing_active),
        "activeDays": active_days,
        "byApp": by_plat,
        "missingActiveUsers": sorted(people.get(u) or (u or "")[:8] + "…" for u in missing_active)[:_LIST_CAP],
    }


async def _targeted() -> tuple[dict, list]:
    people, groups = {}, []
    for path, plat in _POLICY_PATHS:
        pol = await graph_get(path, {"$top": "50"})
        for p in (pol.get("value") or []):
            asg = await graph_get(f"{path}/{p['id']}/assignments", None)
            for a in (asg.get("value") or []):
                gid = (a.get("target") or {}).get("groupId")
                if not gid:
                    continue
                g = await graph_get(f"/groups/{gid}", {"$select": "displayName,id"})
                name = g.get("displayName") or gid
                m = await graph_get(f"/groups/{gid}/transitiveMembers",
                                    {"$top": "999", "$select": "id,userPrincipalName,displayName"})
                n = 0
                for x in (m.get("value") or []):
                    if not x.get("userPrincipalName"):
                        continue
                    people[x["id"]] = x.get("userPrincipalName")
                    n += 1
                if name not in [q["group"] for q in groups]:
                    groups.append({"group": name, "platform": plat, "people": n})
                else:
                    for q in groups:
                        if q["group"] == name and plat not in q["platform"]:
                            q["platform"] += f" · {plat}"
    return people, groups


async def fetch() -> dict:
    try:
        reg = await graph_get(_BETA_REGS, {"$top": "999"})
    except Exception as e:
        return unavailable(
            en=f"managedAppRegistrations read failed: {str(e)[:120]}",
            ko=f"managedAppRegistrations 를 읽지 못했습니다: {str(e)[:120]}")

    rows = reg.get("value") or []
    try:
        people, groups = await _targeted()
    except Exception as e:
        people, groups = {}, []
        scope_err = str(e)[:120]
    else:
        scope_err = None

    try:
        dv = await graph_get("/devices", {"$filter": "operatingSystem eq 'iOS'", "$select": "id",
                                          "$expand": "registeredOwners($select=id)", "$top": "999"})
        ios_owners = {o.get("id") for d in (dv.get("value") or []) for o in (d.get("registeredOwners") or [])}
    except Exception:
        ios_owners = None

    now = datetime.now(timezone.utc)
    by_user, flagged, stale, plat = {}, [], 0, {}
    for r in rows:
        uid = r.get("userId")
        if uid:
            by_user.setdefault(uid, []).append(r)
        reasons = [x for x in (r.get("flaggedReasons") or []) if x and x != "none"]
        ts = _parse(r.get("lastSyncDateTime"))
        old = bool(ts and (now - ts).days >= _STALE_DAYS)
        stale += int(old)
        dt = (r.get("deviceType") or r.get("@odata.type", "").split(".")[-1] or "?")
        plat[dt] = plat.get(dt, 0) + 1
        if reasons:
            flagged.append({
                "user": people.get(uid) or (uid or "")[:8] + "…",
                "device": r.get("deviceName"), "platform": r.get("platformVersion"),
                "app": _app_id(r), "reasons": reasons,
                "lastSync": r.get("lastSyncDateTime"),
            })

    registered_ids = set(by_user)
    missing = sorted(upn for uid, upn in people.items() if uid not in registered_ids)
    multi = devices_per_user(rows, people)

    out = {
        "available": True,
        "registrationCount": len(rows),
        "registeredUsers": len(registered_ids),
        "targetedUsers": len(people),
        "notRegistered": len(missing),
        "notRegisteredUsers": missing[:_LIST_CAP],
        "notRegisteredTruncated": max(0, len(missing) - _LIST_CAP),
        "flagged": flagged,
        "flaggedCount": len(flagged),
        "staleRegistrations": stale,
        "staleDays": _STALE_DAYS,
        "byPlatform": plat,
        "groups": groups,
        "scopeError": scope_err,
        "multiDevice": multi,
        "multiDeviceCount": sum(1 for m in multi if not m["likelyReplaced"]),
        "replacedCount": sum(1 for m in multi if m["likelyReplaced"]),
        "deviceIdGaps": device_id_gaps(rows, people, now),
        "peopleStatus": people_status(rows, people, ios_owners, now) if people else [],
        "iosDeviceLookup": ios_owners is not None,
        "enforceHold": _ENFORCE_HOLD,
        "enforcePlan": enforce_plan(_ENFORCE_PLAN, now),
    }

    findings = []
    if scope_err:
        findings.append(finding(
            "med",
            en=f"Could not read the policy's target groups ({scope_err}). Registration counts are "
               "shown, but 'who is missing' cannot be computed without the target set.",
            ko=f"정책의 대상 그룹을 읽지 못했습니다 ({scope_err}). 등록 수는 나오지만 "
               "대상 집합이 없으면 **누가 빠졌는지**를 계산할 수 없습니다."))
    if flagged:
        findings.append(finding(
            "high",
            en=f"{len(flagged)} app registration(s) are flagged (rooted / bootloader unlocked / "
               "modified ROM). These devices hold company data in managed apps right now.",
            ko=f"앱 등록 {len(flagged)}건이 **플래그** 상태입니다(루팅 · 부트로더 해제 · ROM 변조). "
               "그 기기들이 지금 관리 앱 안에 회사 데이터를 들고 있습니다."))
    if people and missing:
        findings.append(finding(
            "med" if len(missing) > len(people) * 0.25 else "low",
            en=f"{len(missing)} of {len(people)} targeted people have no app registration. "
               "⛔ This number cannot tell 'has not installed yet' apart from 'the broker app is "
               "missing or the device failed attestation' - Graph does not expose the difference. "
               "Treat it as a call list, not as a count of blocked users. This is the app protection "
               "POLICY target, not the CA list - who CA would block is 'No device ID'.",
            ko=f"대상 {len(people)}명 중 **{len(missing)}명**에게 앱 등록이 없습니다. "
               "⛔ 이 숫자는 *아직 안 깔았다* 와 *브로커 앱이 없거나 기기가 검증에 실패했다* 를 "
               "**구분하지 못합니다** — Graph 에 그 차이가 없습니다. **막힌 사람 수가 아니라 "
               "확인해 볼 명단**으로 쓰십시오. 앱 보호 **정책** 대상 기준이며 CA 로 막힐 명단이 "
               "아닙니다 — 그건 '기기 ID 없음' 입니다."))
    if stale:
        findings.append(finding(
            "low",
            en=f"{stale} registration(s) have not checked in for {_STALE_DAYS}+ days. Policy changes "
               "do not reach an app that never checks in.",
            ko=f"등록 {stale}건이 {_STALE_DAYS}일 이상 체크인하지 않았습니다. "
               "체크인하지 않는 앱에는 **정책 변경이 닿지 않습니다.**"))
    if not rows:
        findings.append(finding(
            "med",
            en="No app registrations at all. Either nobody has opened a managed app yet, or the "
               "policy is not reaching anyone.",
            ko="앱 등록이 **한 건도 없습니다.** 아무도 관리 앱을 안 열었거나, 정책이 아무에게도 "
               "닿지 않고 있습니다."))

    _rank = {"high": 0, "med": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: _rank.get(f["severity"], 9))
    out["findings"] = findings
    out["findingCount"] = len(findings)
    out["highFindingCount"] = sum(1 for f in findings if f["severity"] == "high")
    return out
