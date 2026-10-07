from datetime import datetime, timezone

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
        reg = await graph_get("/deviceAppManagement/managedAppRegistrations", {"$top": "999"})
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
                "app": r.get("appIdentifier"), "reasons": reasons,
                "lastSync": r.get("lastSyncDateTime"),
            })

    registered_ids = set(by_user)
    missing = sorted(upn for uid, upn in people.items() if uid not in registered_ids)

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
               "Treat it as a call list, not as a count of blocked users.",
            ko=f"대상 {len(people)}명 중 **{len(missing)}명**에게 앱 등록이 없습니다. "
               "⛔ 이 숫자는 *아직 안 깔았다* 와 *브로커 앱이 없거나 기기가 검증에 실패했다* 를 "
               "**구분하지 못합니다** — Graph 에 그 차이가 없습니다. **막힌 사람 수가 아니라 "
               "확인해 볼 명단**으로 쓰십시오."))
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
