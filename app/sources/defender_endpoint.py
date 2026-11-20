from datetime import datetime, timezone

from ..graph_client import graph_get, graph_post
from ._i18n import finding

_BETA = "https://graph.microsoft.com/beta"
MDE_CONNECTOR_ID = "fc780465-2017-40d4-a0c5-307022471b92"
HEARTBEAT_STALE_H = 24
SILENT_H = 48
INTUNE_RECENT_H = 24
_NEVER = "0001-01-01"

HUNT_DAYS = 30

HUNT = f"""DeviceInfo
| where Timestamp > ago({HUNT_DAYS}d)
| summarize arg_max(Timestamp, DeviceName, OnboardingStatus, SensorHealthState, OSPlatform, AadDeviceId) by DeviceId
| project DeviceId, LastSeen = Timestamp, DeviceName, OnboardingStatus, SensorHealthState, OSPlatform, AadDeviceId"""

_ELIGIBLE = {"pro", "business", "enterprise", "education", "proeducation", "proworkstation"}


def _short(name: str) -> str:
    return str(name or "").split(".")[0].strip().lower()


def connector_state(connectors: list) -> dict:
    c = next((x for x in connectors or [] if x.get("id") == MDE_CONNECTOR_ID), None)
    if not c:
        return {"exists": False, "partnerState": None, "lastHeartbeat": None, "windowsEnabled": False}
    hb = c.get("lastHeartbeatDateTime")
    return {
        "exists": True,
        "partnerState": c.get("partnerState"),
        "lastHeartbeat": None if not hb or str(hb).startswith(_NEVER) else hb,
        "windowsEnabled": bool(c.get("windowsEnabled")),
    }


def match_devices(intune: list, hunt_rows: list, now_iso: str | None = None) -> dict:
    onboarded = [r for r in hunt_rows or [] if (r.get("OnboardingStatus") or "") == "Onboarded"]
    by_aad = {str(r.get("AadDeviceId") or "").lower(): r for r in onboarded if r.get("AadDeviceId")}
    by_name = {_short(r.get("DeviceName")): r for r in onboarded}
    rows, home, used = [], 0, set()
    for d in intune or []:
        edition = str(d.get("skuFamily") or "").lower().replace(" ", "")
        if edition in ("home", "core"):
            home += 1
            continue
        r = by_aad.get(str(d.get("azureADDeviceId") or "").lower()) or by_name.get(_short(d.get("deviceName")))
        if r:
            used.add(r.get("DeviceId"))
        health = (r or {}).get("SensorHealthState") or ""
        silent = bool(r) and bool(now_iso)             and _hours_between(r.get("LastSeen"), now_iso) > SILENT_H             and _hours_between(d.get("lastSyncDateTime"), now_iso) <= INTUNE_RECENT_H
        rows.append({
            "name": d.get("deviceName"),
            "user": d.get("userPrincipalName"),
            "edition": d.get("skuFamily") or "unknown",
            "eligible": edition in _ELIGIBLE,
            "onboarded": bool(r),
            "sensorHealth": health or None,
            "lastSeen": (r or {}).get("LastSeen"),
            "intuneSync": d.get("lastSyncDateTime"),
            "silent": silent,
            "healthy": bool(r) and health == "Active" and not silent,
        })
    orphans = [{"name": r.get("DeviceName"), "sensorHealth": r.get("SensorHealthState"),
                "lastSeen": r.get("LastSeen"), "os": r.get("OSPlatform")}
               for r in onboarded if r.get("DeviceId") not in used]
    discovered = sum(1 for r in hunt_rows or [] if (r.get("OnboardingStatus") or "") != "Onboarded")
    rows.sort(key=lambda x: (not x["onboarded"], x["healthy"], x["name"] or ""))
    return {"devices": rows, "homeCount": home, "orphans": orphans, "discoveredCount": discovered}


def build_findings(conn: dict, m: dict, hunt_error: str | None, now_iso: str) -> list:
    out = []
    ps = (conn.get("partnerState") or "").lower()
    if not conn["exists"]:
        out.append(finding(
            "med",
            en="Intune has no Defender for Endpoint connector. Defender's 'Microsoft Intune connection' "
               "switch can read On while this is missing (seen 2026-11-03) - no EDR policy can onboard "
               "a device until Intune shows the connection as Enabled.",
            ko="Intune 에 Defender for Endpoint 커넥터가 없습니다. Defender 의 'Microsoft Intune connection' "
               "스위치가 On 이어도 이 상태일 수 있습니다(2026-11-03 실측) — Intune 에서 연결이 Enabled 가 "
               "되기 전에는 EDR 정책으로 기기를 온보딩할 수 없습니다."))
    elif ps in ("unresponsive", "error", "unavailable"):
        out.append(finding(
            "high",
            en=f"Defender for Endpoint connector is '{conn['partnerState']}'. Intune stops using "
               f"Defender's data and onboarding stalls. Toggle 'Microsoft Intune connection' Off/On in "
               f"Defender (Settings > Endpoints > Advanced features) and refresh Intune.",
            ko=f"Defender for Endpoint 커넥터 상태가 '{conn['partnerState']}' 입니다. Intune 이 Defender "
               f"데이터를 쓰지 않고 온보딩이 멈춥니다. Defender(Settings > Endpoints > Advanced features)의 "
               f"'Microsoft Intune connection' 을 Off/On 하고 Intune 을 새로 고치십시오."))
    elif ps == "notsetup" or not conn["lastHeartbeat"]:
        out.append(finding(
            "med",
            en="Defender for Endpoint connector exists but Defender has not checked in yet "
               f"(partnerState '{conn['partnerState']}', no heartbeat). Intune keeps its toggles greyed "
               "out until it does.",
            ko="Defender for Endpoint 커넥터는 생겼지만 Defender 가 아직 응답하지 않았습니다"
               f"(partnerState '{conn['partnerState']}' · heartbeat 없음). 응답 전까지 Intune 토글이 잠겨 있습니다."))
    else:
        if _hours_between(conn["lastHeartbeat"], now_iso) > HEARTBEAT_STALE_H:
            out.append(finding(
                "high",
                en=f"Defender for Endpoint connector last heartbeat {conn['lastHeartbeat']} - over "
                   f"{HEARTBEAT_STALE_H}h ago.",
                ko=f"Defender for Endpoint 커넥터 마지막 heartbeat {conn['lastHeartbeat']} — "
                   f"{HEARTBEAT_STALE_H}시간 넘게 응답 없음."))
        if not conn["windowsEnabled"]:
            out.append(finding(
                "low",
                en="Connector is up but 'Connect Windows devices ... to Microsoft Defender for Endpoint' is "
                   "Off in Intune - an EDR policy set to 'Auto from connector' has no package to deploy.",
                ko="커넥터는 연결됐지만 Intune 의 'Connect Windows devices ... to Microsoft Defender for "
                   "Endpoint' 가 Off 입니다 — 'Auto from connector' EDR 정책이 배포할 패키지가 없습니다."))
    if hunt_error:
        out.append(finding(
            "low",
            en=f"Advanced Hunting DeviceInfo could not be read ({hunt_error}) - onboarding status below "
               f"is unknown, not 'none'.",
            ko=f"Advanced Hunting DeviceInfo 를 읽지 못했습니다({hunt_error}) — 아래 온보딩 상태는 "
               f"'없음' 이 아니라 '모름' 입니다."))
    silent = [d for d in m["devices"] if d.get("silent")]
    if silent:
        names = " · ".join(f"{d['name']} (Defender {str(d['lastSeen'])[:10]} · Intune {str(d['intuneSync'])[:10]})"
                           for d in silent)
        out.append(finding(
            "med",
            en=f"{len(silent)} onboarded device(s) checking in to Intune but silent in Defender for over "
               f"{SILENT_H}h: {names}. The last sensor state still reads Active, so this is the only place it "
               f"shows. It has cleared on its own before (LAPTOP-DEMO901, 6 days, 2026-11), so wait a few days "
               f"first. If it persists: reboot once, then on the PC 'sc query sense' and Event Viewer > "
               f"Microsoft > Windows > SENSE > Operational, then compare the same time in the SentinelOne "
               f"console. SentinelOne is on every laptop including the healthy ones, so it is not a cause "
               f"by itself.",
            ko=f"Intune 에는 연결되는데 Defender 보고가 {SILENT_H}시간 넘게 없는 기기 {len(silent)}대: {names}. "
               f"마지막 센서 상태는 아직 Active 라 여기서만 보입니다. 저절로 풀린 적이 있으므로"
               f"(LAPTOP-DEMO901 · 6일 · 2026-11) 며칠 먼저 지켜보십시오. 계속되면 재부팅 1회 → PC 에서 "
               f"'sc query sense' 와 이벤트 뷰어 > Microsoft > Windows > SENSE > Operational → 같은 시각의 "
               f"SentinelOne 콘솔 대조 순서입니다. SentinelOne 은 정상 기기를 포함한 모든 노트북에 있으므로 "
               f"그 자체로 원인이 아닙니다."))
    sick = [d for d in m["devices"] if d["onboarded"] and not d["healthy"] and not d.get("silent")]
    if sick:
        names = " · ".join(f"{d['name']} ({d['sensorHealth'] or '?'})" for d in sick)
        out.append(finding(
            "med",
            en=f"{len(sick)} onboarded device(s) with a sensor that is not Active: {names}. "
               f"'ImpairedCommunication' can mean the sensor cannot reach Defender through HQ SASE TLS "
               f"inspection (not confirmed) - compare with SASE on and off.",
            ko=f"온보딩됐지만 센서가 Active 가 아닌 기기 {len(sick)}대: {names}. "
               f"'ImpairedCommunication' 은 본사 SASE 의 TLS 재서명 때문에 센서가 Defender 에 못 닿는 "
               f"경우일 수 있습니다(미확인) — SASE 켠/끈 상태를 비교하십시오."))
    return out


def _hours_between(a: str, b: str) -> float:
    try:
        ta = datetime.fromisoformat(str(a).replace("Z", "+00:00"))
        tb = datetime.fromisoformat(str(b).replace("Z", "+00:00"))
        return (tb - ta).total_seconds() / 3600
    except (TypeError, ValueError):
        return 0.0


async def fetch() -> dict:
    now = datetime.now(timezone.utc).isoformat()

    c = await graph_get(f"{_BETA}/deviceManagement/mobileThreatDefenseConnectors")
    conn = connector_state(c.get("value", []))

    intune = []
    d = await graph_get(f"{_BETA}/deviceManagement/managedDevices", params={
        "$filter": "operatingSystem eq 'Windows'",
        "$select": "deviceName,userPrincipalName,skuFamily,azureADDeviceId,lastSyncDateTime",
        "$top": 999})
    while True:
        intune.extend(d.get("value", []))
        nxt = d.get("@odata.nextLink")
        if not nxt:
            break
        d = await graph_get(nxt)

    hunt_rows, hunt_error = [], None
    try:
        res = await graph_post("/security/runHuntingQuery", {"Query": HUNT})
        hunt_rows = res.get("results", [])
    except PermissionError:
        hunt_error = "403"
    except Exception as e:
        hunt_error = type(e).__name__

    m = match_devices(intune, hunt_rows, now)
    eligible = [x for x in m["devices"] if x["eligible"]]
    return {
        "available": True,
        "connector": conn,
        "huntError": hunt_error,
        "eligibleCount": len(eligible),
        "onboardedCount": sum(1 for x in eligible if x["onboarded"]),
        "healthyCount": sum(1 for x in eligible if x["healthy"]),
        "homeCount": m["homeCount"],
        "devices": m["devices"],
        "orphans": m["orphans"],
        "discoveredCount": m["discoveredCount"],
        "findings": build_findings(conn, m, hunt_error, now),
    }
