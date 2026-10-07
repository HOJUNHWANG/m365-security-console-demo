import asyncio
import os

from ..graph_client import graph_get
from ._i18n import finding

SUSPECT_BUILDS = [
    b.strip() for b in os.environ.get("DEFENDER_WSC_SUSPECT_BUILDS", "10.0.26200.9278").split(";")
    if b.strip()
]

SUSPECT_UPDATES = [
    u.strip() for u in os.environ.get("DEFENDER_WSC_SUSPECT_UPDATES", "KB5120998;KB5122385").split(";")
    if u.strip()
]

_SEM = asyncio.Semaphore(6)


def _ver(s):
    out = []
    for part in str(s or "").split("."):
        try:
            out.append(int(part))
        except ValueError:
            out.append(0)
    while len(out) < 4:
        out.append(0)
    return tuple(out[:4])


def _at_or_past(build, suspects):
    v = _ver(build)
    return any(v >= _ver(s) for s in suspects)


_SENTINELS = ("0001", "9999")


def _real_deadline(exp) -> bool:
    return bool(exp) and not str(exp).startswith(_SENTINELS)


async def _protection(dev):
    async with _SEM:
        try:
            wp = await graph_get(f"/deviceManagement/managedDevices/{dev['id']}/windowsProtectionState")
        except Exception:
            return dev, None
    return dev, wp


async def fetch() -> dict:
    devices = []
    d = await graph_get("/deviceManagement/managedDevices", params={
        "$select": "id,deviceName,operatingSystem,osVersion,complianceState,userPrincipalName,"
                   "complianceGracePeriodExpirationDateTime",
        "$top": 999})
    while True:
        devices.extend(d.get("value", []))
        nxt = d.get("@odata.nextLink")
        if not nxt:
            break
        d = await graph_get(nxt)

    windows = [x for x in devices if (x.get("operatingSystem") or "").lower().startswith("windows")]
    results = await asyncio.gather(*(_protection(x) for x in windows))

    rows, unread = [], []
    for dev, wp in results:
        if wp is None:
            unread.append(dev.get("deviceName"))
            continue
        rtp = wp.get("realTimeProtectionEnabled")
        rows.append({
            "name": dev.get("deviceName"),
            "osVersion": dev.get("osVersion"),
            "compliance": dev.get("complianceState"),
            "defenderPrimary": rtp is True,
            "realTimeProtection": rtp,
            "malwareProtection": wp.get("malwareProtectionEnabled"),
            "deviceState": wp.get("deviceState"),
            "signatureVersion": wp.get("antivirusSignatureVersion"),
            "graceExpires": dev.get("complianceGracePeriodExpirationDateTime"),
            "onSuspectBuild": _at_or_past(dev.get("osVersion"), SUSPECT_BUILDS) if SUSPECT_BUILDS else False,
        })

    rows.sort(key=lambda r: (not r["defenderPrimary"], r["name"] or ""))
    defender_primary = [r for r in rows if r["defenderPrimary"]]
    exposed = [r for r in defender_primary if r["onSuspectBuild"]]
    shielded = [r for r in rows if r["onSuspectBuild"] and not r["defenderPrimary"]]

    _FAILING = {"noncompliant", "ingraceperiod", "error", "conflict"}
    failing = [r for r in defender_primary
               if str(r.get("compliance") or "").lower() in _FAILING]
    compliance_unread = [r for r in defender_primary if r.get("compliance") is None]

    findings = []

    if failing:
        parts = []
        for r in failing:
            exp = r.get("graceExpires")
            has_exp = _real_deadline(exp)
            parts.append(f"{r['name'] or '?'} ({r['compliance']}"
                         + (f", 유예 만료 {exp}" if has_exp else "") + ")")
        names = " · ".join(parts)
        en_parts = " / ".join(
            f"{r['name'] or '?'} ({r['compliance']}"
            + (f", grace expires {r.get('graceExpires')}"
               if _real_deadline(r.get("graceExpires")) else "") + ")"
            for r in failing)
        findings.append(finding(
            "high",
            en=f"{len(failing)} device(s) that rely on Defender's own Security Center registration "
               f"are NOT compliant right now: {en_parts}. This is the population a Security Center "
               f"reporting break hits, and the failing rule is the antivirus one. Defender's own "
               f"report may say the device is healthy - check that first, and if it is, the fix is "
               f"a real check-in from the device (a reboot; an Intune Sync does not force a "
               f"re-evaluation, and the web Company Portal does not reach the device). When the "
               f"grace period expires, Entra flips isCompliant to false and Conditional Access "
               f"blocks the user. Not on a suspect build does not mean not affected. "
               f"Consider whether `antivirusRequired` should stay in the compliance policy: the "
               f"rule reads the Security Center registration, not antivirus health, and "
               f"`antiSpywareRequired` already covers 'no security product registered'.",
            ko=f"**Defender 자신의 보안 센터 등록에 의존하는 기기 {len(failing)}대가 지금 준수가 "
               f"아닙니다**: {names}. 보안 센터 보고 누락이 생기면 영향을 받는 모집단이 바로 이들이고, "
               f"떨어지는 규칙이 백신 항목입니다. Defender 자체 보고로는 기기가 정상일 수 "
               f"있습니다 — 먼저 그것을 확인하고, 정상이면 조치는 **기기에서의 실제 체크인**"
               f"입니다(재부팅. Intune Sync 는 준수 재평가를 강제하지 않고, 웹 회사 포털은 "
               f"기기에 닿지 않습니다). 유예가 만료되면 Entra 의 isCompliant 가 false 로 "
               f"뒤집히고 조건부 액세스가 그 사용자를 막습니다. **의심 빌드가 아니라는 것이 "
               f"영향이 없다는 뜻은 아닙니다.** 준수 정책에 `antivirusRequired` 를 계속 둘지 "
               f"검토하십시오. 이 규칙은 백신 건강도가 아니라 보안 센터 등록만 읽고, "
               f"'보안 제품이 하나도 등록되지 않음' 은 `antiSpywareRequired` 가 이미 잡습니다."))

    if compliance_unread:
        names = ", ".join(r["name"] or "?" for r in compliance_unread)
        findings.append(finding(
            "med",
            en=f"complianceState could not be read for {len(compliance_unread)} Defender-primary "
               f"device(s): {names}. They are unclassified, not compliant - the list above is "
               f"incomplete by that many. Check the $select on the managedDevices query.",
            ko=f"Defender 주력 기기 {len(compliance_unread)}대의 complianceState 를 읽지 "
               f"못했습니다: {names}. 이 기기들은 '준수' 가 아니라 **분류되지 않은 것**이고, "
               f"위 목록은 그만큼 불완전합니다. managedDevices 조회의 $select 를 확인하십시오."))

    if unread:
        findings.append(finding(
            "med",
            en=f"Defender protection state could not be read for {len(unread)} device(s): "
               f"{', '.join(sorted(x or '?' for x in unread))}. Those devices are unclassified, not "
               f"clear - the exposure list below is incomplete by that many.",
            ko=f"기기 {len(unread)}대의 Defender 보호 상태를 읽지 못했습니다: "
               f"{', '.join(sorted(x or '?' for x in unread))}. 이 기기들은 '문제 없음' 이 아니라 "
               f"**분류되지 않은 것**이고, 아래 노출 목록은 그만큼 불완전합니다."))

    if exposed:
        names = ", ".join(r["name"] or "?" for r in exposed)
        findings.append(finding(
            "high",
            en=f"{len(exposed)} device(s) rely on Defender's own Security Center registration AND are "
               f"on a build under suspicion ({', '.join(SUSPECT_BUILDS)}, arrived with "
               f"{', '.join(SUSPECT_UPDATES)}): {names}. That is the exact combination that produces "
               f"a false antivirus block. If one of these reports its antivirus setting as "
               f"non-compliant, a check-in resolves it - do not go looking at the antivirus.",
            ko=f"기기 {len(exposed)}대가 **Defender 자신의 보안 센터 등록에 의존하면서** 의심 빌드"
               f"({', '.join(SUSPECT_BUILDS)}, {', '.join(SUSPECT_UPDATES)} 와 함께 들어옴)에 "
               f"있습니다: {names}. 백신 항목 오차단을 만드는 조합이 정확히 이것입니다. 이 중 하나가 "
               f"백신 항목을 비준수로 보고하면 **체크인 한 번으로 해결됩니다 - 백신을 들여다보지 "
               f"마십시오.**"))
    elif defender_primary:
        names = ", ".join(r["name"] or "?" for r in defender_primary)
        findings.append(finding(
            "low",
            en=f"{len(defender_primary)} device(s) rely on Defender's own Security Center "
               f"registration for the antivirus compliance rule: {names}. None is on a suspect build "
               f"yet. These are the only devices a Security Center reporting break would be "
               f"visible on; the other {len(rows) - len(defender_primary)} are carried by a "
               f"third-party antivirus registration and would show nothing.",
            ko=f"기기 {len(defender_primary)}대가 백신 준수 규칙에서 **Defender 자신의 보안 센터 "
               f"등록에 의존**합니다: {names}. 아직 의심 빌드에 있는 기기는 없습니다. "
               f"보안 센터 보고 누락이 생기면 드러나는 기기는 이들뿐이고, 나머지 "
               f"{len(rows) - len(defender_primary)}대는 타사 백신 등록이 규칙을 받쳐주므로 "
               f"아무것도 보이지 않습니다."))
    else:
        findings.append(finding(
            "ok",
            en="No device depends on Defender's own Security Center registration - every one is "
               "carried by a third-party antivirus registration.",
            ko="Defender 자신의 보안 센터 등록에 의존하는 기기가 없습니다 - 전부 타사 백신 등록이 "
               "규칙을 받쳐주고 있습니다."))

    order = {"high": 0, "med": 1, "low": 2, "ok": 3}
    findings.sort(key=lambda f: order.get(f["severity"], 9))

    return {
        "available": True,
        "note": "The antivirus compliance rule reads the Windows Security Center registration, not "
                "antivirus health. Where a third-party product holds that registration, Defender's "
                "own registration can break with no effect on compliance - so a fleet-wide "
                "'all compliant' does not mean antivirus reporting is intact.",
        "caveat": "A rollback that fixes such a block usually also reboots the device, and a reboot "
                  "forces a fresh compliance evaluation by itself, so the update is not proven to be "
                  "the cause. The suspect build list is a watchlist, not a verdict.",
        "suspectBuilds": SUSPECT_BUILDS,
        "suspectUpdates": SUSPECT_UPDATES,
        "windowsCount": len(windows),
        "readCount": len(rows),
        "unreadCount": len(unread),
        "unreadDevices": sorted(x or "?" for x in unread),
        "defenderPrimaryCount": len(defender_primary),
        "defenderPrimaryFailing": failing,
        "defenderPrimaryFailingCount": len(failing),
        "complianceUnreadCount": len(compliance_unread),
        "thirdPartyPrimaryCount": len(rows) - len(defender_primary),
        "exposedCount": len(exposed),
        "shieldedCount": len(shielded),
        "defenderPrimary": defender_primary,
        "exposed": exposed,
        "devices": rows,
        "findings": findings,
    }
