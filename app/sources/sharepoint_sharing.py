import json
from datetime import date, datetime
from pathlib import Path

from ..graph_client import graph_get
from ._i18n import finding

_ROOT = Path(__file__).resolve().parents[2]
_SNAPSHOT = _ROOT / "data" / "spo_sharing.json"
_INTENT = _ROOT / "data" / "sharing-intent.json"
_ANON = "externaluserandguestsharing"


def _load(path):
    if not path.exists():
        return None, None
    try:
        return json.loads(path.read_text(encoding="utf-8-sig")), None
    except Exception as exc:
        return None, f"{type(exc).__name__}: {exc}"


def _per_site():
    snap, snap_err = _load(_SNAPSHOT)
    intent, intent_err = _load(_INTENT)
    if snap_err or intent_err:
        return None, (snap_err or intent_err)
    if snap is None:
        return None, None

    want = {}
    for row in ((intent or {}).get("intended") or []):
        u = (row.get("url") or "").rstrip("/").lower()
        if u:
            want[u] = row

    open_sites, drift, unconfirmed = [], [], []
    for s in (snap.get("sites") or []):
        cap = (s.get("sharingCapability") or "").strip()
        if cap.lower() == "disabled" or not cap:
            continue
        u = (s.get("url") or "").rstrip("/").lower()
        row = {"url": s.get("url"), "capability": cap, "anonymous": cap.lower() == _ANON}
        open_sites.append(row)
        rec = want.get(u)
        if rec is None:
            drift.append({**row, "why": "기록에 없는 사이트가 열려 있습니다"})
        elif (rec.get("capability") or "").lower() != cap.lower():
            drift.append({**row, "why": f"기록은 {rec.get('capability')} 인데 실제는 {cap}"})
        elif not rec.get("confirmed", False):
            unconfirmed.append({**row, "reason": rec.get("reason")})

    live = {(s.get("url") or "").rstrip("/").lower() for s in (snap.get("sites") or [])
            if (s.get("sharingCapability") or "").lower() not in ("disabled", "")}
    stale = [want[u] for u in want if u not in live]

    return {
        "collectedAt": snap.get("collectedAt"),
        "siteCount": snap.get("siteCount"),
        "byCapability": snap.get("byCapability") or {},
        "openSites": open_sites,
        "openCount": len(open_sites),
        "anonymousSiteCount": sum(1 for r in open_sites if r["anonymous"]),
        "drift": drift,
        "driftCount": len(drift),
        "unconfirmed": unconfirmed,
        "unconfirmedCount": len(unconfirmed),
        "staleRecords": stale,
        "recordedCount": len(want),
    }, None

_CAPABILITY = {
    "disabled": ("External sharing disabled", "ok"),
    "existingExternalUserSharingOnly": ("Existing guests only", "ok"),
    "externalUserSharingOnly": ("New and existing guests (authenticated)", "ok"),
    "externalUserAndGuestSharing": ("Anyone with the link (ANONYMOUS)", "bad"),
}


def _is_stale(per_site, days=30):
    if not per_site or not per_site.get("collectedAt"):
        return None
    try:
        d = datetime.strptime(per_site["collectedAt"][:10], "%Y-%m-%d").date()
    except Exception:
        return None
    return (date.today() - d).days > days


async def fetch() -> dict:
    s = await graph_get("/admin/sharepoint/settings")

    cap = s.get("sharingCapability")
    cap_label, cap_sev = _CAPABILITY.get(cap, (cap or "unknown", "info"))
    anonymous = cap == "externalUserAndGuestSharing"

    idle = s.get("idleSessionSignOut") or {}
    findings = []

    per_site, per_site_err = _per_site()

    if per_site_err:
        findings.append(finding(
            "med",
            en=f"The per-site measurement or the intent record could not be read ({per_site_err}). "
               "Drift cannot be judged, so the tenant-ceiling warning below stands as it is.",
            ko=f"사이트별 실측/의도 기록을 읽지 못했습니다 ({per_site_err}). "
               "드리프트를 판정할 수 없으므로 아래 천장 경고가 그대로 유효합니다."))

    if anonymous and per_site is None:
        findings.append(finding(
            "high",
            en="Anonymous 'Anyone with the link' sharing is enabled - that access carries no "
               "identity, so it produces no sign-in log and no Conditional Access evaluation. "
               "MFA and device policies do not apply to it. This is the tenant ceiling, and "
               "no per-site snapshot exists to say which sites actually use it. "
               "Run scripts/spo_sharing_collector.ps1.",
            ko="익명 '링크가 있는 모든 사용자' 공유가 켜져 있습니다. 그 접근에는 신원이 없어서 "
               "사인인 로그도 Conditional Access 평가도 생기지 않고, MFA·기기 정책이 적용되지 "
               "않습니다. 이건 테넌트 **천장**이고, 실제로 어느 사이트가 쓰는지 말해 줄 사이트별 "
               "스냅샷이 없습니다. scripts/spo_sharing_collector.ps1 를 돌리십시오."))
    elif anonymous and per_site is not None:
        if per_site["driftCount"]:
            findings.append(finding(
                "high",
                en=f"{per_site['driftCount']} site(s) are sharing externally without a record. "
                   "Deliberate exceptions are written in data/sharing-intent.json; a site that is "
                   "open without being listed there is drift.",
                ko=f"기록에 없는 외부 공유 사이트가 {per_site['driftCount']}곳 있습니다. "
                   "의도된 예외는 data/sharing-intent.json 에 적혀 있고, 여기 없는데 열려 "
                   "있으면 그것이 드리프트입니다."))
        if per_site["unconfirmedCount"]:
            findings.append(finding(
                "med",
                en=f"{per_site['unconfirmedCount']} site(s) are in the intent record but not yet "
                   "confirmed (confirmed=false). Check whether they are still in use and settle "
                   "the record.",
                ko=f"의도 기록에 있으나 아직 확인되지 않은 사이트가 "
                   f"{per_site['unconfirmedCount']}곳 있습니다 (confirmed=false). "
                   "쓰는 사이트인지 확인하고 기록을 확정하십시오."))
        if not per_site["driftCount"] and not per_site["unconfirmedCount"]:
            findings.append(finding(
                "info",
                en=f"Anonymous sharing is open at the tenant ceiling, but only "
                   f"{per_site['anonymousSiteCount']} site(s) actually use it and every one is a "
                   f"recorded exception (measured {per_site['collectedAt']}). No drift.",
                ko=f"익명 공유는 천장으로 열려 있으나 실제로 쓰는 사이트는 "
                   f"{per_site['anonymousSiteCount']}곳이고 전부 기록된 예외입니다 "
                   f"({per_site['collectedAt']} 실측). 드리프트 없음."))
    if s.get("isResharingByExternalUsersEnabled"):
        findings.append(finding(
            "med",
            en="External users can re-share content, so access can spread beyond the people "
               "you invited without any further approval.",
            ko="외부 사용자가 콘텐츠를 재공유할 수 있습니다. 추가 승인 없이 초대한 사람 너머로 "
               "접근권이 퍼질 수 있다는 뜻입니다."))
    if s.get("isLegacyAuthProtocolsEnabled"):
        findings.append(finding(
            "med",
            en="Legacy authentication protocols are enabled for SharePoint - legacy clients "
               "cannot perform interactive MFA, so this is an MFA bypass path.",
            ko="SharePoint 에 레거시 인증 프로토콜이 켜져 있습니다. 레거시 클라이언트는 대화형 "
               "MFA 를 할 수 없으므로 이건 MFA 우회 경로입니다."))
    if s.get("isUnmanagedSyncAppForTenantRestricted") is False:
        findings.append(finding(
            "med",
            en="The OneDrive sync client is allowed on unmanaged devices, so company files can "
               "sync to personal machines. Restricting this breaks existing sync on unmanaged "
               "devices, so schedule it - do not flip it casually.",
            ko="관리되지 않는 기기에서도 OneDrive 동기화 클라이언트가 허용돼 있어, 회사 파일이 "
               "개인 PC 로 동기화될 수 있습니다. 이걸 막으면 그런 기기의 기존 동기화가 끊기므로 "
               "일정을 잡아서 하십시오 - 가볍게 뒤집을 설정이 아닙니다."))
    if not idle.get("isEnabled"):
        findings.append(finding(
            "low",
            en="No idle session sign-out - browser sessions on shared or unattended machines "
               "stay signed in indefinitely.",
            ko="유휴 세션 사인아웃이 없습니다. 공용이거나 자리를 비운 PC 의 브라우저 세션이 "
               "무기한 로그인 상태로 남습니다."))
    if s.get("isSiteCreationEnabled"):
        findings.append(finding(
            "low",
            en="Users can create their own sites, so the sharing surface grows without review.",
            ko="사용자가 사이트를 직접 만들 수 있어서, 검토 없이 공유 표면이 늘어납니다."))

    return {
        "available": True,
        "sharingCapability": cap,
        "sharingCapabilityLabel": cap_label,
        "sharingCapabilitySeverity": cap_sev,
        "anonymousLinksEnabled": anonymous,
        "domainRestrictionMode": s.get("sharingDomainRestrictionMode"),
        "allowedDomains": s.get("sharingAllowedDomainList") or [],
        "blockedDomains": s.get("sharingBlockedDomainList") or [],
        "externalResharingEnabled": bool(s.get("isResharingByExternalUsersEnabled")),
        "legacyAuthEnabled": bool(s.get("isLegacyAuthProtocolsEnabled")),
        "unmanagedSyncRestricted": bool(s.get("isUnmanagedSyncAppForTenantRestricted")),
        "siteCreationEnabled": bool(s.get("isSiteCreationEnabled")),
        "fileActivityNotification": bool(s.get("isFileActivityNotificationEnabled")),
        "idleSessionSignOut": {
            "enabled": bool(idle.get("isEnabled")),
            "warnAfterMinutes": round((idle.get("warnAfterInSeconds") or 0) / 60) or None,
            "signOutAfterMinutes": round((idle.get("signOutAfterInSeconds") or 0) / 60) or None,
        },
        "perSite": per_site,
        "perSiteError": per_site_err,
        "perSiteStale": _is_stale(per_site),
        "findings": findings,
        "findingCount": len(findings),
        "highFindingCount": sum(1 for f in findings if f["severity"] == "high"),
    }
