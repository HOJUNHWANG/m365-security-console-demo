"""Intune device inventory and compliance (Microsoft Intune Plan 1).

Intune is included with Business Premium. Requires DeviceManagementManagedDevices.Read.All and
DeviceManagementConfiguration.Read.All (application permissions, already consented).

$select fetches only the fields actually used, minimising both payload size and the identifying
data collected (serial numbers, IMEI and phone numbers are never requested). Device names and
user UPNs are for display on the access-gated admin dashboard only and are never sent to the AI
summary (ai_overview egresses aggregate counts only).
"""
from collections import Counter

from ..graph_client import graph_get

_BETA = "https://graph.microsoft.com/beta"

MAX_DEVICES = 500
PAGE = 100
DEVICE_ROWS = 200   # maximum rows rendered in the table

# $select - only the fields actually used for display and aggregation
_SELECT = ("id,deviceName,operatingSystem,osVersion,complianceState,isEncrypted,"
           "managedDeviceOwnerType,lastSyncDateTime,userPrincipalName,model")

_OWNER = {"company": "Company", "personal": "Personal", "unknown": "Unknown"}
# Sort order: non-compliant first
_ORDER = {"noncompliant": 0, "error": 1, "inGracePeriod": 2, "conflict": 3,
          "unknown": 4, "configManager": 5, "compliant": 6, "notApplicable": 7}


async def _safe_get(path: str) -> dict:
    """Auxiliary compliance/configuration/overview calls - the device inventory survives if these fail."""
    try:
        return await graph_get(path)
    except Exception:  # noqa: BLE001
        return {}


async def _all_devices() -> tuple[list, bool]:
    url = f"/deviceManagement/managedDevices?$top={PAGE}&$select={_SELECT}"
    out, truncated = [], False
    data = await graph_get(url)   # the core call - 403 and friends propagate up to _safe
    while True:
        out.extend(data.get("value", []))
        if len(out) >= MAX_DEVICES:
            truncated = True
            break
        nxt = data.get("@odata.nextLink")
        if not nxt:
            break
        data = await graph_get(nxt)
    return out, truncated


def _compliance_reqs(p: dict) -> list:
    """Every requirement the policy actually enforces - see the beta note in fetch().

    This listed four settings and silently dropped the rest, so PILOT-Basic rendered as
    "Secure Boot · OS >= 10.0.26100" while it also required firewall, antivirus, antispyware and
    code integrity. A policy that looks weaker than it is invites someone to "strengthen" it by
    adding a control that is already there - which, with a block action, is a live-access change
    made on a false premise. Understating a control is not the safe direction to be wrong in.
    """
    reqs = []
    if p.get("storageRequireEncryption") or p.get("bitLockerEnabled"):
        reqs.append("Encryption")
    if p.get("passwordRequired"):
        reqs.append("Password")
    elif p.get("passwordRequiredType") not in (None, "", "notConfigured"):
        reqs.append("Password")
    if p.get("secureBootEnabled"):
        reqs.append("Secure Boot")
    if p.get("codeIntegrityEnabled"):
        reqs.append("Code Integrity")
    # beta-only fields: absent from a v1.0 response, which is why they were invisible here
    if p.get("activeFirewallRequired"):
        reqs.append("Firewall")
    if p.get("antivirusRequired"):
        reqs.append("Antivirus")
    if p.get("antiSpywareRequired"):
        reqs.append("Antispyware")
    if p.get("defenderEnabled"):
        reqs.append("Defender")
    if p.get("rtpEnabled"):
        reqs.append("Real-time protection")
    if p.get("tpmRequired"):
        reqs.append("TPM")
    if (p.get("deviceThreatProtectionRequiredSecurityLevel") or "unavailable") not in (
            "unavailable", "notSet", "notConfigured"):
        reqs.append("Threat protection")
    if p.get("osMinimumVersion"):
        reqs.append(f"OS >= {p['osMinimumVersion']}")
    return reqs


async def _editions() -> dict:
    """Windows edition (Home / Pro / Enterprise) per device id.

    `skuFamily` exists ONLY on the beta endpoint - asking for it on v1.0 returns 400 and takes the
    whole inventory with it, hence the separate, failure-tolerant call. It matters operationally:
    Intune ADMX ingestion is rejected on Home (0x86000013), so any policy delivered as an ingested
    ADMX template - the Chrome SSO extension among them - can only be deployed by hand there.
    """
    out = {}
    url = f"{_BETA}/deviceManagement/managedDevices?$top={PAGE}&$select=id,skuFamily,joinType"
    for _ in range(MAX_DEVICES // PAGE + 2):
        data = await _safe_get(url)
        for d in data.get("value", []):
            out[d.get("id")] = {"edition": d.get("skuFamily"), "joinType": d.get("joinType")}
        url = data.get("@odata.nextLink")
        if not url:
            break
    return out


async def fetch() -> dict:
    devices, truncated = await _all_devices()
    editions = await _editions()
    ov = await _safe_get("/deviceManagement/managedDeviceOverview")
    # BETA, deliberately. The v1.0 representation of windows10CompliancePolicy OMITS
    # activeFirewallRequired / antivirusRequired / antiSpywareRequired / defenderEnabled /
    # rtpEnabled entirely - it does not return them as false, it does not return them at all.
    # Measured 2026-08-12 on PILOT-Basic: v1.0 showed 4 settings, beta showed 7, and the three
    # missing ones were all enforced. Reading v1.0 here made the policy look thinner than it was.
    # Falls back to v1.0 so a beta outage degrades the detail rather than losing the panel.
    comp = await _safe_get(f"{_BETA}/deviceManagement/deviceCompliancePolicies") \
        or await _safe_get("/deviceManagement/deviceCompliancePolicies")
    cfg = await _safe_get("/deviceManagement/deviceConfigurations")

    comp_counts = Counter((d.get("complianceState") or "unknown") for d in devices)
    os_counts = Counter((d.get("operatingSystem") or "Unknown") for d in devices)
    owners = Counter((d.get("managedDeviceOwnerType") or "unknown") for d in devices)
    encrypted = sum(1 for d in devices if d.get("isEncrypted"))

    rows = [{
        "id": d.get("id"),   # used to deep-link to the device in the Intune portal
        "name": d.get("deviceName"),
        "os": d.get("operatingSystem"),
        "osVersion": d.get("osVersion"),
        "owner": _OWNER.get(d.get("managedDeviceOwnerType"), d.get("managedDeviceOwnerType")),
        "compliance": d.get("complianceState") or "unknown",
        "encrypted": bool(d.get("isEncrypted")),
        "lastSync": d.get("lastSyncDateTime"),
        "user": d.get("userPrincipalName"),
        "model": d.get("model"),
        "edition": (editions.get(d.get("id")) or {}).get("edition"),
        "joinType": (editions.get(d.get("id")) or {}).get("joinType"),
    } for d in devices]
    rows.sort(key=lambda r: (_ORDER.get(r["compliance"], 9), (r["lastSync"] or "")))

    comp_policies = [{
        "name": p.get("displayName"),
        "os": (p.get("@odata.type") or "").split(".")[-1].replace("CompliancePolicy", "") or "—",
        "reqs": _compliance_reqs(p),
    } for p in comp.get("value", [])]

    # `managedDeviceOverview` is a CACHED aggregate Intune recomputes on its own schedule, and it
    # lags a deletion. 2026-08-07: it still returned enrolledDeviceCount=12 hours after
    # DEVICE-A's record was removed, while the inventory returned 11 - so the card read
    # "12 enrolled / 11 compliant / 0 non-compliant", three numbers that cannot all be true, and it
    # reads as one device silently failing compliance. Every other figure here (compliance,
    # encryption, ownership, OS) is counted from the inventory, so the headline must be too.
    # The aggregate is still worth carrying: a gap that does not close is the fingerprint of a
    # ghost record, which is exactly what a stub deletion leaves behind.
    total = len(devices)
    overview_count = ov.get("enrolledDeviceCount")
    return {
        "available": True,
        "total": total,
        # Only meaningful when the inventory is complete - a truncated page would explain the gap.
        "overviewCount": overview_count,
        "overviewLag": (overview_count - total
                        if overview_count is not None and not truncated and overview_count > total
                        else 0),
        "mdmEnrolled": ov.get("mdmEnrolledCount"),
        "byOs": dict(os_counts),
        # Empty when the beta lookup failed - the UI must fall back rather than show "0 Home".
        "byEdition": dict(Counter(
            (editions.get(d.get("id")) or {}).get("edition") or "Unknown" for d in devices)),
        "byJoinType": dict(Counter(
            (editions.get(d.get("id")) or {}).get("joinType") or "Unknown" for d in devices)),
        "editionKnown": sum(1 for d in devices if (editions.get(d.get("id")) or {}).get("edition")),
        "compliant": comp_counts.get("compliant", 0),
        "noncompliant": comp_counts.get("noncompliant", 0) + comp_counts.get("error", 0),
        "gracePeriod": comp_counts.get("inGracePeriod", 0),
        "unknownCompliance": comp_counts.get("unknown", 0),
        "encrypted": encrypted,
        "ownership": {"company": owners.get("company", 0), "personal": owners.get("personal", 0)},
        "compliancePolicyCount": len(comp.get("value", [])),
        "configProfileCount": len(cfg.get("value", [])),
        "compliancePolicies": comp_policies,
        "devices": rows[:DEVICE_ROWS],
        "truncated": truncated,
    }
