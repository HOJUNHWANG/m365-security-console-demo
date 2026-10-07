from collections import Counter

from ..graph_client import graph_get

_BETA = "https://graph.microsoft.com/beta"

MAX_DEVICES = 500
PAGE = 100
DEVICE_ROWS = 200

_SELECT = ("id,deviceName,operatingSystem,osVersion,complianceState,isEncrypted,"
           "managedDeviceOwnerType,lastSyncDateTime,userPrincipalName,model")

_OWNER = {"company": "Company", "personal": "Personal", "unknown": "Unknown"}
_ORDER = {"noncompliant": 0, "error": 1, "inGracePeriod": 2, "conflict": 3,
          "unknown": 4, "configManager": 5, "compliant": 6, "notApplicable": 7}

_NO_USER = "￿"


def _order_rows(rows: list) -> list:
    rows = sorted(rows, key=lambda r: (_ORDER.get(r.get("compliance"), 9), r.get("lastSync") or ""))
    rows = rows[:DEVICE_ROWS]
    return sorted(rows, key=lambda r: ((r.get("user") or "").lower() or _NO_USER,
                                       (r.get("name") or "").lower()))


async def _safe_get(path: str) -> dict:
    try:
        return await graph_get(path)
    except Exception:
        return {}


async def _all_devices() -> tuple[list, bool]:
    url = f"/deviceManagement/managedDevices?$top={PAGE}&$select={_SELECT}"
    out, truncated = [], False
    data = await graph_get(url)
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
    reqs = []
    if p.get("storageRequireEncryption") or p.get("bitLockerEnabled"):
        reqs.append("Encryption")
    if p.get("passwordRequired"):
        reqs.append("Password")
    if p.get("secureBootEnabled"):
        reqs.append("Secure Boot")
    if p.get("codeIntegrityEnabled"):
        reqs.append("Code Integrity")
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


def _inert_settings(p: dict) -> list:
    inert = []
    if not p.get("passwordRequired"):
        pw = [k for k in ("passwordRequiredType", "passwordMinimumLength", "passwordBlockSimple",
                          "passwordExpirationDays", "passwordMinimumCharacterSetCount",
                          "passwordPreviousPasswordBlockCount",
                          "passwordMinutesOfInactivityBeforeLock",
                          "passwordRequiredToUnlockFromIdle")
              if p.get(k) not in (None, "", False, 0, "notConfigured", "deviceDefault")
              or (k == "passwordRequiredType"
                  and p.get(k) not in (None, "", "notConfigured"))]
        if pw:
            inert.append("Password")
    return inert


async def _editions() -> dict:
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
    comp = await _safe_get(f"{_BETA}/deviceManagement/deviceCompliancePolicies") \
        or await _safe_get("/deviceManagement/deviceCompliancePolicies")
    cfg = await _safe_get("/deviceManagement/deviceConfigurations")

    comp_counts = Counter((d.get("complianceState") or "unknown") for d in devices)
    os_counts = Counter((d.get("operatingSystem") or "Unknown") for d in devices)
    owners = Counter((d.get("managedDeviceOwnerType") or "unknown") for d in devices)
    encrypted = sum(1 for d in devices if d.get("isEncrypted"))

    rows = [{
        "id": d.get("id"),
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
    rows = _order_rows(rows)

    comp_policies = [{
        "name": p.get("displayName"),
        "os": (p.get("@odata.type") or "").split(".")[-1].replace("CompliancePolicy", "") or "—",
        "reqs": _compliance_reqs(p),
        "inert": _inert_settings(p),
    } for p in comp.get("value", [])]

    total = len(devices)
    overview_count = ov.get("enrolledDeviceCount")
    return {
        "available": True,
        "total": total,
        "overviewCount": overview_count,
        "overviewLag": (overview_count - total
                        if overview_count is not None and not truncated and overview_count > total
                        else 0),
        "mdmEnrolled": ov.get("mdmEnrolledCount"),
        "byOs": dict(os_counts),
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
        "devices": rows,
        "truncated": truncated,
    }
