"""AI security summary - sends ONLY aggregate metrics (non-PII) from the snapshot to Groq (gpt-oss).

Sent: aggregate numbers only - scores, counts, severities, categories.
Never sent: identifying data such as names, e-mail addresses, mailbox addresses,
incident titles or mail-flow rule targets.
Without GROQ_API_KEY this module is inert (returns None) - nothing leaves the network.
"""
import json
from collections import Counter
from datetime import datetime, timezone

import httpx

from .config import settings

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

SYSTEM_PROMPT = (
    "You are a Microsoft 365 security operations (SOC) analyst. Using ONLY the provided "
    "aggregate security metrics (JSON), write a concise security summary in English for a "
    "non-expert reader.\n"
    "Output PLAIN TEXT only — no markdown, no asterisks, no '#'. Use EXACTLY these three "
    "section labels, each on its own line, with bullets starting with '- ':\n"
    "Assessment:\n"
    "<one short sentence on overall posture>\n"
    "Priorities:\n"
    "- <item, most important first, include the key number> (3-5 bullets)\n"
    "Recommended actions:\n"
    "- <action> (1-2 bullets)\n"
    "Keep every bullet to one short line. Be factual; never invent anything not in the data."
)


def _sanitize(s: dict) -> dict:
    """Extract only the non-PII aggregate metrics from a snapshot."""
    def av(k):
        v = s.get(k, {}) or {}
        return v if v.get("available") else {}

    ss, mfa, acc = av("secureScore"), av("mfaStatus"), av("accountSummary")
    al, inc, th = av("securityAlerts"), av("securityIncidents"), av("threatHunting")
    rs, ac = av("riskySignins"), av("appCredentials")
    adm = av("adminAccounts")
    ea, dev = av("entraAccess"), av("intuneDevices")
    di = av("deviceIdentity")
    sp = av("sharepointSharing")
    un = av("unattendedAccounts")
    ex = s.get("exchangeEop", {}) or {}
    ex_ok = ex.get("available")

    inc_sev = dict(Counter((i.get("severity") or "unknown") for i in inc.get("incidents", []))) if inc else {}
    al_sev = dict(Counter((a.get("severity") or "unknown") for a in al.get("alerts", []))) if al else {}

    return {
        "secureScore": (f"{ss.get('current')}/{ss.get('max')}" if ss else None),
        "secureScorePct": round(ss["current"] / ss["max"] * 100, 1) if ss.get("max") else None,
        "mfaPercent": mfa.get("percent"),
        "mfaRegistered": mfa.get("mfaRegistered"),
        "mfaTotal": mfa.get("total"),
        "globalAdmins": adm.get("globalAdminCount"),
        "accounts": {
            "total": acc.get("total"), "enabled": acc.get("enabled"),
            "disabled": acc.get("disabled"), "guests": acc.get("guests"),
        } if acc else {},
        "guestsPending": acc.get("guestsPending"),
        "failedSignins": rs.get("failed"),
        "recentSignins": rs.get("recent"),
        "signinFailRate": rs.get("failRate"),
        "passwordSprayIps": len(rs.get("sprayIps", [])) if rs else None,
        "multiIpSigninUsers": len(rs.get("multiIpUsers", [])) if rs else None,
        "activeAlerts": al.get("count"),
        "alertSeverity": al_sev,
        "activeIncidents": inc.get("activeCount"),
        "incidentSeverity": inc_sev,
        "emailThreats": th.get("byType"),
        "spoofDelivered": th.get("spoofDelivered"),
        "externalDelivered": th.get("externalDelivered"),
        "zapRemoved": th.get("zapTotal"),
        "urlClicks": th.get("urlClicks"),
        "securityDefaults": ea.get("securityDefaults") if ea else None,
        "conditionalAccessPolicies": ea.get("caPolicyCount") if ea else None,
        "caPoliciesEnabled": ea.get("caEnabledCount") if ea else None,
        "caPoliciesReportOnly": ea.get("caReportOnlyCount") if ea else None,
        "caEnforcedFailures": rs.get("caFailedCount"),
        # Report-only pilot: counts only - the per-sign-in impact rows (UPN, IP, device) stay local
        "caReportOnlyPilotPolicies": rs.get("caReportOnlyPolicyCount"),
        "caReportOnlyWouldBlock": rs.get("caReportOnlyBlockCount"),
        "caReportOnlyWouldInterrupt": rs.get("caReportOnlyInterruptCount"),
        "caReportOnlyUsersAffected": rs.get("caReportOnlyUsers"),
        # Why the report-only hits happened - counts only, no device names or UPNs
        "caReportOnlyByClaim": rs.get("caReportOnlyByClaim"),
        # Device identity coherence - aggregate counts only; the per-device rows stay local
        "devicesWithIncoherentIdentity": di.get("problem") if di else None,
        "devicesChecked": di.get("enrolled") if di else None,
        "devicesWithDuplicateEntraObjects": di.get("duplicateObjectCount") if di else None,
        # Non-interactive CA blocks - counts only. This is the metric whose absence hid a two-hour
        # Teams Rooms outage on 2026-07-30.
        "caBlockedNoSuccessAccounts": (rs.get("nonInteractive") or {}).get("stuckCount"),
        "caStillBlockingAccounts": (rs.get("nonInteractive") or {}).get("flappingCount"),
        "caNonInteractiveBlocks": (rs.get("nonInteractive") or {}).get("blockCount"),
        # Guest hygiene
        "guestsDormant": acc.get("guestsDormant") if acc else None,
        "guestsNeverAccepted": acc.get("guestsPending") if acc else None,
        "guestsNeverSignedIn": acc.get("guestsNeverSignedIn") if acc else None,
        # Unattended identities (Teams Rooms / shared device) caught by a policy they cannot
        # satisfy - counts only; the account names stay local.
        "unattendedAccountsLockedOutByPolicy": un.get("exposedCount") if un else None,
        "unattendedAccountsAtRiskIfEnforced": un.get("reportOnlyExposedCount") if un else None,
        "unattendedAccountsTotal": un.get("licenceProvenCount") if un else None,
        # Role exposure that user-scoped MFA/CA cannot cover
        "servicePrincipalsWithDirectoryRoles": len(adm.get("servicePrincipalRoles", [])) if adm else None,
        "servicePrincipalsWithGlobalAdmin": (
            sum(1 for s in adm.get("servicePrincipalRoles", []) if s.get("role") == "Global Administrator")
            if adm else None),
        "readAllRoleHolders": (
            sum(len(r.get("members", [])) for r in adm.get("readPrivileged", [])) if adm else None),
        "disabledAccountsWithRoles": len(adm.get("disabledWithRoles", [])) if adm else None,
        "managedDevices": dev.get("total") if dev else None,
        "noncompliantDevices": dev.get("noncompliant") if dev else None,
        "devicesEncrypted": dev.get("encrypted") if dev else None,
        "appCredsExpiring": len(ac.get("expiring", [])) if ac else None,
        "mailForwarding": len(ex.get("forwarding", [])) if ex_ok else None,
        "riskyInboxRules": len(ex.get("riskyRules", [])) if ex_ok else None,
        "mailboxDelegations": len(ex.get("delegations", [])) if ex_ok else None,
        "quarantine": (ex.get("quarantine") or {}).get("total") if ex_ok else None,
        # External sharing posture - tenant config flags, no PII. Anonymous sharing matters most:
        # that access carries no identity, so no Conditional Access policy can apply to it.
        "sharepointAnonymousLinksEnabled": sp.get("anonymousLinksEnabled") if sp else None,
        "sharepointSharingLevel": sp.get("sharingCapability") if sp else None,
        "sharepointExternalResharing": sp.get("externalResharingEnabled") if sp else None,
        "sharepointLegacyAuthEnabled": sp.get("legacyAuthEnabled") if sp else None,
        "sharepointSyncBlockedOnUnmanaged": sp.get("unmanagedSyncRestricted") if sp else None,
        "sharepointSharingFindings": sp.get("findingCount") if sp else None,
    }


async def generate(snapshot: dict) -> dict | None:
    if not settings.groq_api_key:
        return None  # inert - nothing is sent

    metrics = _sanitize(snapshot)
    payload = {
        "model": settings.groq_model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "Security metrics:\n" + json.dumps(metrics, ensure_ascii=False)},
        ],
        "temperature": 0.3,
        "max_tokens": 1100,
    }
    headers = {
        "Authorization": f"Bearer {settings.groq_api_key}",
        "Content-Type": "application/json",
    }
    try:
        async with httpx.AsyncClient(timeout=40) as c:
            r = await c.post(GROQ_URL, headers=headers, json=payload)
        if r.status_code != 200:
            return {"available": False, "reason": f"Groq error {r.status_code}: {r.text[:200]}"}
        text = r.json()["choices"][0]["message"]["content"].strip()
        return {
            "available": True,
            "text": text,
            "model": settings.groq_model,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:  # noqa: BLE001
        return {"available": False, "reason": f"Error: {e}"}
