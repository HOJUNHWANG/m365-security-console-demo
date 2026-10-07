import json
from collections import Counter
from datetime import datetime, timezone

import httpx

from .config import settings

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"

LANG_SPLIT = "=== KOREAN ==="

SYSTEM_PROMPT = (
    "You are a Microsoft 365 security operations (SOC) analyst. Using ONLY the provided "
    "aggregate security metrics (JSON), write a concise security summary for a "
    "non-expert reader.\n"
    "Output PLAIN TEXT only — no markdown, no asterisks, no '#'. Use EXACTLY these three "
    "section labels, each on its own line, with bullets starting with '- ':\n"
    "Assessment:\n"
    "<one short sentence on overall posture>\n"
    "Priorities:\n"
    "- <item, most important first, include the key number> (3-5 bullets)\n"
    "Recommended actions:\n"
    "- <action> (1-2 bullets)\n"
    "Keep every bullet to one short line. Be factual; never invent anything not in the data.\n"
    "\n"
    "Write the summary TWICE. First in English exactly as specified above. Then a line "
    f"containing only {LANG_SPLIT} and then the SAME summary in Korean, using the Korean "
    "section labels 평가: / 우선순위: / 권장 조치: and the same bullet structure. The two "
    "versions must state the same facts and the same numbers.\n"
    "⚠ The Korean half must be written in KOREAN prose - every sentence and every bullet. "
    "Korean section labels with English sentences underneath is a failure.\n"
    "⛔ Keep product names, policy names and technical identifiers in English inside the Korean "
    "text (Conditional Access, Intune, Entra ID, MFA, Secure Score, SharePoint, Defender)."
)


def _sanitize(s: dict) -> dict:
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
        "caReportOnlyPilotPolicies": rs.get("caReportOnlyPolicyCount"),
        "caReportOnlyWouldBlock": rs.get("caReportOnlyBlockCount"),
        "caReportOnlyWouldInterrupt": rs.get("caReportOnlyInterruptCount"),
        "caReportOnlyUsersAffected": rs.get("caReportOnlyUsers"),
        "caReportOnlyByClaim": rs.get("caReportOnlyByClaim"),
        "devicesWithIncoherentIdentity": di.get("problem") if di else None,
        "devicesChecked": di.get("enrolled") if di else None,
        "devicesWithDuplicateEntraObjects": di.get("duplicateObjectCount") if di else None,
        "caBlockedNoSuccessAccounts": (rs.get("nonInteractive") or {}).get("stuckCount"),
        "caStillBlockingAccounts": (rs.get("nonInteractive") or {}).get("flappingCount"),
        "caNonInteractiveBlocks": (rs.get("nonInteractive") or {}).get("blockCount"),
        "guestsDormant": acc.get("guestsDormant") if acc else None,
        "guestsNeverAccepted": acc.get("guestsPending") if acc else None,
        "guestsNeverSignedIn": acc.get("guestsNeverSignedIn") if acc else None,
        "unattendedAccountsLockedOutByPolicy": un.get("exposedCount") if un else None,
        "unattendedAccountsAtRiskIfEnforced": un.get("reportOnlyExposedCount") if un else None,
        "unattendedAccountsTotal": un.get("licenceProvenCount") if un else None,
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
        "sharepointAnonymousLinksEnabled": sp.get("anonymousLinksEnabled") if sp else None,
        "sharepointSharingLevel": sp.get("sharingCapability") if sp else None,
        "sharepointExternalResharing": sp.get("externalResharingEnabled") if sp else None,
        "sharepointLegacyAuthEnabled": sp.get("legacyAuthEnabled") if sp else None,
        "sharepointSyncBlockedOnUnmanaged": sp.get("unmanagedSyncRestricted") if sp else None,
        "sharepointSharingFindings": sp.get("findingCount") if sp else None,
    }


async def generate(snapshot: dict) -> dict | None:
    if not settings.groq_api_key:
        return None

    metrics = _sanitize(snapshot)
    payload = {
        "model": settings.groq_model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": "Security metrics:\n" + json.dumps(metrics, ensure_ascii=False)},
        ],
        "temperature": 0.3,
        "max_tokens": 2200,
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
        text_ko = ""
        if LANG_SPLIT in text:
            head, _, tail = text.partition(LANG_SPLIT)
            if head.strip() and tail.strip():
                text, text_ko = head.strip(), tail.strip()
        return {
            "available": True,
            "text": text,
            "textEn": text,
            "textKo": text_ko,
            "model": settings.groq_model,
            "generatedAt": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as e:
        return {"available": False, "reason": f"Error: {e}"}
