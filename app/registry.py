import asyncio

from . import signin_cache

from .sources import (
    account_summary,
    admin_accounts,
    app_credentials,
    attack_simulation,
    browser_claims,
    ca_exceptions,
    defender_posture,
    device_identity,
    dlp_simulation,
    enterprise_apps,
    entra_access,
    exchange_eop,
    intune_devices,
    mam_registrations,
    licenses,
    mfa_status,
    recent_audits,
    risky_signins,
    secure_score,
    secure_score_actions,
    security_alerts,
    security_incidents,
    sharepoint_sharing,
    sharing_links,
    threat_hunting,
    unattended_accounts,
)

SOURCES = {
    "secureScore": secure_score.fetch,
    "secureScoreActions": secure_score_actions.fetch,
    "securityAlerts": security_alerts.fetch,
    "securityIncidents": security_incidents.fetch,
    "threatHunting": threat_hunting.fetch,
    "attackSimulation": attack_simulation.fetch,
    "mfaStatus": mfa_status.fetch,
    "riskySignins": risky_signins.fetch,
    "entraAccess": entra_access.fetch,
    "caExceptions": ca_exceptions.fetch,
    "unattendedAccounts": unattended_accounts.fetch,
    "intuneDevices": intune_devices.fetch,
    "mamRegistrations": mam_registrations.fetch,
    "deviceIdentity": device_identity.fetch,
    "defenderPosture": defender_posture.fetch,
    "browserClaims": browser_claims.fetch,
    "exchangeEop": exchange_eop.fetch,
    "sharepointSharing": sharepoint_sharing.fetch,
    "dlpSimulation": dlp_simulation.fetch,
    "sharingLinks": sharing_links.fetch,
    "adminAccounts": admin_accounts.fetch,
    "accountSummary": account_summary.fetch,
    "appCredentials": app_credentials.fetch,
    "enterpriseApps": enterprise_apps.fetch,
    "recentAudits": recent_audits.fetch,
    "licenses": licenses.fetch,
}


async def _safe(name, fn):
    try:
        return name, await fn()
    except PermissionError:
        return name, {
            "available": False,
            "reason": "Permission not consented, or insufficient licensing (403). Check admin consent and licences.",
        }
    except Exception as e:
        detail = str(e).strip()
        return name, {
            "available": False,
            "reason": f"{type(e).__name__}: {detail}" if detail else f"{type(e).__name__} (no message)",
        }


async def collect_all() -> dict:
    signin_cache.invalidate()
    signin_cache.prewarm()
    results = await asyncio.gather(*[_safe(n, fn) for n, fn in SOURCES.items()])
    return dict(results)
