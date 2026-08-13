"""Source registry and the collect-everything logic - shared by the API endpoint and the collector."""
import asyncio

from . import signin_cache

from .sources import (
    account_summary,
    admin_accounts,
    app_credentials,
    attack_simulation,
    browser_claims,
    device_identity,
    entra_access,
    exchange_eop,
    intune_devices,
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

# A data source is a module. To add a card, add one line here.
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
    "unattendedAccounts": unattended_accounts.fetch,
    "intuneDevices": intune_devices.fetch,
    "deviceIdentity": device_identity.fetch,
    "browserClaims": browser_claims.fetch,
    "exchangeEop": exchange_eop.fetch,
    "sharepointSharing": sharepoint_sharing.fetch,
    "sharingLinks": sharing_links.fetch,
    "adminAccounts": admin_accounts.fetch,
    "accountSummary": account_summary.fetch,
    "appCredentials": app_credentials.fetch,
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
    except Exception as e:  # noqa: BLE001 - one dead source must not hide the rest
        # ALWAYS include the exception type. httpx timeout exceptions (ReadTimeout, ConnectTimeout,
        # PoolTimeout) and bare TimeoutError all stringify to "", so f"Error: {e}" produced the
        # useless "Error: " that made a 2026-08-04 partial collect undiagnosable.
        detail = str(e).strip()
        return name, {
            "available": False,
            "reason": f"{type(e).__name__}: {detail}" if detail else f"{type(e).__name__} (no message)",
        }


async def collect_all() -> dict:
    """Collect every source in parallel and return {key: result}."""
    # The 7-day sign-in pull is shared by three sources (signin_cache). Drop it first so this cycle
    # fetches fresh data - without this the second cycle would render the first cycle's sign-ins.
    signin_cache.invalidate()
    signin_cache.prewarm()      # start the heavy pull now so it overlaps the rest of the cycle
    results = await asyncio.gather(*[_safe(n, fn) for n, fn in SOURCES.items()])
    return dict(results)
