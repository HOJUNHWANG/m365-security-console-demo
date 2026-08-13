"""SharePoint / OneDrive external-sharing posture.

Why this card exists
--------------------
Conditional Access can only govern access that involves an identity. SharePoint's
`sharingCapability` decides whether that is even true: with anonymous "Anyone with the link"
sharing enabled, content is reachable with **no authentication at all**, so it produces no sign-in
record and no CA evaluation. Every MFA and device policy in the tenant is silently bypassed on that
path, and nothing in the identity-side dashboards reveals it.

**Correction (2026-08-03): the earlier note here claimed this tenant was on `externalUserSharingOnly`
with anonymous links OFF. That was wrong.** The tenant is on `externalUserAndGuestSharing`, i.e.
anonymous links are permitted - but deliberately: two sites are shared with a partner who said they
cannot authenticate, and the other ~32 sites are set to `Disabled` per-site.

So `sharingCapability` here is a **ceiling, not the posture**, and this card cannot see the
difference: **per-site `sharingCapability` is absent from Microsoft Graph** (not a permission gap -
the property does not exist on `/sites`). Only SPO PowerShell shows it. Treat the anonymous finding
below as "the ceiling is open, go look at the actual links" - `sharing_links.py` enumerates those.

Needs `SharePointTenantSettings.Read.All` (application permission). Note the app-only token is
cached per process, so the running server must be restarted after the permission is first granted.
"""
from ..graph_client import graph_get

# sharingCapability values, from most to least restrictive.
_CAPABILITY = {
    "disabled": ("External sharing disabled", "ok"),
    "existingExternalUserSharingOnly": ("Existing guests only", "ok"),
    "externalUserSharingOnly": ("New and existing guests (authenticated)", "ok"),
    "externalUserAndGuestSharing": ("Anyone with the link (ANONYMOUS)", "bad"),
}


async def fetch() -> dict:
    s = await graph_get("/admin/sharepoint/settings")

    cap = s.get("sharingCapability")
    cap_label, cap_sev = _CAPABILITY.get(cap, (cap or "unknown", "info"))
    # Only this value permits unauthenticated access; everything else forces a guest identity,
    # which is what brings the access under Conditional Access at all.
    anonymous = cap == "externalUserAndGuestSharing"

    idle = s.get("idleSessionSignOut") or {}
    findings = []

    if anonymous:
        findings.append({
            "severity": "high",
            "text": "Anonymous 'Anyone with the link' sharing is enabled - that access carries no "
                    "identity, so it produces no sign-in log and no Conditional Access evaluation. "
                    "MFA and device policies do not apply to it. This is the tenant ceiling; the "
                    "Anonymous Sharing Links panel shows the links that actually exist.",
        })
    if s.get("isResharingByExternalUsersEnabled"):
        findings.append({
            "severity": "med",
            "text": "External users can re-share content, so access can spread beyond the people "
                    "you invited without any further approval.",
        })
    if s.get("isLegacyAuthProtocolsEnabled"):
        findings.append({
            "severity": "med",
            "text": "Legacy authentication protocols are enabled for SharePoint - legacy clients "
                    "cannot perform interactive MFA, so this is an MFA bypass path.",
        })
    if s.get("isUnmanagedSyncAppForTenantRestricted") is False:
        findings.append({
            "severity": "med",
            "text": "The OneDrive sync client is allowed on unmanaged devices, so company files can "
                    "sync to personal machines. Restricting this breaks existing sync on unmanaged "
                    "devices, so schedule it - do not flip it casually.",
        })
    if not idle.get("isEnabled"):
        findings.append({
            "severity": "low",
            "text": "No idle session sign-out - browser sessions on shared or unattended machines "
                    "stay signed in indefinitely.",
        })
    if s.get("isSiteCreationEnabled"):
        findings.append({
            "severity": "low",
            "text": "Users can create their own sites, so the sharing surface grows without review.",
        })

    # Deliberately NOT collected: macSyncEnabled, commentingOnSitePagesEnabled,
    # deletedUserSiteRetentionDays, tenantDefaultTimezone. They are tenant trivia, never
    # referenced by any panel, and a security dashboard showing a timezone invites the reader to
    # treat everything on the page as equally meaningful.
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
        "findings": findings,
        "findingCount": len(findings),
        "highFindingCount": sum(1 for f in findings if f["severity"] == "high"),
    }
