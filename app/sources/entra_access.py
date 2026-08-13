"""Entra ID access policies - Security Defaults and Conditional Access (P1).

Available with Business Premium (Entra ID P1). Security Defaults (the free baseline) and
Conditional Access are mutually exclusive - exactly one is active. Requires Policy.Read.All
(application permission, already consented).
Policy user/app targets are reduced to a scope summary (All / N targets) to avoid GUID noise
and identifying data.
"""
import os

from ..graph_client import graph_get

# Exclusions that are known and intended (break-glass accounts, room mailboxes ...). Set as a
# semicolon-separated UPN list so the card can separate "we meant this" from "why is this here".
# Deliberately NOT hardcoded: the break-glass UPNs must not appear in this repo.
ACKNOWLEDGED_EXCLUSIONS = {
    u.strip().lower() for u in os.environ.get("CA_ACKNOWLEDGED_EXCLUSIONS", "").split(";") if u.strip()
}


async def _resolve_principal(pid: str) -> dict:
    """Turn an exclusion GUID into something readable. Users and groups are both possible."""
    for path, key in (("/users/", "userPrincipalName"), ("/groups/", "displayName")):
        try:
            o = await graph_get(f"{path}{pid}", params={"$select": f"id,displayName,{key}"})
            name = o.get(key) or o.get("displayName")
            return {"id": pid, "name": name,
                    "kind": "user" if key == "userPrincipalName" else "group",
                    "acknowledged": (name or "").lower() in ACKNOWLEDGED_EXCLUSIONS}
        except Exception:  # noqa: BLE001 - wrong type or deleted object; try the next shape
            continue
    # A GUID that resolves to nothing is a ghost exclusion - this tenant has had them before.
    return {"id": pid, "name": None, "kind": "unresolvable", "acknowledged": False}


def _user_scope(cond: dict) -> str:
    u = cond.get("users") or {}
    inc = u.get("includeUsers") or []
    if "All" in inc:
        return "All users"
    n = len(inc) + len(u.get("includeGroups") or []) + len(u.get("includeRoles") or [])
    return f"{n} target(s)" if n else "—"


def _app_scope(cond: dict) -> str:
    a = cond.get("applications") or {}
    inc = a.get("includeApplications") or []
    if "All" in inc:
        return "All apps"
    return f"{len(inc)} app(s)" if inc else "—"


def _session_controls(p: dict) -> list:
    """Names of the enabled session controls on a policy.

    Some policies carry no grant control at all - token protection (secureSignInSession) and
    sign-in frequency are session controls - so reading only grantControls makes such a policy
    look like it enforces nothing. Each sub-object is {isEnabled: bool, ...}; a few are plain
    booleans, so both shapes are handled.
    """
    out = []
    for name, val in (p.get("sessionControls") or {}).items():
        if isinstance(val, dict):
            if val.get("isEnabled"):
                out.append(name)
        elif val:
            out.append(name)
    return out


async def fetch() -> dict:
    sd = await graph_get("/policies/identitySecurityDefaultsEnforcementPolicy")
    ca = await graph_get("/identity/conditionalAccess/policies")
    nl = await graph_get("/identity/conditionalAccess/namedLocations")

    pols = ca.get("value", [])
    policies = []
    for p in pols:
        cond = p.get("conditions") or {}
        grant = p.get("grantControls") or {}
        # Exclusions, resolved. They are the standing hole in every policy and the easiest thing to
        # forget: this tenant has already had a ghost-exclusion cleanup, and on 2026-08-04 four users
        # were excluded from the device pilots as a "temporary" measure while a re-registration is on
        # hold - i.e. indefinitely. A number on screen is the only thing that keeps that visible.
        u = cond.get("users") or {}
        excluded = []
        for pid in (u.get("excludeUsers") or []) + (u.get("excludeGroups") or []):
            excluded.append(await _resolve_principal(pid))

        policies.append({
            "id": p.get("id"),   # used to deep-link to the policy in the Entra portal
            "name": p.get("displayName"),
            "state": p.get("state"),   # enabled | disabled | enabledForReportingButNotEnforced
            "controls": grant.get("builtInControls") or [],
            "sessionControls": _session_controls(p),
            "operator": grant.get("operator"),
            "users": _user_scope(cond),
            "apps": _app_scope(cond),
            "excluded": excluded,
            "excludedCount": len(excluded),
            "excludedUnacknowledged": sum(1 for e in excluded if not e["acknowledged"]),
            "excludedUnresolvable": sum(1 for e in excluded if e["kind"] == "unresolvable"),
        })
    # Does any enabled CA policy actually require MFA? If Security Defaults is off and this is
    # False, there is no baseline MFA enforcement at all (the Overview raises an action item).
    mfa_by_ca = any(
        p.get("state") == "enabled" and "mfa" in (p.get("controls") or [])
        for p in policies
    )
    return {
        "available": True,
        "securityDefaults": bool(sd.get("isEnabled")),
        "caPolicyCount": len(pols),
        "caEnabledCount": sum(1 for p in pols if p.get("state") == "enabled"),
        "caReportOnlyCount": sum(1 for p in pols if p.get("state") == "enabledForReportingButNotEnforced"),
        "mfaEnforcedByCa": mfa_by_ca,
        "namedLocationCount": len(nl.get("value", [])),
        "caPolicies": policies,
        # Tenant-wide exclusion picture. `acknowledged` is driven by CA_ACKNOWLEDGED_EXCLUSIONS, so an
        # unacknowledged count above zero means "someone has to say whether this is still intended".
        "exclusionTotal": sum(p["excludedCount"] for p in policies),
        "exclusionUnacknowledged": sum(p["excludedUnacknowledged"] for p in policies),
        "exclusionUnresolvable": sum(p["excludedUnresolvable"] for p in policies),
        "exclusionDistinct": len({e["id"] for p in policies for e in p["excluded"]}),
        "exclusionAckConfigured": bool(ACKNOWLEDGED_EXCLUSIONS),
    }
