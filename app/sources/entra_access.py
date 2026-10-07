import os

from ..graph_client import graph_get

ACKNOWLEDGED_EXCLUSIONS = {
    u.strip().lower() for u in os.environ.get("CA_ACKNOWLEDGED_EXCLUSIONS", "").split(";") if u.strip()
}


async def _resolve_principal(pid: str) -> dict:
    for path, key in (("/users/", "userPrincipalName"), ("/groups/", "displayName")):
        try:
            o = await graph_get(f"{path}{pid}", params={"$select": f"id,displayName,{key}"})
            name = o.get(key) or o.get("displayName")
            return {"id": pid, "name": name,
                    "kind": "user" if key == "userPrincipalName" else "group",
                    "acknowledged": (name or "").lower() in ACKNOWLEDGED_EXCLUSIONS}
        except Exception:
            continue
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
    acts = a.get("includeUserActions") or []
    ctx = a.get("includeAuthenticationContextClassReferences") or []
    parts = []
    if "All" in inc:
        parts.append("All apps")
    elif inc:
        parts.append(f"{len(inc)} app(s)")
    parts += [f"user action: {u.rsplit(':', 1)[-1]}" for u in acts]
    if ctx:
        parts.append(f"{len(ctx)} auth context(s)")
    return " · ".join(parts) if parts else "—"


def _session_controls(p: dict) -> list:
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
        u = cond.get("users") or {}
        excluded = []
        for pid in (u.get("excludeUsers") or []) + (u.get("excludeGroups") or []):
            excluded.append(await _resolve_principal(pid))

        policies.append({
            "id": p.get("id"),
            "name": p.get("displayName"),
            "state": p.get("state"),
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
        "exclusionTotal": sum(p["excludedCount"] for p in policies),
        "exclusionUnacknowledged": sum(p["excludedUnacknowledged"] for p in policies),
        "exclusionUnresolvable": sum(p["excludedUnresolvable"] for p in policies),
        "exclusionDistinct": len({e["id"] for p in policies for e in p["excluded"]}),
        "exclusionAckConfigured": bool(ACKNOWLEDGED_EXCLUSIONS),
    }
