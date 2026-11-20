import os

from ..config import settings
from ..graph_client import graph_get

ACKNOWLEDGED_EXCLUSIONS = {
    u.strip().lower()
    for u in (os.environ.get("CA_ACKNOWLEDGED_EXCLUSIONS") or settings.ca_acknowledged_exclusions or "").split(";")
    if u.strip()
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


async def _name_of(path: str, oid: str, cache: dict) -> str | None:
    key = f"{path}{oid}"
    if key not in cache:
        try:
            cache[key] = (await graph_get(key, params={"$select": "displayName"})).get("displayName")
        except Exception:
            cache[key] = None
    return cache[key]


async def _user_scope(cond: dict, cache: dict) -> str:
    u = cond.get("users") or {}
    inc = u.get("includeUsers") or []
    if "All" in inc:
        return "All users"
    parts = []
    users = [x for x in inc if x not in ("None", "GuestsOrExternalUsers")]
    if users:
        parts.append(f"{len(users)} user(s)")
    for path, ids, label in (("/groups/", u.get("includeGroups") or [], "group"),
                             ("/directoryRoleTemplates/", u.get("includeRoles") or [], "role")):
        names = [await _name_of(path, i, cache) for i in ids]
        known = [n for n in names if n]
        if known:
            parts.append(f"{label}: " + ", ".join(known))
        if len(known) < len(ids):
            parts.append(f"{len(ids) - len(known)} {label}(s)")
    if "GuestsOrExternalUsers" in inc or u.get("includeGuestsOrExternalUsers"):
        parts.append("guests")
    return " · ".join(parts) if parts else "—"


_PLATFORM = {"windows": "Windows", "macos": "macOS", "ios": "iOS", "android": "Android", "linux": "Linux",
             "windowsphone": "Windows Phone", "all": "all"}


def _conditions(cond: dict, loc_names: dict) -> list:
    out = []
    cat = [c for c in (cond.get("clientAppTypes") or []) if c != "all"]
    if cat:
        out.append("clients: " + ", ".join(cat))
    pl = cond.get("platforms") or {}
    inc = [_PLATFORM.get(p.lower(), p) for p in (pl.get("includePlatforms") or [])]
    exc = [_PLATFORM.get(p.lower(), p) for p in (pl.get("excludePlatforms") or [])]
    if inc and inc != ["all"]:
        out.append("platforms: " + ", ".join(inc) + (f" except {', '.join(exc)}" if exc else ""))
    elif exc:
        out.append("platforms: all except " + ", ".join(exc))
    lc = cond.get("locations") or {}

    def _loc(ids):
        return ", ".join({"All": "any", "AllTrusted": "trusted locations"}.get(i, loc_names.get(i, "1 location"))
                         for i in ids)
    li, le = lc.get("includeLocations") or [], lc.get("excludeLocations") or []
    if li or le:
        out.append("locations: " + (_loc(li) if li else "any") + (f" except {_loc(le)}" if le else ""))
    df = ((cond.get("devices") or {}).get("deviceFilter") or {})
    if df.get("rule"):
        out.append(f"device filter ({df.get('mode') or 'include'}): {df['rule']}")
    for k, label in (("signInRiskLevels", "sign-in risk"), ("userRiskLevels", "user risk")):
        if cond.get(k):
            out.append(f"{label}: " + ", ".join(cond[k]))
    return out


def _app_scope(cond: dict) -> str:
    a = cond.get("applications") or {}
    inc = a.get("includeApplications") or []
    acts = a.get("includeUserActions") or []
    ctx = a.get("includeAuthenticationContextClassReferences") or []
    parts = []
    exc = a.get("excludeApplications") or []
    named = [x for x in inc if x in ("Office365", "MicrosoftAdminPortals")]
    if "All" in inc:
        parts.append("All apps" + (f" (except {len(exc)})" if exc else ""))
    elif inc:
        parts += named
        if len(inc) > len(named):
            parts.append(f"{len(inc) - len(named)} app(s)")
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
    loc_names = {n.get("id"): n.get("displayName") for n in nl.get("value", []) if n.get("id")}
    name_cache: dict = {}
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
            "users": await _user_scope(cond, name_cache),
            "apps": _app_scope(cond),
            "conditions": _conditions(cond, loc_names),
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
