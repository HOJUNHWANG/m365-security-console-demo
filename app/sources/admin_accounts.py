"""Directory role holders - a security-oriented summary.

Rewritten 2026-07-28. The old implementation queried a hand-picked list of ~15 high-risk roles and
fetched members per role, which meant any role NOT on that list was invisible: a live audit found an
active **Global Reader** and a disabled account holding a Purview role, neither of which the card
reported. Global Reader cannot change anything but can read everything (all configuration, sign-in
logs, Defender data, Exchange config), so omitting it understated the tenant's exposure.

`/roleManagement/directory/roleAssignments?$expand=roleDefinition` returns EVERY assignment in the
tenant in a single call, so coverage is now complete and cheaper than before (the old path used ~15
calls and still missed roles). `$expand=principal` is rejected (400), so principals are resolved
individually - there are only a handful of assignments in a tenant this size.

Roles are split by what compromise costs you: CONTROL roles can change things, READ_ALL roles can
read everything. Both matter; they just fail differently.
"""
import asyncio

from ..graph_client import graph_get

# Change/control roles - large blast radius if compromised.
CONTROL_ROLES = {
    "Global Administrator",
    "Privileged Role Administrator",
    "Privileged Authentication Administrator",
    "Security Administrator",
    "Conditional Access Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "Teams Administrator",
    "User Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "Authentication Administrator",
    "Helpdesk Administrator",
    "Password Administrator",
    "Hybrid Identity Administrator",
    "Intune Administrator",
    "Compliance Administrator",
    "Billing Administrator",
}

# Read-everything roles - no write access, but full reconnaissance value if compromised.
READ_ALL_ROLES = {
    "Global Reader",
    "Security Reader",
    "Security Operator",
    "Reports Reader",
}


def _classify(role: str) -> str:
    if role in CONTROL_ROLES:
        return "control"
    if role in READ_ALL_ROLES:
        return "readAll"
    return "other"


async def _all_users() -> dict:
    """One paged /users call -> {id: user}.

    Deliberately NOT a per-principal /users/{id} lookup: `/directoryObjects` omits
    `accountEnabled` for users, and doing a follow-up call per principal made the
    "disabled account still holds a role" finding fail SILENTLY whenever those calls were
    throttled during a parallel collect - the card then reported "no disabled accounts",
    which is worse than reporting nothing. One bulk call is deterministic and cheaper.
    """
    out, data = {}, await graph_get(
        "/users", params={"$select": "id,userPrincipalName,displayName,accountEnabled",
                          "$top": "999"})
    while True:
        for u in data.get("value", []):
            out[u["id"]] = u
        nxt = data.get("@odata.nextLink")
        if not nxt:
            return out
        data = await graph_get(nxt)


async def _principal(pid: str, users: dict) -> dict:
    """Resolve an assignment's principal. Can be a user, a service principal or a group."""
    u = users.get(pid)
    if u:
        return {"id": pid, "kind": "user", "name": u.get("displayName"),
                "upn": u.get("userPrincipalName"), "enabled": u.get("accountEnabled")}
    # Not a user -> service principal or group. accountEnabled is not needed for those.
    try:
        o = await graph_get(f"/directoryObjects/{pid}")
    except Exception:  # noqa: BLE001 - a stale assignment must not kill the card
        return {"id": pid, "kind": "unknown", "name": None, "upn": None, "enabled": None}
    return {
        "id": pid,
        "kind": (o.get("@odata.type") or "").rsplit(".", 1)[-1] or "unknown",
        "name": o.get("displayName"),
        "upn": o.get("userPrincipalName"),
        "enabled": o.get("accountEnabled"),
    }


async def fetch() -> dict:
    data = await graph_get(
        "/roleManagement/directory/roleAssignments",
        params={"$expand": "roleDefinition", "$top": "500"},
    )
    assignments = data.get("value", [])

    # Resolve each distinct principal once, users from one bulk call
    users = await _all_users()
    pids = {a.get("principalId") for a in assignments if a.get("principalId")}
    resolved = dict(
        zip(pids, await asyncio.gather(*[_principal(p, users) for p in pids]))
    )

    by_role: dict[str, list] = {}
    per_principal: dict[str, dict] = {}
    for a in assignments:
        role = (a.get("roleDefinition") or {}).get("displayName") or "(unknown role)"
        p = resolved.get(a.get("principalId")) or {}
        member = {
            "name": p.get("name"),
            "upn": p.get("upn"),
            "kind": p.get("kind"),
            "enabled": p.get("enabled"),
            # a role scoped to part of the directory is less dangerous than tenant-wide
            "scoped": (a.get("directoryScopeId") or "/") != "/",
        }
        by_role.setdefault(role, []).append(member)
        key = p.get("upn") or p.get("name") or p.get("id") or "?"
        e = per_principal.setdefault(
            key, {"name": p.get("name"), "upn": p.get("upn"), "kind": p.get("kind"), "count": 0, "roles": []}
        )
        e["count"] += 1
        e["roles"].append(role)

    def rows(kind: str) -> list:
        out = [
            {"role": r, "category": kind, "members": m}
            for r, m in by_role.items() if _classify(r) == kind
        ]
        out.sort(key=lambda x: len(x["members"]), reverse=True)
        return out

    control, read_all, other = rows("control"), rows("readAll"), rows("other")
    global_admins = by_role.get("Global Administrator", [])

    # Findings worth an action item rather than just a list
    disabled_with_roles = [
        {"name": m.get("name"), "upn": m.get("upn"), "role": r}
        for r, ms in by_role.items() for m in ms
        if m.get("kind") == "user" and m.get("enabled") is False
    ]
    sp_roles = [
        {"name": m.get("name"), "role": r}
        for r, ms in by_role.items() for m in ms if m.get("kind") == "servicePrincipal"
    ]
    group_roles = [
        {"name": m.get("name"), "role": r}
        for r, ms in by_role.items() for m in ms if m.get("kind") == "group"
    ]

    top = sorted(per_principal.values(), key=lambda e: e["count"], reverse=True)[:8]

    return {
        "available": True,
        # --- kept for backwards compatibility with the existing card / AI sanitiser ---
        "globalAdmins": [{"name": m["name"], "upn": m["upn"]} for m in global_admins],
        "globalAdminCount": len(global_admins),
        "privileged": control,                 # control roles, same shape as before
        "topAccounts": top,
        "highRiskRoleCount": len(control),
        # --- new: complete coverage ---
        "assignmentCount": len(assignments),
        "rolesWithMembers": len(by_role),
        "readPrivileged": read_all,            # read-everything roles (Global Reader etc.)
        "readPrivilegedCount": len(read_all),
        "otherRoles": other,                   # everything else that has a member
        "otherRoleCount": len(other),
        "disabledWithRoles": disabled_with_roles,
        "servicePrincipalRoles": sp_roles,
        "groupRoleAssignments": group_roles,
    }
