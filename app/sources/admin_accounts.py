import asyncio

from ..graph_client import graph_get

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
    u = users.get(pid)
    if u:
        return {"id": pid, "kind": "user", "name": u.get("displayName"),
                "upn": u.get("userPrincipalName"), "enabled": u.get("accountEnabled")}
    try:
        o = await graph_get(f"/directoryObjects/{pid}")
    except Exception:
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
        "globalAdmins": [{"name": m["name"], "upn": m["upn"]} for m in global_admins],
        "globalAdminCount": len(global_admins),
        "privileged": control,
        "topAccounts": top,
        "highRiskRoleCount": len(control),
        "assignmentCount": len(assignments),
        "rolesWithMembers": len(by_role),
        "readPrivileged": read_all,
        "readPrivilegedCount": len(read_all),
        "otherRoles": other,
        "otherRoleCount": len(other),
        "disabledWithRoles": disabled_with_roles,
        "servicePrincipalRoles": sp_roles,
        "groupRoleAssignments": group_roles,
    }
