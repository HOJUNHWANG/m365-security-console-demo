"""Recent directory audit - history of admin and configuration changes (who did what).

Entra Free retains directory audit logs for 7 days.
"""
from ..graph_client import graph_get


async def fetch() -> dict:
    data = await graph_get("/auditLogs/directoryAudits", {
        "$top": 15,
        "$orderby": "activityDateTime desc",
    })
    items = []
    for a in data.get("value", []):
        ib = a.get("initiatedBy", {}) or {}
        who = (
            (ib.get("user", {}) or {}).get("userPrincipalName")
            or (ib.get("app", {}) or {}).get("displayName")
            or "?"
        )
        items.append({
            "activity": a.get("activityDisplayName"),
            "by": who,
            "result": a.get("result"),
            "time": a.get("activityDateTime"),
        })
    return {"available": True, "items": items}
