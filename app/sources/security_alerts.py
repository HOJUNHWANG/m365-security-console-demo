"""Security alerts - Microsoft 365 alerts (alerts_v2), unresolved first.

On Business Standard there may be few alerts or none at all (none is displayed as healthy).
"""
from ..graph_client import graph_get


async def fetch() -> dict:
    # Must be ordered newest-first or new alerts never surface. With $top but no $orderby,
    # Graph returns the oldest alerts, which pinned the card to ancient ones.
    data = await graph_get(
        "/security/alerts_v2",
        {"$top": 50, "$orderby": "createdDateTime desc"},
    )
    items = [
        {
            "id": a.get("id"),   # used to deep-link to the alert in the Defender portal
            "title": a.get("title"),
            "severity": a.get("severity"),
            "status": a.get("status"),
            "created": a.get("createdDateTime"),
        }
        for a in data.get("value", [])
    ]
    active = [i for i in items if i.get("status") != "resolved"]
    return {"available": True, "alerts": active[:15], "count": len(active)}
