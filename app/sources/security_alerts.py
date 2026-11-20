from ..graph_client import graph_get


async def fetch() -> dict:
    data = await graph_get(
        "/security/alerts_v2",
        {"$top": 50, "$orderby": "createdDateTime desc"},
    )
    items = [
        {
            "id": a.get("id"),
            "title": a.get("title"),
            "severity": a.get("severity"),
            "status": a.get("status"),
            "created": a.get("createdDateTime"),
            "source": a.get("serviceSource"),
        }
        for a in data.get("value", [])
    ]
    active = [i for i in items if i.get("status") != "resolved"]
    endpoint = sum(1 for i in active if i.get("source") == "microsoftDefenderForEndpoint")
    return {"available": True, "alerts": active[:15], "count": len(active), "endpointCount": endpoint}
