from ..graph_client import graph_get


async def fetch() -> dict:
    data = await graph_get(
        "/security/incidents",
        {"$top": 50, "$orderby": "createdDateTime desc"},
    )
    incs = data.get("value", [])

    def shape(i):
        return {
            "id": i.get("id"),
            "displayName": i.get("displayName"),
            "severity": i.get("severity"),
            "status": i.get("status"),
            "classification": i.get("classification"),
            "createdDateTime": i.get("createdDateTime"),
        }

    shaped = [shape(i) for i in incs]
    shaped.sort(key=lambda x: x.get("createdDateTime") or "", reverse=True)
    active = sum(1 for i in incs if i.get("status") != "resolved")
    return {"available": True, "incidents": shaped[:20], "activeCount": active}
