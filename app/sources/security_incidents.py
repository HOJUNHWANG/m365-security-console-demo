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
    active = [x for x in shaped if is_active(x.get("status"))]
    shown = active + [x for x in shaped if not is_active(x.get("status"))][:max(0, 20 - len(active))]
    shown.sort(key=lambda x: x.get("createdDateTime") or "", reverse=True)
    return {"available": True, "incidents": shown, "activeCount": len(active)}


ACTIVE_STATUSES = {"active", "inprogress", "awaitingaction"}


def is_active(status) -> bool:
    return str(status or "").lower() in ACTIVE_STATUSES
