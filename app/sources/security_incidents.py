"""Security incidents - correlated incidents from Defender XDR. The top-level SOC view.

Populated in a Defender for Office 365 P2 / Defender XDR environment.
Requires: SecurityIncident.Read.All
"""
from ..graph_client import graph_get


async def fetch() -> dict:
    # Must be ordered newest-first or new incidents never surface. With $top but no $orderby,
    # Graph returns the oldest incidents and pins the card to them (same issue as the alerts card).
    data = await graph_get(
        "/security/incidents",
        {"$top": 50, "$orderby": "createdDateTime desc"},
    )
    incs = data.get("value", [])

    def shape(i):
        return {
            "id": i.get("id"),   # used to deep-link to the incident in the Defender portal
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
