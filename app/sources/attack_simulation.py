"""Attack simulation training - phishing simulation status (Defender for Office 365 P2).

Requires: AttackSimulation.Read.All
"""
from ..graph_client import graph_get


async def fetch() -> dict:
    data = await graph_get("/security/attackSimulation/simulations", {"$top": 20})
    # Drop noise: excluded entries and throwaway items named "TEST",
    # leaving only real training campaigns.
    sims = [
        s
        for s in data.get("value", [])
        if s.get("status") != "excluded"
        and (s.get("displayName") or "").strip().upper() != "TEST"
    ]

    def shape(s):
        return {
            "displayName": s.get("displayName"),
            "status": s.get("status"),
            "attackType": s.get("attackType"),
            "createdDateTime": s.get("createdDateTime"),
        }

    shaped = [shape(s) for s in sims]
    shaped.sort(key=lambda x: x.get("createdDateTime") or "", reverse=True)
    return {"available": True, "simulations": shaped[:15], "count": len(sims)}
