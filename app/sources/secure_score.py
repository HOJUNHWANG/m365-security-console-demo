"""Microsoft Secure Score - the score and its trend."""
from ..graph_client import graph_get


async def fetch() -> dict:
    data = await graph_get("/security/secureScores", {"$top": 7})
    scores = data.get("value", [])
    if not scores:
        return {"available": True, "current": None, "max": None, "history": []}

    latest = scores[0]
    history = [
        {"date": s.get("createdDateTime"), "score": s.get("currentScore")}
        for s in reversed(scores)
    ]
    return {
        "available": True,
        "current": latest.get("currentScore"),
        "max": latest.get("maxScore"),
        "history": history,
    }
