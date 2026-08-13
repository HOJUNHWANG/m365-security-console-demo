"""Secure Score recommendations - the unimplemented controls that would raise the score most.

Compares the current per-control score from secureScores against the maximum from
secureScoreControlProfiles, and ranks by the resulting potential gain (gap).
"""
from ..graph_client import graph_get


async def fetch() -> dict:
    profiles_data = await graph_get("/security/secureScoreControlProfiles", {"$top": 300})
    profiles = {p.get("id"): p for p in profiles_data.get("value", [])}

    scores_data = await graph_get("/security/secureScores", {"$top": 1})
    scores = scores_data.get("value", [])
    if not scores:
        return {"available": True, "recommendations": []}

    recs = []
    for cs in scores[0].get("controlScores", []):
        prof = profiles.get(cs.get("controlName"), {})
        max_score = prof.get("maxScore") or 0
        cur = cs.get("score") or 0
        gap = max_score - cur
        if gap > 0 and max_score > 0:
            recs.append({
                "title": prof.get("title") or cs.get("controlName"),
                "gap": round(gap, 1),
                "category": prof.get("controlCategory"),
            })
    recs.sort(key=lambda r: r["gap"], reverse=True)
    return {"available": True, "recommendations": recs[:8]}
