import os
from datetime import datetime, timezone

from . import ai_overview, cache, graph_client
from .registry import collect_all

AI_MIN_INTERVAL_MIN = 55

CARRY_FORWARD_MAX_MIN = float(os.environ.get("CARRY_FORWARD_MAX_MIN", "360"))


def _recent_overview():
    prev = cache.read_snapshot() or {}
    ov = prev.get("_aiOverview")
    if not (ov and ov.get("available") and ov.get("generatedAt")):
        return None
    try:
        age_min = (datetime.now(timezone.utc) - datetime.fromisoformat(ov["generatedAt"])).total_seconds() / 60
    except Exception:
        return None
    if not ov.get("textKo"):
        return None
    return ov if 0 <= age_min < AI_MIN_INTERVAL_MIN else None


def _carry_forward(data: dict, prev: dict | None) -> None:
    if not prev:
        return
    now = datetime.now(timezone.utc)
    for key, cur in data.items():
        if key.startswith("_") or not isinstance(cur, dict) or cur.get("available"):
            continue
        old = prev.get(key)
        if not isinstance(old, dict) or not old.get("available"):
            continue
        as_of = (old.get("carried") or {}).get("asOf") or prev.get("_collectedAt")
        try:
            when = datetime.fromisoformat(str(as_of).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            continue
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        age_min = (now - when).total_seconds() / 60
        if not 0 <= age_min <= CARRY_FORWARD_MAX_MIN:
            continue
        data[key] = {**old, "carried": {
            "asOf": as_of,
            "ageMin": round(age_min, 1),
            "reason": cur.get("reason"),
        }}


async def refresh() -> dict:
    reachable = await graph_client.check_connectivity()
    data = await collect_all()
    _carry_forward(data, cache.read_snapshot())

    if not reachable:
        prev = cache.read_snapshot()
        base = prev if prev is not None else data
        return {**base, "_collectFailed": True}

    overview = _recent_overview()
    if overview is None:
        overview = await ai_overview.generate(data)
    if overview is not None:
        data["_aiOverview"] = overview
    snap = cache.write_snapshot(data)
    cache.append_history(data)
    return snap
