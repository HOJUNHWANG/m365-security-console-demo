"""Collection pipeline - collect_all + AI summary + cache/history write.
Shared by the API endpoint and the scheduled collector."""
import os
from datetime import datetime, timezone

from . import ai_overview, cache, graph_client
from .registry import collect_all

# Minimum interval between AI summary regenerations (minutes). Even though collection runs every
# 20 minutes, the summary is regenerated only ~hourly to limit outbound calls to Groq and cost.
# 55 minutes ensures the top-of-the-hour collection always regenerates it.
AI_MIN_INTERVAL_MIN = 55

# How long a source may keep showing its last good value after it starts failing.
#
# `refresh()` already protected the WHOLE snapshot when Graph was unreachable, but had no answer for
# the ordinary case: Graph is up, twenty sources succeed, and three fail. Those three were written as
# `{"available": false, "reason": …}`, so a transient failure blanked whole tabs - on 2026-08-05 a
# throttle emptied Risky Sign-ins, Device Identity and Browser Claims for the entire morning, and the
# data that had been collected 20 minutes earlier was thrown away to do it.
#
# So a failed source now carries its previous value forward, labelled with its true age. Six hours is
# the cutoff: long enough to ride out a throttle or a reboot, short enough that nobody makes a
# conditional-access decision on data from the previous working day. Past it the source goes properly
# unavailable, because at that point "no data" is the honest answer.
CARRY_FORWARD_MAX_MIN = float(os.environ.get("CARRY_FORWARD_MAX_MIN", "360"))


def _recent_overview():
    """Reuse the previous snapshot's AI summary if it is recent (within AI_MIN_INTERVAL_MIN)."""
    prev = cache.read_snapshot() or {}
    ov = prev.get("_aiOverview")
    if not (ov and ov.get("available") and ov.get("generatedAt")):
        return None
    try:
        age_min = (datetime.now(timezone.utc) - datetime.fromisoformat(ov["generatedAt"])).total_seconds() / 60
    except Exception:  # noqa: BLE001 - if the timestamp will not parse, just regenerate
        return None
    return ov if 0 <= age_min < AI_MIN_INTERVAL_MIN else None


def _carry_forward(data: dict, prev: dict | None) -> None:
    """Replace this cycle's failed sources with their last good value, in place.

    The carried value keeps its ORIGINAL `asOf`, not the time it was carried. Re-stamping it would
    make a value that has been carried for hours look like it was just collected - the exact failure
    this is meant to prevent - and the age would never grow past one cycle.
    """
    if not prev:
        return
    now = datetime.now(timezone.utc)
    for key, cur in data.items():
        if key.startswith("_") or not isinstance(cur, dict) or cur.get("available"):
            continue
        old = prev.get(key)
        if not isinstance(old, dict) or not old.get("available"):
            continue
        # An already-carried value keeps its first timestamp; a fresh one is dated by the snapshot it
        # came from.
        as_of = (old.get("carried") or {}).get("asOf") or prev.get("_collectedAt")
        try:
            # Same normalisation as cache.snapshot_age_minutes: tolerate a trailing Z and a naive
            # timestamp, since both have appeared in snapshots written by older versions.
            when = datetime.fromisoformat(str(as_of).replace("Z", "+00:00"))
        except (TypeError, ValueError):
            continue  # cannot age it, so cannot honestly carry it
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        age_min = (now - when).total_seconds() / 60
        if not 0 <= age_min <= CARRY_FORWARD_MAX_MIN:
            continue
        data[key] = {**old, "carried": {
            "asOf": as_of,
            "ageMin": round(age_min, 1),
            # Keep the live failure reason: the panel shows data, so the reason it is not fresh has
            # to travel with it or the failure becomes invisible.
            "reason": cur.get("reason"),
        }}


async def refresh() -> dict:
    """Collect, then write to cache/history only if Graph was actually reachable.

    If the whole collection fails because the network is not up yet (right after boot or
    resume, when nearly every Graph source dies), return the previous good snapshot instead
    of overwriting it. Without this, a failed startup collection replaces a good cache with
    "14/17 unavailable/403" and injects a null point into the trend history. The AI summary
    is skipped in that case too.
    """
    reachable = await graph_client.check_connectivity()
    data = await collect_all()
    _carry_forward(data, cache.read_snapshot())

    if not reachable:
        prev = cache.read_snapshot()
        base = prev if prev is not None else data  # nothing to preserve (first run): skip the write, still return the result
        return {**base, "_collectFailed": True}

    overview = _recent_overview()  # reuse a recent summary (skips regeneration and the outbound call)
    if overview is None:
        overview = await ai_overview.generate(data)  # None when no key is set (nothing is sent)
    if overview is not None:
        data["_aiOverview"] = overview
    snap = cache.write_snapshot(data)
    cache.append_history(data)
    return snap
