"""Graph snapshot + AI summary collector - run periodically by Task Scheduler.

Refreshes data/graph_snapshot.json, appends to the history, and (if a key is set)
generates the AI summary.
Run from the project root:  .venv\\Scripts\\python.exe -m app.collector

This is the BACKSTOP, not the primary path: the web app runs the same collection in-process every 20
minutes (see main.py for why - the scheduled task silently misses days when the machine is asleep at
the daily occurrence time). Both write the same snapshot, and the comment in main.py used to call the
overlap "wasteful but harmless".

It was not harmless. Two full collects every 20 minutes means paging /auditLogs/signIns twice as
often as needed, and that endpoint is the most throttle-sensitive call in the whole collection. On
2026-08-05 the tenant was returning 429 to *every* filtered signIns query - even `$top=5` - which
took out the three sources that share the sign-in pull. The web loop already skips a collect when the
snapshot is fresh; the backstop had no such guard and so always collected, doubling the load whether
or not it was needed. Now it defers, which is what a backstop should do.

SKIP_IF_YOUNGER_MIN=0 forces a collect regardless (used by `-Force` in the .cmd, and useful when the
loop is known to be down).
"""
import asyncio
import os

from . import cache, pipeline

SKIP_IF_YOUNGER_MIN = float(os.environ.get("SKIP_IF_YOUNGER_MIN", "10"))


def main():
    if SKIP_IF_YOUNGER_MIN > 0:
        age = cache.snapshot_age_minutes()
        if age is not None and age < SKIP_IF_YOUNGER_MIN:
            print(f"[collector] SKIPPED - the in-process loop collected {age:.1f} min ago "
                  f"(< {SKIP_IF_YOUNGER_MIN:g}). Nothing to do; this task is the backstop.")
            return
    snap = asyncio.run(pipeline.refresh())
    if snap.get("_collectFailed"):
        # Collection failed (e.g. network not up yet after boot/resume) - the good cache was preserved.
        print(
            f"[collector] SKIPPED - Graph unreachable (network not ready?). "
            f"Keeping previous snapshot: {snap.get('_collectedAt')}"
        )
        return
    keys = [k for k, v in snap.items() if isinstance(v, dict) and not k.startswith("_")]
    # Carried sources have available=True but are not fresh - see main.py for why they are counted
    # apart. A backstop that prints "21/21 OK" during an outage is worse than one that prints nothing.
    carried = [k for k in keys if snap[k].get("available") and snap[k].get("carried")]
    down = [k for k in keys if not snap[k].get("available")]
    fresh = len(keys) - len(carried) - len(down)
    ai = snap.get("_aiOverview")
    aimsg = "AI ok" if (ai and ai.get("available")) else ("AI off" if ai is None else "AI fail")
    print(f"[collector] {fresh}/{len(keys)} fresh, {len(carried)} carried, {len(down)} down "
          f"| {aimsg} | {snap.get('_collectedAt')}")
    if carried:
        print(f"[collector]   carried: {', '.join(carried)}")
    if down:
        print(f"[collector]   down: {', '.join(down)}")


if __name__ == "__main__":
    main()
