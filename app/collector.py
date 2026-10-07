import asyncio
import os

from . import cache, pipeline

SKIP_IF_YOUNGER_MIN = float(os.environ.get("SKIP_IF_YOUNGER_MIN", "10"))


def main():
    if SKIP_IF_YOUNGER_MIN > 0:
        age = cache.snapshot_age_minutes()
        if age is not None and age < SKIP_IF_YOUNGER_MIN:
            print(f"[collector] SKIPPED - the in-process loop collected {age:.1f} min ago "
                  f"(< {SKIP_IF_YOUNGER_MIN:g}). Nothing to do.")
            return
    snap = asyncio.run(pipeline.refresh())
    if snap.get("_collectFailed"):
        print(
            f"[collector] SKIPPED - Graph unreachable (network not ready?). "
            f"Keeping previous snapshot: {snap.get('_collectedAt')}"
        )
        return
    keys = [k for k, v in snap.items() if isinstance(v, dict) and not k.startswith("_")]
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
