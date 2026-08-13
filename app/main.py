import asyncio
import contextlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from . import cache, graph_stats, pipeline, signin_cache
from .sources import exchange_eop

# Log under uvicorn's own logger. A plain getLogger("collector.loop") propagates to a root
# logger that uvicorn never configures, so every line was silently dropped - and a collector
# nobody can see is exactly what let this break twice unnoticed.
log = logging.getLogger("uvicorn.error")

# ---------------------------------------------------------------------------------------------
# In-process collection loop
#
# Collection used to depend solely on the "MS365 Dashboard - Graph Collect" scheduled task, whose
# 20-minute cadence comes from a daily calendar trigger with a repetition. That arrangement stops
# silently whenever the machine is asleep at the daily occurrence time (07:00): the occurrence is
# missed, StartWhenAvailable runs a one-off catch-up after resume, and the repetition series for
# that day never arms. Observed twice - 2026-07-31 (overnight standby) and 2026-08-03 (weekend
# standby), the second time with MultipleInstances=Queue already applied, which proved the earlier
# "instance collision" theory wrong. The scheduler's operational log shows zero id=107 events for
# this task on either day while firing 60 for other tasks in the same window.
#
# This web app, by contrast, has been up continuously since 2026-07-27 and survives standby, so the
# loop lives here and the scheduled task becomes a backstop rather than the critical path. Both
# write the same snapshot, so an overlap is wasteful but harmless.
#
# COLLECT_INTERVAL_MIN=0 disables the loop (e.g. if the scheduled task is preferred again).
# ---------------------------------------------------------------------------------------------
COLLECT_INTERVAL_MIN = int(os.environ.get("COLLECT_INTERVAL_MIN", "20"))
COLLECT_STARTUP_DELAY_SEC = int(os.environ.get("COLLECT_STARTUP_DELAY_SEC", "60"))

# ---------------------------------------------------------------------------------------------
# Collection window (LOCAL time, "startHour-endHour", end exclusive).
#
# The backstop scheduled task has always carried Repetition.Duration=PT9H40M from 07:00, so its last
# fire is ~16:40 - a deliberate quiet period after hours. When collection moved in here, that intent
# was silently lost: this loop had no clock and has been running around it ever since, ~72 cycles a day
# instead of ~29. For a throttle-sensitive endpoint like /auditLogs/signIns, 2.5x the intended daily
# volume is not a rounding error, and it went unnoticed because nothing reported the schedule.
#
# ONE exception: while the shared sign-in window is still backfilling, the loop keeps working outside
# the window. Converging is the whole point of backfill, and stopping overnight would restart the wait
# each morning. Same reasoning as skipping the reuse interval while incomplete (signin_cache).
#
# Empty or malformed value = no restriction (previous behaviour).
COLLECT_ACTIVE_HOURS = os.environ.get("COLLECT_ACTIVE_HOURS", "7-17")


def _parse_hours(spec: str) -> tuple[int, int] | None:
    try:
        start_s, end_s = str(spec).split("-")
        start, end = int(start_s), int(end_s)
    except (ValueError, AttributeError):
        return None
    if not (0 <= start <= 24 and 0 <= end <= 24) or start == end:
        return None
    return start, end


_ACTIVE_HOURS = _parse_hours(COLLECT_ACTIVE_HOURS)


def _within_window(when: datetime | None = None) -> bool:
    """Is local time inside the collection window? True when no window is configured."""
    if _ACTIVE_HOURS is None:
        return True
    hour = (when or datetime.now()).hour
    start, end = _ACTIVE_HOURS
    # A window that wraps past midnight (e.g. 22-6) is inside when either side matches.
    return start <= hour < end if start < end else (hour >= start or hour < end)


def _backfilling() -> bool:
    """Is the shared sign-in window still incomplete? Reading it is cheap (cached after first load)."""
    try:
        return not signin_cache.coverage_info().get("complete")
    except Exception:  # noqa: BLE001 - never let a status read stop the loop
        return False

# The skip guard exists so the loop does not re-collect on top of a *very recent* collection (the
# backstop scheduled task, or the user pressing "Collect now"). It must NOT be compared against the
# full interval.
#
# The bug that caused three mornings of "auto-collect stopped" (2026-07-31, 08-03, 08-04): the loop
# sleeps exactly COLLECT_INTERVAL_MIN *after finishing* a collect, and _collectedAt is stamped at
# that same moment - so at the next tick the age is 20.000... minutes and `age < 20` is decided by
# floating-point jitter. Landing a hair under meant a SILENT skip (it logged at DEBUG, which uvicorn
# does not show), and the loop then slept another full interval. Effective cadence became 40 minutes,
# and from outside it looked exactly like a dead collector.
#
# Half the interval is far from both boundaries: a tick one interval after a collect always collects,
# while a manual collect seconds earlier is still absorbed.
COLLECT_SKIP_IF_YOUNGER_MIN = max(1.0, COLLECT_INTERVAL_MIN / 2)

# One collection at a time. The API's ?live=1 path shares this, so a manual "Collect now" and a
# scheduled tick cannot run concurrently and double-write the snapshot.
_collect_lock = asyncio.Lock()


# Outcome of the last N collections, for the Data Health tab.
#
# In-memory on purpose: this answers "what has this worker been doing", and the pattern over cycles is
# the thing that mattered on 2026-08-05 - a flat run of identical partial failures is what finally
# showed that waiting could not fix it. Persistent facts live in the snapshot and signin_store; a
# restart clears this and the tab says so.
_recent_cycles: list[dict] = []
MAX_CYCLES = 24


async def _collect_once(reason: str) -> dict:
    async with _collect_lock:
        started = time.monotonic()
        snap = await pipeline.refresh()
        if snap.get("_collectFailed"):
            log.warning("collect (%s) SKIPPED - Graph unreachable; kept %s",
                        reason, snap.get("_collectedAt"))
            return snap
        keys = [k for k, v in snap.items() if isinstance(v, dict) and not k.startswith("_")]
        # A carried-forward source has available=True (pipeline._carry_forward keeps the last good
        # value so the tab still renders). Counting it as OK would report 21/21 for a cycle in which
        # three sources actually failed - the log would go quiet exactly when it matters. So carried
        # sources are counted and named separately from fresh ones.
        down = [k for k in keys if not snap[k].get("available")]
        carried = [k for k in keys if snap[k].get("available") and snap[k].get("carried")]
        fresh = len(keys) - len(down) - len(carried)
        parts = []
        if carried:
            parts.append("CARRIED (stale, last good value): " + ", ".join(
                f"{k} ({snap[k]['carried'].get('ageMin')} min old"
                f" - {snap[k]['carried'].get('reason') or 'no reason'})" for k in carried))
        # Name the failures. "18/20" on its own sends you digging through the snapshot by hand, and a
        # partial collect is the case you most need to understand quickly.
        if down:
            parts.append("FAILED: " + ", ".join(
                f"{k} ({snap[k].get('reason') or 'no reason'})" for k in down))
        _recent_cycles.append({
            "at": datetime.now(timezone.utc).isoformat(),
            "trigger": reason,
            "seconds": round(time.monotonic() - started, 1),
            "total": len(keys), "fresh": fresh, "carried": len(carried), "down": len(down),
            "downKeys": down, "carriedKeys": carried,
        })
        del _recent_cycles[:-MAX_CYCLES]

        summary_line = "collect (%s) %d/%d fresh, %d carried, %d down | %s"
        args = (reason, fresh, len(keys), len(carried), len(down), snap.get("_collectedAt"))
        if parts:
            # The detail goes in as an ARGUMENT, never concatenated into the format string. Failure
            # reasons carry Graph URLs, and a percent-encoded one ("...%3a...") makes logging try to
            # interpret `%3a` as a format spec: it gives up and dumps the raw template instead, so the
            # log went blind on exactly the partial collects it exists to explain (seen 2026-08-05).
            log.warning(summary_line + " | %s", *args, " | ".join(parts))
        else:
            log.info(summary_line, *args)
        return snap


async def _collect_loop() -> None:
    # Let the server finish starting, and let the network settle after a boot or resume, before the
    # first collection. pipeline.refresh() already preserves the previous snapshot if Graph is
    # unreachable, so a premature run is not destructive - just noisy.
    await asyncio.sleep(COLLECT_STARTUP_DELAY_SEC)
    while True:
        try:
            age = cache.snapshot_age_minutes() if hasattr(cache, "snapshot_age_minutes") else None
            if not _within_window() and not _backfilling():
                # Outside the configured hours and nothing is catching up: stay off the tenant.
                # INFO, not silence - a quiet loop must never look like a dead one.
                log.info("collect (loop) skipped - outside the collection window (%s local)",
                         COLLECT_ACTIVE_HOURS)
            elif age is not None and age < COLLECT_SKIP_IF_YOUNGER_MIN:
                # Something else (the backstop task, or a manual Collect now) refreshed just now.
                # Logged at INFO on purpose: a skip must never be indistinguishable from a loop that
                # has died. That was the whole reason the 40-minute cadence went unnoticed.
                log.info("collect (loop) skipped - snapshot is only %.1f min old (< %.1f)",
                         age, COLLECT_SKIP_IF_YOUNGER_MIN)
            else:
                if not _within_window():
                    log.info("collect (loop) running outside the window (%s local) - the sign-in "
                             "window is still backfilling and stopping would restart the wait",
                             COLLECT_ACTIVE_HOURS)
                await _collect_once("loop")
        except asyncio.CancelledError:
            raise
        except Exception:  # noqa: BLE001 - a failed cycle must not kill the loop
            log.exception("collect cycle failed; continuing")
        await asyncio.sleep(COLLECT_INTERVAL_MIN * 60)


@contextlib.asynccontextmanager
async def lifespan(_app: FastAPI):
    task = None
    if COLLECT_INTERVAL_MIN > 0:
        task = asyncio.create_task(_collect_loop())
        log.info("in-process collection loop started, every %d min", COLLECT_INTERVAL_MIN)
    try:
        yield
    finally:
        if task:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task


app = FastAPI(title="MS365 Security Dashboard", lifespan=lifespan)
STATIC_DIR = Path(__file__).parent / "static"


def _data_health(snap: dict) -> dict:
    """Everything about the COLLECTION rather than the tenant, for the Data Health tab.

    Built at request time, not stored in the snapshot: half of it is live process state (Graph
    counters, cycle history, sign-in window coverage) and freezing that into a file is what made an
    earlier audit misread a working Trends panel as dead.

    This tab exists because 2026-08-05 was spent answering questions the dashboard could not answer
    about itself: is a source stale or dead, is this a timeout or a throttle, how many requests are we
    making, has the failure changed, and how much of the sign-in window do we actually hold.
    """
    sources = []
    for k, v in snap.items():
        if k.startswith("_") or not isinstance(v, dict) or "available" not in v:
            continue
        carried = v.get("carried") or {}
        sources.append({
            "key": k,
            "state": "down" if not v.get("available") else ("carried" if carried else "fresh"),
            "reason": v.get("reason") or carried.get("reason"),
            "ageMin": carried.get("ageMin"),
            # Byte size answers "is this worth collecting", which is otherwise guesswork.
            "bytes": len(json.dumps(v, ensure_ascii=False, default=str)),
        })
    sources.sort(key=lambda s: ({"down": 0, "carried": 1, "fresh": 2}[s["state"]], -s["bytes"]))

    return {
        "sources": sources,
        "signinWindow": {**signin_cache.coverage_info(), **signin_cache.stale_info(),
                         "staleMaxMin": signin_cache.STALE_MAX_MIN,
                         "refreshMin": signin_cache.INCREMENTAL_REFRESH_MIN,
                         "coldRefreshMin": signin_cache.MIN_REFRESH_MIN,
                         "pageSize": signin_cache.PAGE_SIZE,
                         "pageDelaySec": signin_cache.PAGE_DELAY_SEC,
                         "maxPagesPerCycle": signin_cache.MAX_PAGES_PER_CYCLE},
        "collection": {
            "intervalMin": COLLECT_INTERVAL_MIN,
            "skipIfYoungerMin": COLLECT_SKIP_IF_YOUNGER_MIN,
            # Surfaced so the schedule cannot silently disappear again the way it did when collection
            # moved in-process. `outsideButRunning` is the backfill exception in action.
            "activeHours": COLLECT_ACTIVE_HOURS if _ACTIVE_HOURS else None,
            "withinWindow": _within_window(),
            "outsideButRunning": (not _within_window()) and _backfilling(),
            "lastCollectedAt": snap.get("_collectedAt"),
            "snapshotAgeMin": (round(cache.snapshot_age_minutes(), 1)
                               if cache.snapshot_age_minutes() is not None else None),
            "snapshotBytes": len(json.dumps(snap, ensure_ascii=False, default=str)),
            "cycles": list(reversed(_recent_cycles)),
        },
        "graph": graph_stats.snapshot(),
    }


@app.get("/api/health")
async def health():
    """Data Health on its own, so it can be polled without re-serving the whole snapshot."""
    return _data_health(cache.read_snapshot() or {})


@app.get("/api/summary")
async def summary(live: bool = False):
    """Serves the cached snapshot by default (instant). live=1 forces a fresh collection
    plus AI summary, then updates the cache and history."""
    if live:
        # Goes through _collect_once so a manual collect is logged like any other - previously the
        # ?live=1 path wrote a snapshot with no log line at all, which made the log lie about when
        # collections happened and hid partial failures triggered by hand.
        snap = await _collect_once("live")
    else:
        snap = cache.read_snapshot()
        if snap is None:  # no cache yet - collect live once
            async with _collect_lock:
                snap = await pipeline.refresh()
    out = dict(snap)
    if not live:
        # Mail security (EXO) only reads the local exo_snapshot.json, so it would otherwise be
        # frozen at the moment the combined Graph cache was written. When an EXO collection lands
        # at the same time as a Graph collection it can lag a full cycle, making it look as if
        # "the 13:00 collection was skipped". Reading the file is instant (no network), so re-read
        # the latest EXO file even when serving from cache.
        try:
            out["exchangeEop"] = await exchange_eop.fetch()
        except Exception:
            pass  # on failure keep the cached value
    out["_history"] = cache.read_history()
    out["_dataHealth"] = _data_health(out)
    return out


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
