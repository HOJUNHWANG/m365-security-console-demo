"""One sign-in pull per collection cycle, shared by every source that needs it, fetched INCREMENTALLY.

Why this exists
---------------
Three sources each paged the same window of `/auditLogs/signIns` independently - `risky_signins`,
`device_identity` and `browser_claims`, all 7 days, all capped at 8000, all page size 1000. That is
the heaviest call in the whole collection, and it was being made three times for identical data.

`risky_signins` already fetched **full records** (no `$select`), so a single unfiltered pull is a
superset of what the other two need - nothing is lost by sharing it. Records are likewise STORED
whole: trimming them to the fields currently used would save disk but reintroduces the one failure
mode worth avoiding here - a field quietly missing turns a security number wrong rather than making
it error - and the store can never be re-derived without another Graph pull.

Why the pull is incremental
---------------------------
Sharing the pull cut three requests to one, but one full 7-day pull every 20 minutes was still the
wrong shape: a 20-minute step against a 7-day window is 0.2% new data, so ~99.8% of every pull was
records already held. Two processes doing that three times an hour (the web loop and the backstop
task) put the tenant into a sustained throttle on 2026-08-05 - every filtered signIns query, even
`$top=5`, returned 429 - which blanked all three sources for a morning.

So the window now lives on disk (`signin_store`) and a cycle fetches only what arrived since the last
one. See `signin_store` for the late-arrival overlap, which is the part that would silently lose
sign-ins if it were done naively.

Contract
--------
- `invalidate()` is called once by `registry.collect_all()` before the sources run. It re-fetches only
  if the last successful pull has aged past the refresh interval - which is shorter when the store is
  warm, because a delta is cheap enough to run every cycle.
- `get_interactive()` is safe to call concurrently: the first caller performs the fetch while the
  others wait on the same lock and then read the cached result. Callers that want a shorter window
  filter the returned list themselves - re-fetching a subset would defeat the point.
- **The returned list is shared. Do not mutate it** (no sort in place, no element edits). Every
  current caller only reads, or builds its own filtered list.
- A failed fetch falls back to the stored window rather than raising, up to `STALE_MAX_MIN`, and marks
  it stale via `stale_info()`. Before this, sharing the pull also shared its failures: one throttled
  request took out three whole tabs, twice in a row, and an earlier version of this docstring wrote
  that coupling off as "acceptable". It was not - the consolidation had quietly turned a one-source
  outage into a three-tab one. Because the store is on disk, the fallback now also survives a restart,
  which is what was missing on 2026-08-05: by the time the fix was in, the morning's failures had
  already overwritten the last good values and there was nothing left to fall back to.
"""
import asyncio
import os
from datetime import datetime, timedelta, timezone

from . import signin_store
from .graph_client import graph_get

# The union of what the callers asked for. If any source ever needs more, raise it HERE rather than
# adding a second pull - and remember the cap is a bound on records, not on days.
WINDOW_DAYS = 7
MAX_RECORDS = 8000

# Page size, and it is not a free knob: signIns rejects a single request that costs too many resource
# units, independently of how much budget is left. Measured 2026-08-05, back to back, same filter,
# same minute:
#
#     $top=1000  ->  429   (62.8 s to be told so)
#     $top=500   ->  429   (62.8 s)
#     $top=250   ->  200   ( 8.8 s, 250 records)
#
# So 250 is not a throttle workaround, it is under the per-request ceiling while 500 is over it. This
# is also the missing half of the morning's diagnosis: PAGE_SIZE had been raised 500 -> 1000 the day
# before, which put every page of the shared pull over the line - and because the rejection took 62 s
# to arrive while the client timeout was 60 s, it surfaced as `ReadTimeout` and looked like a slow
# tenant rather than a request that was simply too big.
#
# Cost of the smaller page: ~10 requests for a cold 7-day pull instead of ~3 (~1.5 min total at the
# measured 9 s/page). A delta is one page either way, so the steady-state cost is unchanged.
PAGE_SIZE = int(os.environ.get("SIGNIN_PAGE_SIZE", "250"))

# Pause between pages of a multi-page pull. See _page_from for why this exists rather than a bigger
# page or more retries. Deltas are one page, so this is paid only by backfill.
PAGE_DELAY_SEC = float(os.environ.get("SIGNIN_PAGE_DELAY_SEC", "15"))

# Pages per cycle while backfilling. The budget refills slowly, so one cycle should take a bite and
# stop rather than push until it is rejected - being rejected costs ~62 s of wall clock and teaches us
# nothing. Six pages (1,500 records) is a bite that fits comfortably.
MAX_PAGES_PER_CYCLE = int(os.environ.get("SIGNIN_MAX_PAGES_PER_CYCLE", "6"))


# Backoff after attempts that achieve nothing.
#
# Measured 2026-08-05: coverage stopped at 1,240 records for ~3 hours while every cycle spent one ~68 s
# attempt and got 429 - 3 of 3 attempts against this endpoint, i.e. 100%, even though it was 0.7% of all
# Graph attempts. Retrying every 20 minutes was not converging; it was consuming whatever budget had
# refilled and returning to zero, which is the same trap as discarding partial pages, one level up.
#
# The trigger is "banked nothing", not "raised an exception": a cycle that banks pages and THEN fails
# made progress and should keep its cadence. Only a completely fruitless attempt backs off. `_bank`
# resets the counter, so productive cycles never slow down.
BACKOFF_MAX_MIN = float(os.environ.get("SIGNIN_BACKOFF_MAX_MIN", "120"))


class SigninBackfillIncomplete(RuntimeError):
    """The stored window does not cover WINDOW_DAYS yet, so no source may read it.

    Raised INSTEAD of handing over a partial window. That gate is the point: sources compute
    "did this user ever produce a device claim in 7 days" and similar, so a store covering 2 days
    would answer `missing` for someone who claimed on day 5 - a confidently wrong answer, which is
    worse than an unavailable panel. The message carries progress so the failure is informative
    rather than just red.
    """

# How stale the fallback may get before we stop serving it. Three hours is long enough to ride out a
# throttle (Graph's ask is measured in seconds) or a restart, and short enough that nobody makes an
# enforcement decision on it. Past this the source goes unavailable and `pipeline._carry_forward`
# takes over with its own 6-hour cap, so degradation is: fresh -> stale records -> carried snapshot ->
# unavailable. Panels state the age at every step.
STALE_MAX_MIN = int(os.environ.get("SIGNIN_STALE_MAX_MIN", "180"))

# Minimum interval between real pulls. Two values, because the cost of a pull is not constant:
#   - COLD: no usable store, so the pull is the full 7-day window. Expensive; keep it rare.
#   - WARM: only the delta since the last pull, a small slice at the newest end. Cheap enough to run
#     every cycle, which is how incremental buys BETTER freshness than the hourly cap a full pull
#     needed while also costing less.
MIN_REFRESH_MIN = int(os.environ.get("SIGNIN_MIN_REFRESH_MIN", "60"))
INCREMENTAL_REFRESH_MIN = int(os.environ.get("SIGNIN_INCREMENTAL_REFRESH_MIN", "20"))

_lock = asyncio.Lock()
_cache: dict | None = None   # {"records": list, "truncated": bool} or {"error": Exception}

# In-memory mirror of the on-disk window, plus when we last successfully pulled. These survive
# invalidate() on purpose: they are both the fallback for a failed fetch and the base for a delta.
_stored: list = []
_stored_newest: datetime | None = None
_stored_oldest: datetime | None = None   # backfill frontier: how far back coverage reaches
_complete = False                        # has coverage reached WINDOW_DAYS?
_last_pull_at: datetime | None = None
_loaded = False

_serving_stale_at: datetime | None = None   # this cycle fell back after a FAILED fetch
_reused_at: datetime | None = None          # this cycle reused a still-fresh pull, by design
_last_mode: str | None = None               # "full" | "delta" | "backfill" - for logging/telemetry

_fruitless = 0                              # consecutive attempts that banked nothing
_next_attempt_at: datetime | None = None    # set while backing off


def _age_min(when: datetime | None) -> float:
    if when is None:
        return float("inf")
    return (datetime.now(timezone.utc) - when).total_seconds() / 60


def _ensure_loaded() -> None:
    """Read the store once per process, so a restart resumes instead of restarting the backfill."""
    global _stored, _stored_newest, _stored_oldest, _complete, _last_pull_at, _loaded
    if _loaded:
        return
    _loaded = True
    s = signin_store.load()
    if not s["records"]:
        return
    _stored = s["records"]
    _stored_newest = s["newest"] or signin_store.newest_of(_stored)
    _stored_oldest = s["oldest"] or signin_store.oldest_of(_stored)
    _complete = s["complete"]
    # `writtenAt`, not the newest record time - see signin_store.load().
    _last_pull_at = s["writtenAt"]


def coverage_info() -> dict:
    """How much of the window is actually held, for progress reporting.

    Loads the store if it has not been read yet: this is called by the Data Health endpoint, which can
    run before any collection has happened in this worker, and reporting 0 records for a store that
    holds a warm window would misread a resuming backfill as one that never started.
    """
    _ensure_loaded()
    target = WINDOW_DAYS * 24 * 60
    if _stored_oldest is None:
        held = 0.0
    else:
        held = max(0.0, (datetime.now(timezone.utc) - _stored_oldest).total_seconds() / 60)
    return {"complete": _complete, "records": len(_stored),
            "heldDays": round(min(held, target) / 1440, 2), "targetDays": WINDOW_DAYS,
            "percent": round(min(held / target, 1.0) * 100) if target else 100,
            # Backoff state, so a paused backfill is visibly paused rather than looking dead.
            "fruitlessAttempts": _fruitless,
            "nextAttemptAt": _next_attempt_at.isoformat() if _next_attempt_at else None,
            "nextAttemptInMin": (round((_next_attempt_at - datetime.now(timezone.utc))
                                       .total_seconds() / 60, 1)
                                 if _next_attempt_at else None)}


def invalidate() -> None:
    """Start a new cycle: re-fetch only if the last successful pull has aged past the interval.

    The store and `_last_pull_at` are intentionally left alone - they are the delta base and the
    fallback. Only the per-cycle cache and the age markers are reset.
    """
    global _cache, _serving_stale_at, _reused_at
    _ensure_loaded()
    _serving_stale_at = None
    _reused_at = None

    # Backing off after fruitless attempts takes precedence over everything: another attempt inside the
    # window would just spend the budget that is being allowed to refill.
    if _next_attempt_at is not None and datetime.now(timezone.utc) < _next_attempt_at:
        wait = round((_next_attempt_at - datetime.now(timezone.utc)).total_seconds() / 60, 1)
        if _complete and _stored:
            _cache = {"records": _stored, "truncated": len(_stored) >= MAX_RECORDS}
            _serving_stale_at = _last_pull_at
        else:
            cov = coverage_info()
            _cache = {"error": SigninBackfillIncomplete(
                f"backing off for {wait} more min after {_fruitless} attempt(s) that fetched nothing "
                f"(Graph kept refusing). Coverage held at {cov['heldDays']} of {cov['targetDays']} days "
                f"({cov['percent']}%, {cov['records']} records); it resumes automatically.")}
        return

    # While backfilling, never skip a cycle: every cycle is another bite out of the remaining window,
    # and the refresh interval exists to avoid redundant work, not to slow down catching up.
    if not _complete:
        _cache = None
        return
    interval = INCREMENTAL_REFRESH_MIN if _stored else MIN_REFRESH_MIN
    if _stored and _age_min(_last_pull_at) < interval:
        # Pre-seed this cycle from the store, so no source triggers a fetch.
        _cache = {"records": _stored, "truncated": len(_stored) >= MAX_RECORDS}
        _reused_at = _last_pull_at
    else:
        _cache = None


def stale_info() -> dict:
    """How old this cycle's sign-in data is, and whether that age is a failure or by design.

    Sources include this in their output so a panel can say "sign-ins are 34 min old" instead of
    presenting stale numbers as current - the failure mode that matters most here is a confident
    number that is quietly out of date.

    `stale` is True only for the failure case (the fetch failed and the stored window was served
    instead). Planned reuse inside the refresh interval reports its age with `stale: False`, because
    flagging normal operation as a problem is how a warning becomes wallpaper.
    """
    if _serving_stale_at is not None:
        return {"stale": True, "ageMin": round(_age_min(_serving_stale_at), 1),
                "asOf": _serving_stale_at.isoformat(), "mode": "fallback"}
    if _reused_at is not None:
        return {"stale": False, "reused": True, "ageMin": round(_age_min(_reused_at), 1),
                "asOf": _reused_at.isoformat(), "mode": "reused"}
    return {"stale": False, "ageMin": 0.0, "mode": _last_mode or "full"}


def prewarm() -> None:
    """Start the shared pull immediately, without waiting for a source to ask for it.

    Sharing the pull removed two thirds of the sign-in page requests but also SERIALISED them: the
    first caller held the lock and paged on its own while the other two sources sat idle waiting,
    instead of doing their /devices and group lookups. Kicking the fetch off here puts it in flight
    before any source runs, so the heavy paging overlaps with everything else again.

    Fire-and-forget on purpose. The result (or the error) lands in the cache and every caller gets it
    from there; the done-callback consumes the exception so a failed pull does not surface as an
    "exception was never retrieved" warning on top of the real error each source already reports.
    """
    task = asyncio.ensure_future(get_interactive())
    task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)


def window_start() -> datetime:
    """Start of the cached window, so callers can filter to a shorter one consistently."""
    return datetime.now(timezone.utc) - timedelta(days=WINDOW_DAYS)


async def get_interactive() -> tuple[list, bool]:
    """Interactive sign-ins for the shared window. Returns (records, truncated).

    v1.0 `/auditLogs/signIns` returns interactive sign-ins only; non-interactive needs an explicit
    `signInEventTypes` filter and is fetched separately by the one source that wants it.
    """
    global _cache, _serving_stale_at
    async with _lock:
        _ensure_loaded()
        if _cache is None:
            try:
                records, truncated = await _fetch()
            except Exception as exc:  # noqa: BLE001 - one fetch, shared by three sources
                # A COMPLETE window may be served stale. An incomplete one may not be served at all,
                # so the error propagates and the three sources stay unavailable while it fills.
                if _complete and _stored and _age_min(_last_pull_at) <= STALE_MAX_MIN:
                    # Serve the stored window rather than blanking three tabs. The error still
                    # reaches the log via the caller-side warning; what changes is that the panels
                    # keep rendering, labelled with their true age.
                    _serving_stale_at = _last_pull_at
                    _cache = {"records": _stored, "truncated": len(_stored) >= MAX_RECORDS}
                else:
                    _cache = {"error": exc}
            else:
                _cache = {"records": records, "truncated": truncated}
        if "error" in _cache:
            raise _cache["error"]
        return _cache["records"], _cache["truncated"]


async def _fetch() -> tuple[list, bool]:
    """One bite: a delta if coverage is complete, otherwise the next chunk of backfill.

    Whatever pages come back are merged and persisted EVEN IF the fetch then failed. That is the
    difference between converging and not: on 2026-08-05 a 429 arrived for the nextLink after page 1
    had already succeeded, and the old code discarded that page along with the error. With a budget
    that refills slowly and a window needing ~10 pages, discarding partial progress means every cycle
    spends the refill and returns to zero - it can never finish, no matter how long you wait.
    """
    global _stored, _stored_newest, _stored_oldest, _complete, _last_pull_at, _last_mode
    floor = window_start()

    if _complete:
        start_at = signin_store.delta_start(_stored_newest, WINDOW_DAYS) or floor
        before = None
        _last_mode = "delta" if start_at > floor else "full"
    elif _stored_oldest is None:
        # Nothing held yet: start at the newest end and work backwards on later cycles.
        start_at, before = floor, None
        _last_mode = "backfill-start"
    else:
        # Extend backwards from the frontier.
        start_at, before = floor, signin_store.backfill_before(_stored_oldest)
        _last_mode = "backfill"

    # `sink` is owned HERE, not returned, precisely so that a mid-way failure still leaves the pages
    # already fetched visible to the `finally` below. Taking them from a return value would lose them
    # on exception - which is the exact behaviour this whole mechanism exists to remove.
    sink: list = []
    truncated = exhausted = False
    try:
        truncated, exhausted = await _page_from(start_at, before, sink)
    finally:
        if sink:
            _bank(sink, exhausted, floor)   # progress was made; this also clears any backoff
        else:
            _note_fruitless()               # nothing at all came back; slow down

    if not _complete:
        cov = coverage_info()
        raise SigninBackfillIncomplete(
            f"sign-in window is still backfilling: {cov['heldDays']} of {cov['targetDays']} days "
            f"({cov['percent']}%, {cov['records']} records). Continues next cycle; sources stay "
            f"unavailable until the window is whole, because a partial window produces confidently "
            f"wrong answers rather than missing ones.")
    return _stored, truncated or len(_stored) >= MAX_RECORDS


def _note_fruitless() -> None:
    """An attempt that returned no records at all: double the wait before the next one."""
    global _fruitless, _next_attempt_at
    _fruitless += 1
    wait = min(INCREMENTAL_REFRESH_MIN * (2 ** (_fruitless - 1)), BACKOFF_MAX_MIN)
    _next_attempt_at = datetime.now(timezone.utc) + timedelta(minutes=wait)


def _bank(fetched: list, exhausted: bool, floor: datetime) -> None:
    """Merge and persist what arrived, then recompute the coverage frontier.

    The frontier is the oldest end of the **contiguous run that reaches `newest`** - not simply the
    oldest record held. That distinction is the whole safety property: signIns pages newest-first, so
    a fetch that stops at the page cap leaves a GAP between the slice it just got and whatever the
    store already held further back. Using the store's global oldest as the frontier would then claim
    coverage across that hole and hand sources a window with a gap in the middle - which is the
    confidently-wrong-answer failure this design exists to prevent.

    Records below the frontier are kept (they are valid, and they dedupe by id when backfill reaches
    them); they just do not count as coverage yet.
    """
    global _stored, _stored_newest, _stored_oldest, _complete, _last_pull_at
    global _fruitless, _next_attempt_at
    # Pages arrived, so the current cadence is working: clear the backoff rather than slowing a cycle
    # that is making progress. Only wholly fruitless attempts are throttled back.
    _fruitless = 0
    _next_attempt_at = None
    merged = signin_store.merge(_stored, fetched, WINDOW_DAYS)
    _stored = merged
    _stored_newest = signin_store.newest_of(merged)
    _last_pull_at = datetime.now(timezone.utc)

    if exhausted:
        # Graph had nothing older to give: the run reaches as far back as retention allows, so the
        # whole store is one contiguous window and coverage is done.
        _stored_oldest = signin_store.oldest_of(merged)
        _complete = True
    else:
        _stored_oldest = signin_store.oldest_of(fetched)
        # A few minutes of slack: the floor moves as time passes, so requiring an exact reach would
        # leave coverage flapping between complete and not on every cycle.
        _complete = (_stored_oldest is not None
                     and _stored_oldest <= floor + timedelta(minutes=5))

    try:
        signin_store.save(merged, _stored_newest, _stored_oldest, _complete)
    except OSError:
        # A store we cannot persist costs the next process its progress; it must not fail this cycle,
        # which already holds the data in memory.
        pass


async def _page_from(start_at: datetime, before: datetime | None,
                     records: list) -> tuple[bool, bool]:
    """Page the window [start_at, before), appending into `records`. Returns (truncated, exhausted).

    Records are appended to a list the CALLER owns rather than returned, so that when this raises
    part-way the caller still has the pages that did arrive. `exhausted` means Graph offered no
    nextLink - nothing older exists, so coverage is as complete as retention allows.
    """
    flt = f"createdDateTime ge {start_at.strftime('%Y-%m-%dT%H:%M:%SZ')}"
    if before is not None:
        flt += f" and createdDateTime lt {before.strftime('%Y-%m-%dT%H:%M:%SZ')}"
    params = {"$filter": flt, "$top": PAGE_SIZE}
    truncated = False
    pages = 0
    data = await graph_get("/auditLogs/signIns", params=params)
    while True:
        records.extend(data.get("value", []))
        pages += 1
        if len(records) >= MAX_RECORDS:
            truncated = True
            break
        nxt = data.get("@odata.nextLink")
        if not nxt:
            return truncated, True
        if pages >= MAX_PAGES_PER_CYCLE:
            # Stop while we are ahead. Pushing until rejected costs ~62 s and banks nothing extra.
            break
        # Pace the paging. Reducing PAGE_SIZE to 250 got the FIRST page through, but a later page was
        # still rejected - and the 429 came back for the nextLink URL, not the initial request. Both
        # shapes tried on 2026-08-05 moved roughly the same total (3 x 1000 and 10 x 250 are both
        # ~2,500 records), which points at a budget accumulated over a short window rather than a
        # per-request ceiling. A pause between pages is the only thing that helps that, and it costs
        # nothing where it matters: a warm delta is a single page, so this loop does not run at all.
        # Only backfill pays it.
        if PAGE_DELAY_SEC:
            await asyncio.sleep(PAGE_DELAY_SEC)
        # nextLink is absolute and already carries the filter - do not re-send params
        data = await graph_get(nxt)
    return truncated, False
