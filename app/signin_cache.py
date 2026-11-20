import asyncio
import os
from datetime import datetime, timedelta, timezone

from . import signin_store
from .graph_client import graph_get

WINDOW_DAYS = 7
MAX_RECORDS = 8000

PAGE_SIZE = int(os.environ.get("SIGNIN_PAGE_SIZE", "250"))

PAGE_DELAY_SEC = float(os.environ.get("SIGNIN_PAGE_DELAY_SEC", "15"))

MAX_PAGES_PER_CYCLE = int(os.environ.get("SIGNIN_MAX_PAGES_PER_CYCLE", "6"))


BACKOFF_MAX_MIN = float(os.environ.get("SIGNIN_BACKOFF_MAX_MIN", "120"))


class SigninBackfillIncomplete(RuntimeError):
    pass

STALE_MAX_MIN = int(os.environ.get("SIGNIN_STALE_MAX_MIN", "180"))

MIN_REFRESH_MIN = int(os.environ.get("SIGNIN_MIN_REFRESH_MIN", "60"))
INCREMENTAL_REFRESH_MIN = int(os.environ.get("SIGNIN_INCREMENTAL_REFRESH_MIN", "20"))

_lock = asyncio.Lock()
_cache: dict | None = None

_stored: list = []
_stored_newest: datetime | None = None
_stored_oldest: datetime | None = None
_complete = False
_last_pull_at: datetime | None = None
_loaded = False

_serving_stale_at: datetime | None = None
_reused_at: datetime | None = None
_last_mode: str | None = None

_fruitless = 0
_next_attempt_at: datetime | None = None


def _age_min(when: datetime | None) -> float:
    if when is None:
        return float("inf")
    return (datetime.now(timezone.utc) - when).total_seconds() / 60


def _ensure_loaded() -> None:
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
    _last_pull_at = s["writtenAt"]


def coverage_info() -> dict:
    _ensure_loaded()
    target = WINDOW_DAYS * 24 * 60
    if _stored_oldest is None:
        held = 0.0
    else:
        held = max(0.0, (datetime.now(timezone.utc) - _stored_oldest).total_seconds() / 60)
    return {"complete": _complete, "records": len(_stored),
            "heldDays": round(min(held, target) / 1440, 2), "targetDays": WINDOW_DAYS,
            "percent": round(min(held / target, 1.0) * 100) if target else 100,
            "fruitlessAttempts": _fruitless,
            "nextAttemptAt": _next_attempt_at.isoformat() if _next_attempt_at else None,
            "nextAttemptInMin": (round((_next_attempt_at - datetime.now(timezone.utc))
                                       .total_seconds() / 60, 1)
                                 if _next_attempt_at else None)}


def invalidate() -> None:
    global _cache, _serving_stale_at, _reused_at
    _ensure_loaded()
    _serving_stale_at = None
    _reused_at = None

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

    if not _complete:
        _cache = None
        return
    interval = INCREMENTAL_REFRESH_MIN if _stored else MIN_REFRESH_MIN
    if _stored and _age_min(_last_pull_at) < interval:
        _cache = {"records": _stored, "truncated": len(_stored) >= MAX_RECORDS}
        _reused_at = _last_pull_at
    else:
        _cache = None


def stale_info() -> dict:
    if _serving_stale_at is not None:
        return {"stale": True, "ageMin": round(_age_min(_serving_stale_at), 1),
                "asOf": _serving_stale_at.isoformat(), "mode": "fallback"}
    if _reused_at is not None:
        return {"stale": False, "reused": True, "ageMin": round(_age_min(_reused_at), 1),
                "asOf": _reused_at.isoformat(), "mode": "reused"}
    return {"stale": False, "ageMin": 0.0, "mode": _last_mode or "full"}


def prewarm() -> None:
    task = asyncio.ensure_future(get_interactive())
    task.add_done_callback(lambda t: t.exception() if not t.cancelled() else None)


def window_start() -> datetime:
    return datetime.now(timezone.utc) - timedelta(days=WINDOW_DAYS)


async def get_interactive() -> tuple[list, bool]:
    global _cache, _serving_stale_at
    async with _lock:
        _ensure_loaded()
        if _cache is None:
            try:
                records, truncated = await _fetch()
            except Exception as exc:
                if _complete and _stored and _age_min(_last_pull_at) <= STALE_MAX_MIN:
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
    global _stored, _stored_newest, _stored_oldest, _complete, _last_pull_at, _last_mode
    floor = window_start()

    if _complete:
        start_at = signin_store.delta_start(_stored_newest, WINDOW_DAYS) or floor
        before = None
        _last_mode = "delta" if start_at > floor else "full"
    elif _stored_oldest is None:
        start_at, before = floor, None
        _last_mode = "backfill-start"
    else:
        start_at, before = floor, signin_store.backfill_before(_stored_oldest)
        _last_mode = "backfill"

    sink: list = []
    truncated = exhausted = False
    try:
        truncated, exhausted = await _page_from(start_at, before, sink)
    finally:
        if sink:
            _bank(sink, exhausted, floor)
        else:
            _note_fruitless()

    if not _complete:
        cov = coverage_info()
        raise SigninBackfillIncomplete(
            f"sign-in window is still backfilling: {cov['heldDays']} of {cov['targetDays']} days "
            f"({cov['percent']}%, {cov['records']} records). Continues next cycle; sources stay "
            f"unavailable until the window is whole, because a partial window produces confidently "
            f"wrong answers rather than missing ones.")
    return _stored, truncated or len(_stored) >= MAX_RECORDS


def _note_fruitless() -> None:
    global _fruitless, _next_attempt_at
    _fruitless += 1
    wait = min(INCREMENTAL_REFRESH_MIN * (2 ** (_fruitless - 1)), BACKOFF_MAX_MIN)
    _next_attempt_at = datetime.now(timezone.utc) + timedelta(minutes=wait)


def _bank(fetched: list, exhausted: bool, floor: datetime) -> None:
    global _stored, _stored_newest, _stored_oldest, _complete, _last_pull_at
    global _fruitless, _next_attempt_at
    _fruitless = 0
    _next_attempt_at = None
    merged = signin_store.merge(_stored, fetched, WINDOW_DAYS)
    _stored = merged
    _stored_newest = signin_store.newest_of(merged)
    _last_pull_at = datetime.now(timezone.utc)

    if exhausted:
        _stored_oldest = signin_store.oldest_of(merged)
        _complete = True
    else:
        _stored_oldest = signin_store.oldest_of(fetched)
        _complete = (_stored_oldest is not None
                     and _stored_oldest <= floor + timedelta(minutes=5))

    try:
        signin_store.save(merged, _stored_newest, _stored_oldest, _complete)
    except OSError:
        pass


async def _page_from(start_at: datetime, before: datetime | None,
                     records: list) -> tuple[bool, bool]:
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
            break
        if PAGE_DELAY_SEC:
            await asyncio.sleep(PAGE_DELAY_SEC)
        data = await graph_get(nxt)
    return truncated, False
