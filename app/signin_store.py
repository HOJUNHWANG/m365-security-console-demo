"""On-disk rolling window of interactive sign-ins, so collection can be incremental.

Why
---
Sign-in logs are append-only history, but the collector was treating them as live state to be
re-read in full: the whole 7-day window, every 20 minutes, from two processes. A 20-minute step
against a 7-day window is 0.2% new data, so ~99.8% of every pull was records we already had. On
2026-08-05 that spend put the tenant into a sustained throttle on `/auditLogs/signIns` - every
filtered query, even `$top=5`, came back 429 - and took out the three sources that share the pull for
a whole morning.

With a local window, a cycle fetches only what arrived since the last one (~tens of records instead
of ~2,460) and merges it in. Two consequences beyond the load saving:

  - the 7-day window is available even while Graph is refusing us, so a throttle no longer empties
    Device Identity, Browser Claims and Risky Sign-ins
  - because a delta is cheap, sign-ins can refresh MORE often than the hourly cap a full pull needed

Late arrivals
-------------
Entra sign-in logs are not immediately consistent: a record can surface after records with a later
`createdDateTime` have already been returned. Fetching strictly "newer than the newest I have" would
drop those permanently - the failure would be silent and would look like the sign-in never happened,
which for this dashboard is the worst possible shape of bug. So a delta always re-reads an overlap
before the high-water mark and merges by record id.

The file lives in data/ (gitignored) alongside the snapshot, and holds tenant PII - UPNs, IP
addresses - exactly like graph_snapshot.json, under the same protections.
"""
import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"
STORE = DATA_DIR / "signin_window.json"

# How far before the high-water mark a delta re-reads, to catch late-arriving records. One hour is
# generous against observed ingestion lag (minutes) and costs almost nothing: it is a small slice at
# the newest end of the window, and duplicates are dropped by id.
OVERLAP_MIN = int(os.environ.get("SIGNIN_OVERLAP_MIN", "60"))


def _parse(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        when = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except (TypeError, ValueError):
        return None
    return when if when.tzinfo else when.replace(tzinfo=timezone.utc)


def _key(rec: dict) -> str:
    """Dedupe key. `id` is unique per sign-in; the composite is a fallback for a record without one,
    which should not happen but must not collapse unrelated sign-ins into each other if it does."""
    rid = rec.get("id")
    if rid:
        return str(rid)
    return "|".join(str(rec.get(f) or "") for f in
                    ("createdDateTime", "userId", "appDisplayName", "ipAddress", "correlationId"))


def load() -> dict:
    """The whole store in one read: records plus the three timestamps and the coverage flag.

    One read because the store can be several MB - parsing it again just to pull a timestamp out of
    the header would be a real cost, not a stylistic one.

      newest    - high-water mark, where a delta starts from
      oldest    - how far BACK coverage actually reaches (backfill frontier)
      writtenAt - when we last successfully pulled. NOT the newest record time: a quiet tenant can
                  leave the newest record hours behind a successful pull, and using that to measure
                  staleness overstates it and forces needless full pulls.
      complete  - has coverage reached the full window? Consumers are gated on this.

    A store that cannot be read is treated as absent rather than fatal: the caller starts a fresh
    backfill, which is slower but correct.
    """
    empty = {"records": [], "newest": None, "oldest": None, "writtenAt": None, "complete": False}
    try:
        raw = json.loads(STORE.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return empty
    records = raw.get("records") if isinstance(raw, dict) else None
    if not isinstance(records, list):
        return empty
    return {"records": records,
            "newest": _parse(raw.get("newest")),
            "oldest": _parse(raw.get("oldest")),
            "writtenAt": _parse(raw.get("writtenAt")),
            "complete": bool(raw.get("complete"))}


def merge(stored: list, fetched: list, window_days: int) -> list:
    """Combine stored and freshly fetched records, newest first, pruned to the window.

    Fetched records win over stored ones with the same id, so a record that was re-read in the
    overlap is refreshed rather than duplicated.
    """
    by_key = {_key(r): r for r in stored}
    by_key.update({_key(r): r for r in fetched})
    cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
    kept = [r for r in by_key.values() if (_parse(r.get("createdDateTime")) or cutoff) >= cutoff]
    # Newest first, matching what Graph returns, so callers that assume ordering keep working.
    kept.sort(key=lambda r: r.get("createdDateTime") or "", reverse=True)
    return kept


def delta_start(newest: datetime | None, window_days: int) -> datetime | None:
    """Where a delta fetch should start, or None if a full window pull is needed.

    Returns None when there is no high-water mark, or when it is old enough that the "delta" would
    span most of the window anyway - at that point a plain full pull is simpler and no more
    expensive.
    """
    if newest is None:
        return None
    floor = datetime.now(timezone.utc) - timedelta(days=window_days)
    start = newest - timedelta(minutes=OVERLAP_MIN)
    return start if start > floor else None


def backfill_before(oldest: datetime | None) -> datetime | None:
    """Upper bound for the next backfill chunk: everything older than what we already hold.

    A small overlap on THIS end too, for the same reason as the newest end - a record sitting exactly
    on the boundary would otherwise be skipped by a strict `lt`, and one skipped record is invisible.
    Duplicates are dropped by id, so overlapping is free.
    """
    if oldest is None:
        return None
    return oldest + timedelta(minutes=1)


def save(records: list, newest: datetime | None, oldest: datetime | None = None,
         complete: bool = False) -> None:
    """Write the store atomically.

    A partially written store would be read back as corrupt on the next start and silently downgrade
    every cycle to a full pull - the exact load this file exists to avoid - so the write goes to a
    temp file in the same directory and is then replaced.

    Called even when a pull FAILED part-way: keeping the pages already won is the whole point of
    incremental backfill. Discarding them is what made the 2026-08-05 outage unable to converge.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    payload = {
        "newest": newest.isoformat() if newest else None,
        "oldest": oldest.isoformat() if oldest else None,
        "complete": complete,
        "count": len(records),
        "writtenAt": datetime.now(timezone.utc).isoformat(),
        "records": records,
    }
    fd, tmp = tempfile.mkstemp(dir=str(DATA_DIR), prefix=".signin_window.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False)
        os.replace(tmp, STORE)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def newest_of(records: list) -> datetime | None:
    return max((d for d in (_parse(r.get("createdDateTime")) for r in records) if d), default=None)


def oldest_of(records: list) -> datetime | None:
    return min((d for d in (_parse(r.get("createdDateTime")) for r in records) if d), default=None)
