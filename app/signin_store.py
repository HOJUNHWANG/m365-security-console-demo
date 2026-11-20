import json
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"
STORE = DATA_DIR / "signin_window.json"

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
    rid = rec.get("id")
    if rid:
        return str(rid)
    return "|".join(str(rec.get(f) or "") for f in
                    ("createdDateTime", "userId", "appDisplayName", "ipAddress", "correlationId"))


def load() -> dict:
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
    by_key = {_key(r): r for r in stored}
    by_key.update({_key(r): r for r in fetched})
    cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)
    kept = [r for r in by_key.values() if (_parse(r.get("createdDateTime")) or cutoff) >= cutoff]
    kept.sort(key=lambda r: r.get("createdDateTime") or "", reverse=True)
    return kept


def delta_start(newest: datetime | None, window_days: int) -> datetime | None:
    if newest is None:
        return None
    floor = datetime.now(timezone.utc) - timedelta(days=window_days)
    start = newest - timedelta(minutes=OVERLAP_MIN)
    return start if start > floor else None


def backfill_before(oldest: datetime | None) -> datetime | None:
    if oldest is None:
        return None
    return oldest + timedelta(minutes=1)


def save(records: list, newest: datetime | None, oldest: datetime | None = None,
         complete: bool = False) -> None:
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
