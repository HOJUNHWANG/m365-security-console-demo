"""Mail security (Exchange / EOP) - reads the snapshot produced by exo_collector.ps1.

Running PowerShell per request would be far too slow, so a separate collector writes
data/exo_snapshot.json; this source reads it and reports its freshness (age since collection).
"""
import json
from datetime import datetime, timezone
from pathlib import Path

SNAPSHOT = Path(__file__).resolve().parent.parent.parent / "data" / "exo_snapshot.json"

# Scheduled EXO collection times (local, business hours). Keep in sync with the daily triggers
# (plus one at startup) of the "MS365 Dashboard - EXO Collect" Windows scheduled task.
# The admin leaves at 17:00, so there are no evening or overnight runs.
EXO_COLLECT_TIMES = ["10:00", "13:00", "16:00"]
# Staleness warning threshold (hours). Generous enough that the normal overnight gap
# (16:00 to 10:00 the next day, ~18h) does not trigger a false alarm.
EXO_STALE_HOURS = 20


async def fetch() -> dict:
    if not SNAPSHOT.exists():
        return {
            "available": False,
            "reason": "No EXO snapshot found. Run scripts/exo_collector.ps1 first.",
        }
    try:
        data = json.loads(SNAPSHOT.read_text(encoding="utf-8-sig"))
    except Exception as e:  # noqa: BLE001
        return {"available": False, "reason": f"Failed to read snapshot: {e}"}

    age_h = None
    stale = False
    collected = data.get("collectedAt")
    if collected:
        try:
            dt = datetime.fromisoformat(collected.replace("Z", "+00:00"))
            age_h = round((datetime.now(timezone.utc) - dt).total_seconds() / 3600, 1)
            stale = age_h > EXO_STALE_HOURS
        except ValueError:
            pass

    data["available"] = True
    data["ageHours"] = age_h
    data["stale"] = stale
    data["collectTimes"] = EXO_COLLECT_TIMES
    return data


def read_allowlist() -> dict | None:
    """Read the auto-synced allowlist from the EXO snapshot. Returns None if absent."""
    if not SNAPSHOT.exists():
        return None
    try:
        data = json.loads(SNAPSHOT.read_text(encoding="utf-8-sig"))
    except Exception:  # noqa: BLE001
        return None
    return data.get("allowlist")
