"""Snapshot cache plus a history of headline metrics (for trend sparklines)."""
import json
from datetime import datetime, timezone
from pathlib import Path

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
SNAPSHOT = DATA_DIR / "graph_snapshot.json"
HISTORY = DATA_DIR / "graph_history.json"
HISTORY_MAX = 2000  # ~90 days at a 20-min cadence during business hours (~22 runs/day)


def _read(path):
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8-sig"))
    except Exception:
        return None


def read_snapshot():
    return _read(SNAPSHOT)


def snapshot_age_minutes():
    """Age of the cached snapshot in minutes, or None if there is no readable snapshot.

    Lets the in-process collection loop skip a cycle when something else already refreshed - the
    backstop scheduled task, or a manual "Collect now" - so the two paths do not both collect a
    minute apart. Reads the recorded _collectedAt rather than the file mtime, because the file is
    also rewritten when nothing was collected (Graph unreachable preserves the previous snapshot).
    """
    snap = _read(SNAPSHOT) or {}
    ts = snap.get("_collectedAt")
    if not ts:
        return None
    try:
        when = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - when).total_seconds() / 60


def write_snapshot(data: dict) -> dict:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    payload = dict(data)
    payload["_collectedAt"] = datetime.now(timezone.utc).isoformat()
    SNAPSHOT.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    return payload


def read_history() -> list:
    return _read(HISTORY) or []


def append_history(data: dict) -> dict:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    hist = read_history()

    def m(key):
        v = data.get(key, {}) or {}
        return v if v.get("available") else {}

    ss, mfa, al = m("secureScore"), m("mfaStatus"), m("securityAlerts")
    inc, adm, acc = m("securityIncidents"), m("adminAccounts"), m("accountSummary")
    rec = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "secureScorePct": round(ss["current"] / ss["max"] * 100, 1)
        if ss.get("max") else None,
        "mfaPercent": mfa.get("percent"),
        "activeAlerts": al.get("count"),
        "activeIncidents": inc.get("activeCount"),
        "globalAdmins": adm.get("globalAdminCount"),
        "guestsPending": acc.get("guestsPending"),
    }
    hist.append(rec)
    hist = hist[-HISTORY_MAX:]
    HISTORY.write_text(json.dumps(hist, ensure_ascii=False), encoding="utf-8")
    return rec
