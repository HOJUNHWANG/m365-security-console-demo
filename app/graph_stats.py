import re
import time
from collections import Counter
from datetime import datetime, timezone

MAX_ERRORS = 12
MAX_SLOW = 8

_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_LONG = re.compile(r"[A-Za-z0-9_-]{24,}")
_DRIVE = re.compile(r"\b[a-zA-Z]![A-Za-z0-9_\-!.]{20,}")
_SITEID = re.compile(r"[A-Za-z0-9.-]+\.sharepoint\.com,[0-9a-fA-F-]{36},[0-9a-fA-F-]{36}")

_started = datetime.now(timezone.utc)
_requests = 0
_retries = 0
_by_status: Counter = Counter()
_by_endpoint: dict[str, dict] = {}
_errors: list[dict] = []
_slow: list[dict] = []


def normalise(path: str) -> str:
    p = (path or "").split("?")[0]
    p = p.replace("https://graph.microsoft.com/v1.0", "").replace(
        "https://graph.microsoft.com/beta", "beta:")
    p = _SITEID.sub("{site}", p)
    p = _DRIVE.sub("{drive}", p)
    p = _GUID.sub("{id}", p)
    p = "/".join(seg if not _LONG.match(seg) else "{token}" for seg in p.split("/"))
    return p or "/"


def record(path: str, status, seconds: float, retried: int = 0) -> None:
    global _requests, _retries
    key = normalise(path)
    _requests += 1
    _retries += retried
    _by_status[str(status)] += 1
    e = _by_endpoint.setdefault(key, {"n": 0, "err": 0, "sec": 0.0, "max": 0.0})
    e["n"] += 1
    e["sec"] += seconds
    e["max"] = max(e["max"], seconds)
    ok = isinstance(status, int) and 200 <= status < 300
    if not ok:
        e["err"] += 1
        _errors.append({"at": datetime.now(timezone.utc).isoformat(), "endpoint": key,
                        "status": str(status), "seconds": round(seconds, 1)})
        del _errors[:-MAX_ERRORS]
    _slow.append({"endpoint": key, "seconds": round(seconds, 1), "status": str(status)})
    _slow.sort(key=lambda x: -x["seconds"])
    del _slow[MAX_SLOW:]


def snapshot() -> dict:
    up_min = (datetime.now(timezone.utc) - _started).total_seconds() / 60
    per_hour = round(_requests / (up_min / 60), 1) if up_min > 1 else None
    busiest = sorted(_by_endpoint.items(), key=lambda kv: -kv[1]["n"])[:12]
    failing = [kv for kv in _by_endpoint.items() if kv[1]["err"] and kv not in busiest]
    busiest = busiest + sorted(failing, key=lambda kv: -kv[1]["err"])
    return {
        "since": _started.isoformat(),
        "upMinutes": round(up_min, 1),
        "requests": _requests,
        "retries": _retries,
        "requestsPerHour": per_hour,
        "byStatus": dict(sorted(_by_status.items())),
        "throttled": _by_status.get("429", 0),
        "serverErrors": sum(v for k, v in _by_status.items() if k in ("500", "502", "503", "504")),
        "timeouts": sum(v for k, v in _by_status.items() if not k.isdigit()),
        "endpoints": [{"endpoint": k, "n": v["n"], "errors": v["err"],
                       "errRate": round(v["err"] / v["n"] * 100) if v["n"] else 0,
                       "avgSec": round(v["sec"] / v["n"], 1) if v["n"] else 0,
                       "maxSec": round(v["max"], 1)} for k, v in busiest],
        "worstEndpoint": max(
            ({"endpoint": k, "n": v["n"], "errors": v["err"],
              "errRate": round(v["err"] / v["n"] * 100)} for k, v in _by_endpoint.items()
             if v["err"]), key=lambda e: (e["errRate"], e["errors"]), default=None),
        "recentErrors": list(reversed(_errors)),
        "slowest": list(_slow),
    }


class Timer:
    def __init__(self, path):
        self.path = path
        self.status = "unknown"
        self.retried = 0

    def __enter__(self):
        self._t0 = time.monotonic()
        return self

    def __exit__(self, exc_type, exc, tb):
        if self.status == "unknown" and exc_type is not None:
            self.status = exc_type.__name__
        record(self.path, self.status, time.monotonic() - self._t0, self.retried)
        return False
