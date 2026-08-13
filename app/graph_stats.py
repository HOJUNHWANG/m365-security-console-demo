"""Lightweight counters for what the Graph client is actually experiencing.

Why this exists
---------------
On 2026-08-05 three sources were down for most of a day and the first several hours went into
answering questions that a counter would have answered instantly:

  - is this a timeout or a throttle?      (it was a 429 arriving after our timeout had expired)
  - how many requests are we even making? (~540/h at the worst, from retry amplification)
  - is it still the same failure?         (it changed from 429 to a Microsoft 500 mid-afternoon,
                                           and nothing on the page would have shown that)

None of that was visible. The dashboard reported per-source `available`, and the reason string was
whatever exception happened to surface. So these counters exist to make the collection layer itself
observable, and they feed the Data Health tab.

Deliberately in-process and unpersisted: this is "what has this worker seen since it started", which
is the right frame for diagnosing a live problem. Persistent facts (window coverage, last successful
pull) live in signin_store instead. A restart resets these, and the tab says so.

Paths are normalised before use as keys - GUIDs collapse to {id} and query strings are dropped. That
keeps the key space bounded, and it also means no user, group or device identifier is echoed into the
page.
"""
import re
import time
from collections import Counter
from datetime import datetime, timezone

MAX_ERRORS = 12
MAX_SLOW = 8

_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_LONG = re.compile(r"[A-Za-z0-9_-]{24,}")   # skiptokens, deltatokens, opaque ids
# SharePoint/OneDrive composite ids: "b!Rrz1K49NLUSzSp_686yXuOgqH9pe…" for a drive, and the
# "host,siteGuid,webGuid" form for a site. The first pass missed drive ids because `!` and `,` are not
# in the _LONG character class, so each user's OneDrive became its own key - unbounded, and a
# per-person identifier printed on a web page. Both problems, one fix.
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
    """Endpoint key: no query string, no identifiers.

    A nextLink is a full absolute URL carrying $skiptoken, so without this every page of every pull
    would become its own key - and the token would be printed on a web page.
    """
    p = (path or "").split("?")[0]
    p = p.replace("https://graph.microsoft.com/v1.0", "").replace(
        "https://graph.microsoft.com/beta", "beta:")
    p = _SITEID.sub("{site}", p)
    p = _DRIVE.sub("{drive}", p)
    p = _GUID.sub("{id}", p)
    p = "/".join(seg if not _LONG.match(seg) else "{token}" for seg in p.split("/"))
    return p or "/"


def record(path: str, status, seconds: float, retried: int = 0) -> None:
    """One completed attempt. `status` is an HTTP code, or a string like 'timeout' for no response."""
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
    # Slowest calls, because "the endpoint got 7x slower" was a real signal today and nothing showed
    # it. Kept sorted and truncated so this stays a fixed-size list.
    _slow.append({"endpoint": key, "seconds": round(seconds, 1), "status": str(status)})
    _slow.sort(key=lambda x: -x["seconds"])
    del _slow[MAX_SLOW:]


def snapshot() -> dict:
    up_min = (datetime.now(timezone.utc) - _started).total_seconds() / 60
    per_hour = round(_requests / (up_min / 60), 1) if up_min > 1 else None
    # Busiest, PLUS every endpoint that has errors even if it is nowhere near the busiest. Ranking by
    # volume alone hid the only endpoint that was failing: /auditLogs/signIns made 3 attempts against
    # ~400 SharePoint reads, so it fell off a top-12-by-volume list while failing 100% of the time.
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
                       # Per-endpoint failure rate. The tenant-wide rate is the wrong denominator when
                       # one endpoint is failing outright: 3/417 reads as 0.7%, 3/3 reads as 100%.
                       "errRate": round(v["err"] / v["n"] * 100) if v["n"] else 0,
                       "avgSec": round(v["sec"] / v["n"], 1) if v["n"] else 0,
                       "maxSec": round(v["max"], 1)} for k, v in busiest],
        # The endpoint hurting most, by failure rate rather than volume - for the headline.
        "worstEndpoint": max(
            ({"endpoint": k, "n": v["n"], "errors": v["err"],
              "errRate": round(v["err"] / v["n"] * 100)} for k, v in _by_endpoint.items()
             if v["err"]), key=lambda e: (e["errRate"], e["errors"]), default=None),
        "recentErrors": list(reversed(_errors)),
        "slowest": list(_slow),
    }


class Timer:
    """Times one attempt and records it, whatever the outcome."""

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
