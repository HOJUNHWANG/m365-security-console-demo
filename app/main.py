import asyncio
import contextlib
import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import cache, edit_guard, graph_stats, pipeline, signin_cache
from .sources import exchange_eop, impersonation_watch, intune_devices

log = logging.getLogger("uvicorn.error")

_APP_DIR = Path(__file__).resolve().parent
_PROCESS_START = time.time()
STALE_CODE_TTL_SEC = 15
RESTART_CMD = ("Stop-ScheduledTask 'MS365 Dashboard - Web'; "
               "Start-ScheduledTask 'MS365 Dashboard - Web'")
_stale_code_cache: tuple = (0.0, None)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _code_stale() -> dict:
    global _stale_code_cache
    now = time.time()
    if _stale_code_cache[1] is not None and now - _stale_code_cache[0] < STALE_CODE_TTL_SEC:
        return _stale_code_cache[1]
    newer = []
    for p in _APP_DIR.rglob("*.py"):
        try:
            m = p.stat().st_mtime
        except OSError:
            continue
        if m > _PROCESS_START:
            newer.append((m, p.relative_to(_APP_DIR.parent).as_posix()))
    newer.sort(reverse=True)
    info = {
        "stale": bool(newer),
        "processStarted": _iso(_PROCESS_START),
        "newestFile": newer[0][1] if newer else None,
        "newestChangedAt": _iso(newer[0][0]) if newer else None,
        "staleCount": len(newer),
        "staleFiles": [f for _, f in newer[:8]],
        "restartCmd": RESTART_CMD,
    }
    _stale_code_cache = (now, info)
    return info


COLLECT_INTERVAL_MIN = int(os.environ.get("COLLECT_INTERVAL_MIN", "20"))
COLLECT_STARTUP_DELAY_SEC = int(os.environ.get("COLLECT_STARTUP_DELAY_SEC", "60"))

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
    if _ACTIVE_HOURS is None:
        return True
    hour = (when or datetime.now()).hour
    start, end = _ACTIVE_HOURS
    return start <= hour < end if start < end else (hour >= start or hour < end)


def _backfilling() -> bool:
    try:
        return not signin_cache.coverage_info().get("complete")
    except Exception:
        return False

COLLECT_SKIP_IF_YOUNGER_MIN = max(1.0, COLLECT_INTERVAL_MIN / 2)

_collect_lock = asyncio.Lock()

_collect_state: dict = {"trigger": None, "startedAt": None, "pending": False}
_bg_tasks: set = set()


_recent_cycles: list[dict] = []
MAX_CYCLES = 24


async def _collect_once(reason: str) -> dict:
    async with _collect_lock:
        _collect_state.update(trigger=reason, startedAt=datetime.now(timezone.utc).isoformat())
        try:
            return await _collect_once_locked(reason)
        finally:
            _collect_state.update(trigger=None, startedAt=None)


async def _collect_once_locked(reason: str) -> dict:
    started = time.monotonic()
    snap = await pipeline.refresh()
    if snap.get("_collectFailed"):
        log.warning("collect (%s) SKIPPED - Graph unreachable; kept %s",
                    reason, snap.get("_collectedAt"))
        return snap
    keys = [k for k, v in snap.items() if isinstance(v, dict) and not k.startswith("_")]
    down = [k for k in keys if not snap[k].get("available")]
    carried = [k for k in keys if snap[k].get("available") and snap[k].get("carried")]
    fresh = len(keys) - len(down) - len(carried)
    parts = []
    if carried:
        parts.append("CARRIED (stale, last good value): " + ", ".join(
            f"{k} ({snap[k]['carried'].get('ageMin')} min old"
            f" - {snap[k]['carried'].get('reason') or 'no reason'})" for k in carried))
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
        log.warning(summary_line + " | %s", *args, " | ".join(parts))
    else:
        log.info(summary_line, *args)
    return snap


async def _collect_loop() -> None:
    await asyncio.sleep(COLLECT_STARTUP_DELAY_SEC)
    while True:
        try:
            age = cache.snapshot_age_minutes() if hasattr(cache, "snapshot_age_minutes") else None
            if not _within_window() and not _backfilling():
                log.info("collect (loop) skipped - outside the collection window (%s local)",
                         COLLECT_ACTIVE_HOURS)
            elif age is not None and age < COLLECT_SKIP_IF_YOUNGER_MIN:
                log.info("collect (loop) skipped - snapshot is only %.1f min old (< %.1f)",
                         age, COLLECT_SKIP_IF_YOUNGER_MIN)
            else:
                if not _within_window():
                    log.info("collect (loop) running outside the window (%s local) - the sign-in "
                             "window is still backfilling and stopping would restart the wait",
                             COLLECT_ACTIVE_HOURS)
                sc = _code_stale()
                if sc["stale"]:
                    log.warning("collect (loop) STALE CODE - %s changed at %s, after this process "
                                "started at %s (%d file(s)). The snapshot about to be written comes "
                                "from the OLD module. Fix: %s",
                                sc["newestFile"], sc["newestChangedAt"], sc["processStarted"],
                                sc["staleCount"], sc["restartCmd"])
                await _collect_once("loop")
        except asyncio.CancelledError:
            raise
        except Exception:
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
            "bytes": len(json.dumps(v, ensure_ascii=False, default=str)),
        })
    sources.sort(key=lambda s: ({"down": 0, "carried": 1, "fresh": 2}[s["state"]], -s["bytes"]))

    return {
        "sources": sources,
        "code": _code_stale(),
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
    return _data_health(cache.read_snapshot() or {})


@app.get("/api/summary")
async def summary(live: bool = False):
    if live:
        snap = await _collect_once("live")
    else:
        snap = cache.read_snapshot()
        if snap is None:
            async with _collect_lock:
                snap = await pipeline.refresh()
    out = dict(snap)
    if not live:
        try:
            out["exchangeEop"] = await exchange_eop.fetch()
        except Exception:
            pass
    try:
        out["intuneDevices"] = intune_devices.apply_manual_keys(out.get("intuneDevices"),
                                                                intune_devices.load_manual_keys())
    except Exception:
        pass
    out["_history"] = cache.read_history()
    out["_dataHealth"] = _data_health(out)
    return out


COLLECT_HEADER = "X-Dashboard-Collect"


def collect_status_payload() -> dict:
    snap = cache.read_snapshot() or {}
    last = _recent_cycles[-1] if _recent_cycles else None
    return {"running": _collect_lock.locked() or bool(_collect_state.get("pending")),
            "trigger": _collect_state.get("trigger") or ("manual" if _collect_state.get("pending") else None),
            "startedAt": _collect_state.get("startedAt"),
            "collectedAt": snap.get("_collectedAt"), "last": last}


@app.post("/api/collect")
async def collect_now(request: Request):
    if request.headers.get(COLLECT_HEADER) != "1":
        return JSONResponse({"status": "refused", "reason": f"missing {COLLECT_HEADER} header"}, status_code=400)
    if _collect_lock.locked() or _collect_state.get("pending"):
        return {"status": "running", **collect_status_payload()}
    _collect_state["pending"] = True

    async def _run():
        try:
            await _collect_once("manual")
        except Exception:
            log.exception("collect (manual) failed")
        finally:
            _collect_state["pending"] = False

    t = asyncio.create_task(_run())
    _bg_tasks.add(t)
    t.add_done_callback(_bg_tasks.discard)
    return {"status": "started", **collect_status_payload()}


@app.get("/api/collect-status")
async def collect_status():
    return collect_status_payload()


@app.get("/api/edit-status")
async def edit_status(request: Request):
    client = request.client.host if request.client else ""
    return {"canEdit": edit_guard.is_local(dict(request.headers), client)}


async def _lookalike_write(request: Request, action: str):
    client = request.client.host if request.client else ""
    ok, why = edit_guard.check_write(dict(request.headers), client)
    try:
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict):
        body = {}
    domain = str(body.get("domain") or "")[:253]
    if not ok:
        impersonation_watch.audit(action, domain, f"denied:{why}", "remote" if why == "remote" else "local",
                                  {"client": client, "host": request.headers.get("host", "")[:100]})
        log.warning("lookalike %s denied (%s) for %r", action, why, domain)
        return JSONResponse({"ok": False, "code": why,
                             "ko": "이 기록은 대시보드 PC 에서 직접 연 화면(http://127.0.0.1:8000)에서만 할 수 있습니다.",
                             "en": "Recording is only possible from the dashboard PC itself (http://127.0.0.1:8000)."},
                            status_code=403)
    reason = str(body.get("reason") or "")
    by = str(body.get("by") or "").strip() or "dashboard"
    if action == "record":
        eop = await exchange_eop.fetch()
        imp = eop.get("impersonation") or {}
        allowed = [x["domain"] for x in imp.get("suspects") or [] if x.get("level") != "blocked"]
        allowed += [x["domain"] for x in imp.get("newDomains") or [] if x.get("level") not in ("blocked", "confirmed")]
        own = (eop.get("allowlist") or {}).get("ownDomains") or []
        res = impersonation_watch.record_intent(domain, reason, by, own=own, allowed=allowed)
    else:
        res = impersonation_watch.remove_intent(domain)
    impersonation_watch.audit(action, domain, res["code"], "local",
                              {"reason": reason[:300], "by": by[:80]} if action == "record" else None)
    log.info("lookalike %s %r -> %s", action, domain, res["code"])
    return JSONResponse(res, status_code=200 if res["ok"] else 400)


@app.post("/api/lookalike/record")
async def lookalike_record(request: Request):
    return await _lookalike_write(request, "record")


@app.post("/api/lookalike/remove")
async def lookalike_remove(request: Request):
    return await _lookalike_write(request, "remove")


@app.get("/")
async def index():
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/favicon.svg", include_in_schema=False)
async def favicon():
    return FileResponse(STATIC_DIR / "favicon.svg")


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
