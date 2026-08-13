"""Shared Microsoft Graph client.

Acquires a token via app-only (client credentials) auth and calls Graph.
Phase 1 is read-only, so write helpers (POST/PATCH/DELETE) are deliberately absent.
"""
import asyncio
import os
import time

import httpx
import msal

from . import graph_stats
from .config import settings

GRAPH_BASE = "https://graph.microsoft.com/v1.0"
AUTHORITY = f"https://login.microsoftonline.com/{settings.tenant_id}"
SCOPE = ["https://graph.microsoft.com/.default"]

# Global concurrency cap across all Graph calls (avoids throttling). NOTE: this is process-wide, so a
# source with its own internal semaphore is still bounded by THIS number - an inner limit higher than
# 6 buys nothing.
_SEM = asyncio.Semaphore(6)

# Per-request read timeout. This number matters more than it looks.
#
# When /auditLogs/signIns is throttled, Graph does NOT reject quickly: it holds the request for ~62 s
# and then answers 429 with `Retry-After: 30`. At the old 60 s timeout that reply never arrived, one
# second short, and the consequences compounded:
#   - the failure surfaced as "ReadTimeout (no message)", which reads as a slow tenant, so the
#     morning of 2026-08-05 was spent looking at page sizes instead of at a throttle
#   - the 429 branch below never ran, so `Retry-After` was never honoured
#   - each request was instead retried 3x after 2 s / 4 s - which is precisely what keeps a throttle
#     alive. Three sources x three pages x three retries is up to 27 requests per collect, per
#     process, all of them counted against the budget we were already over.
# Measured 2026-08-05: four out of four filtered signIns queries returned 429 at 61.8-62.2 s
# (independent of $top, even $top=5), while an unfiltered query returned 200 in 5.8 s. 120 s leaves
# room for the rejection to land so the backoff below can do its job.
GET_TIMEOUT_SEC = int(os.environ.get("GRAPH_GET_TIMEOUT_SEC", "120"))

# Upper bound on how long we will honour a Retry-After. Graph asked for 30 s in the 2026-08-05
# throttle; the previous `min(wait, 10)` slept a third of what was asked and walked straight into the
# next 429. Sleeping LESS than Graph asks is worse than not retrying at all.
MAX_RETRY_AFTER_SEC = int(os.environ.get("GRAPH_MAX_RETRY_AFTER_SEC", "45"))


class GraphThrottled(RuntimeError):
    """Graph returned 429 after our retries were exhausted.

    A distinct type because the remedy is the opposite of a timeout's: collect less often and make
    fewer requests, rather than waiting longer per request. Reported by name in the source's
    `reason`, so a throttle is never again read as a slow network.
    """

_app = msal.ConfidentialClientApplication(
    client_id=settings.client_id,
    client_credential=settings.client_secret,
    authority=AUTHORITY,
)


def _get_token() -> str:
    # MSAL caches and refreshes the token internally.
    result = _app.acquire_token_silent(SCOPE, account=None)
    if not result:
        result = _app.acquire_token_for_client(scopes=SCOPE)
    if "access_token" not in result:
        raise RuntimeError(
            f"Token acquisition failed: {result.get('error_description', result)}"
        )
    return result["access_token"]


async def check_connectivity() -> bool:
    """Check whether Graph is reachable, using token acquisition as the probe.

    Filters out the state right after boot/resume where the network is not up yet.
    Acquiring a token requires actually reaching login.microsoftonline.com, which makes
    it a reliable proxy for network readiness. _get_token is blocking (msal), so it runs
    in a thread.
    """
    try:
        await asyncio.to_thread(_get_token)
        return True
    except Exception:  # noqa: BLE001 - if we cannot connect, treat anything as a failure
        return False


async def graph_get(path: str, params: dict | None = None) -> dict:
    """Graph GET. If path is an absolute URL (e.g. @odata.nextLink) it is used as-is."""
    url = path if path.startswith("http") else f"{GRAPH_BASE}{path}"
    async with _SEM:
        async with httpx.AsyncClient(timeout=GET_TIMEOUT_SEC) as client:
            last_timeout: Exception | None = None
            for attempt in range(3):
                headers = {"Authorization": f"Bearer {_get_token()}"}
                # Every ATTEMPT is timed and counted, not just the final outcome: the retry
                # amplification that sustained the 2026-08-05 throttle was invisible precisely
                # because only outcomes were ever reported. See graph_stats.
                t0 = time.monotonic()
                try:
                    resp = await client.get(url, headers=headers, params=params)
                except httpx.TimeoutException as exc:
                    graph_stats.record(url, type(exc).__name__, time.monotonic() - t0, attempt)
                    # A slow response is transient, and heavy endpoints (auditLogs/signIns paging)
                    # genuinely exceed the timeout when the tenant is being throttled. Previously a
                    # single timeout killed the whole source for that cycle - that is what produced
                    # the 18/20 collect on 2026-08-04 with an empty error message.
                    last_timeout = exc
                    if attempt < 2:
                        await asyncio.sleep(2 * (attempt + 1))
                        continue
                    raise
                graph_stats.record(url, resp.status_code, time.monotonic() - t0, attempt)
                if resp.status_code == 429:
                    # Do NOT retry a throttle inside the same collection. Measured 2026-08-05: a
                    # throttled signIns query does not fail fast - Graph holds it ~62 s and then
                    # answers 429. Three attempts therefore cost ~190 s of wall clock, add three more
                    # requests to a budget we are already over, and on a sustained throttle (which is
                    # what this was: 429 for every filtered query, at every page size, for over
                    # 20 minutes) fail anyway. The collection loop runs again in 20 minutes; that is
                    # the retry, and it is a far better one than hammering now.
                    break
                if resp.status_code in (500, 502, 503, 504) and attempt < 2:
                    # Transient server error: back off and retry. Honour Retry-After as given - a
                    # shorter sleep than asked for is what turns one throttle into a sustained one.
                    default = 2 * (attempt + 1)
                    try:
                        wait = int(resp.headers.get("Retry-After", default))
                    except (TypeError, ValueError):
                        wait = default
                    await asyncio.sleep(min(max(wait, 1), MAX_RETRY_AFTER_SEC))
                    continue
                break
            else:  # pragma: no cover - loop always breaks or raises
                if last_timeout:
                    raise last_timeout
    if resp.status_code == 403:
        # Permission not consented, or gated by licensing
        raise PermissionError(path)
    if resp.status_code == 429:
        # Name it, and pass on what Graph asked for. The wording matters: this used to surface as
        # "ReadTimeout (no message)", which points at the network and sent a morning's diagnosis in
        # the wrong direction.
        raise GraphThrottled(
            f"Graph throttled {path.split('?')[0]} (Retry-After: "
            f"{resp.headers.get('Retry-After', 'not set')}s). Not retried in this cycle on purpose - "
            f"collection is making too many requests, not running too slowly."
        )
    resp.raise_for_status()
    return resp.json()


async def graph_post(path: str, body: dict) -> dict:
    """Graph POST - for read-only queries only (e.g. Advanced Hunting runHuntingQuery).

    Restricted to calls that read without changing state, keeping Phase 1 read-only.
    """
    url = path if path.startswith("http") else f"{GRAPH_BASE}{path}"
    async with _SEM:
        async with httpx.AsyncClient(timeout=60) as client:
            for attempt in range(3):
                headers = {"Authorization": f"Bearer {_get_token()}", "Content-Type": "application/json"}
                resp = await client.post(url, headers=headers, json=body)
                if resp.status_code in (429, 500, 502, 503, 504) and attempt < 2:
                    wait = int(resp.headers.get("Retry-After", str(2 * (attempt + 1))))
                    await asyncio.sleep(min(wait, 10))
                    continue
                break
    if resp.status_code == 403:
        raise PermissionError(path)
    resp.raise_for_status()
    return resp.json()
