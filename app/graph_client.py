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

_SEM = asyncio.Semaphore(6)

GET_TIMEOUT_SEC = int(os.environ.get("GRAPH_GET_TIMEOUT_SEC", "120"))

MAX_RETRY_AFTER_SEC = int(os.environ.get("GRAPH_MAX_RETRY_AFTER_SEC", "45"))


class GraphThrottled(RuntimeError):
    pass

_app = msal.ConfidentialClientApplication(
    client_id=settings.client_id,
    client_credential=settings.client_secret,
    authority=AUTHORITY,
)


def _get_token() -> str:
    result = _app.acquire_token_silent(SCOPE, account=None)
    if not result:
        result = _app.acquire_token_for_client(scopes=SCOPE)
    if "access_token" not in result:
        raise RuntimeError(
            f"Token acquisition failed: {result.get('error_description', result)}"
        )
    return result["access_token"]


async def check_connectivity() -> bool:
    try:
        await asyncio.to_thread(_get_token)
        return True
    except Exception:
        return False


async def graph_get(path: str, params: dict | None = None) -> dict:
    url = path if path.startswith("http") else f"{GRAPH_BASE}{path}"
    async with _SEM:
        async with httpx.AsyncClient(timeout=GET_TIMEOUT_SEC) as client:
            last_timeout: Exception | None = None
            for attempt in range(3):
                headers = {"Authorization": f"Bearer {_get_token()}"}
                t0 = time.monotonic()
                try:
                    resp = await client.get(url, headers=headers, params=params)
                except httpx.TimeoutException as exc:
                    graph_stats.record(url, type(exc).__name__, time.monotonic() - t0, attempt)
                    last_timeout = exc
                    if attempt < 2:
                        await asyncio.sleep(2 * (attempt + 1))
                        continue
                    raise
                graph_stats.record(url, resp.status_code, time.monotonic() - t0, attempt)
                if resp.status_code == 429:
                    break
                if resp.status_code in (500, 502, 503, 504) and attempt < 2:
                    default = 2 * (attempt + 1)
                    try:
                        wait = int(resp.headers.get("Retry-After", default))
                    except (TypeError, ValueError):
                        wait = default
                    await asyncio.sleep(min(max(wait, 1), MAX_RETRY_AFTER_SEC))
                    continue
                break
            else:
                if last_timeout:
                    raise last_timeout
    if resp.status_code == 403:
        raise PermissionError(path)
    if resp.status_code == 429:
        raise GraphThrottled(
            f"Graph throttled {path.split('?')[0]} (Retry-After: "
            f"{resp.headers.get('Retry-After', 'not set')}s). Not retried in this cycle on purpose - "
            f"collection is making too many requests, not running too slowly."
        )
    resp.raise_for_status()
    return resp.json()


async def graph_post(path: str, body: dict) -> dict:
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
