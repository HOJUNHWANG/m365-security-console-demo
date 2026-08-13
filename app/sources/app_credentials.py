"""App credential expiry - client secrets and certificates on app registrations.

An expired secret means an outage; a long-lived forgotten one is a security risk.
Shows only credentials expiring within 60 days (or already expired), soonest first.
"""
from datetime import datetime, timezone

from ..graph_client import graph_get


def _parse(dt: str | None):
    if not dt:
        return None
    try:
        return datetime.fromisoformat(dt.replace("Z", "+00:00"))
    except ValueError:
        return None


async def fetch() -> dict:
    data = await graph_get("/applications", {
        "$select": "displayName,appId,passwordCredentials,keyCredentials",
        "$top": 999,
    })
    now = datetime.now(timezone.utc)
    items = []
    for app in data.get("value", []):
        name = app.get("displayName")
        creds = (
            [("secret", c) for c in app.get("passwordCredentials", [])]
            + [("cert", c) for c in app.get("keyCredentials", [])]
        )
        for kind, c in creds:
            end = _parse(c.get("endDateTime"))
            if not end:
                continue
            items.append({
                "app": name,
                "type": kind,
                "daysLeft": (end - now).days,
                "expires": (c.get("endDateTime") or "")[:10],
            })
    expiring = sorted([i for i in items if i["daysLeft"] <= 60], key=lambda i: i["daysLeft"])
    return {"available": True, "expiring": expiring[:20], "totalCreds": len(items)}
