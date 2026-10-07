from datetime import datetime, timedelta, timezone

from ..graph_client import graph_get

DORMANT_DAYS = 90
GUEST_LIST_MAX = 200


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


async def _all_users() -> list:
    params = {
        "$select": "id,displayName,userPrincipalName,mail,userType,accountEnabled,"
                   "externalUserState,externalUserStateChangeDateTime,createdDateTime,"
                   "signInActivity",
        "$top": 999,
    }
    out = []
    data = await graph_get("/users", params=params)
    while True:
        out.extend(data.get("value", []))
        nxt = data.get("@odata.nextLink")
        if not nxt:
            break
        data = await graph_get(nxt)
    return out


def _last_activity(u: dict) -> str | None:
    sa = u.get("signInActivity") or {}
    stamps = [sa.get("lastSignInDateTime"),
              sa.get("lastNonInteractiveSignInDateTime"),
              sa.get("lastSuccessfulSignInDateTime")]
    stamps = [s for s in stamps if s]
    return max(stamps) if stamps else None


async def fetch() -> dict:
    users = await _all_users()
    now = datetime.now(timezone.utc)
    dormant_before = _iso(now - timedelta(days=DORMANT_DAYS))

    total = len(users)
    enabled = sum(1 for u in users if u.get("accountEnabled"))
    guests_raw = [u for u in users if u.get("userType") == "Guest"]

    guests = []
    for u in guests_raw:
        state = u.get("externalUserState") or "Unknown"
        pending = state == "PendingAcceptance"
        last = _last_activity(u)
        dormant = (not pending) and (last is None or last < dormant_before)
        days_idle = None
        if last:
            try:
                days_idle = (now - datetime.fromisoformat(last.replace("Z", "+00:00"))).days
            except ValueError:
                days_idle = None
        guests.append({
            "name": u.get("displayName") or "",
            "upn": u.get("userPrincipalName") or "",
            "mail": u.get("mail") or "",
            "state": state,
            "enabled": bool(u.get("accountEnabled")),
            "invited": u.get("createdDateTime"),
            "lastActivity": last,
            "daysIdle": days_idle,
            "neverSignedIn": last is None,
            "dormant": dormant,
            "pending": pending,
        })

    guests.sort(key=lambda g: (not g["pending"] and not g["dormant"],
                               not g["neverSignedIn"],
                               -(g["daysIdle"] or 0)))

    guests_pending = sum(1 for g in guests if g["pending"])
    guests_dormant = sum(1 for g in guests if g["dormant"])
    guests_never = sum(1 for g in guests if g["neverSignedIn"] and not g["pending"])

    return {
        "available": True,
        "total": total,
        "enabled": enabled,
        "disabled": total - enabled,
        "guests": len(guests),
        "guestsPending": guests_pending,
        "guestsDormant": guests_dormant,
        "guestsNeverSignedIn": guests_never,
        "guestsActive": len(guests) - guests_pending - guests_dormant,
        "guestsDisabled": sum(1 for g in guests if not g["enabled"]),
        "members": total - len(guests),
        "dormantDays": DORMANT_DAYS,
        "guestList": guests[:GUEST_LIST_MAX],
        "guestListTruncated": len(guests) > GUEST_LIST_MAX,
    }
