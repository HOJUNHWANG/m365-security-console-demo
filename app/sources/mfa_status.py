from collections import Counter

from ..graph_client import graph_get

MFA_TRUSTED_HOMES = {"hd.com"}


def is_guest(u: dict) -> bool:
    t = (u.get("userType") or "").lower()
    if t:
        return t == "guest"
    return "#EXT#" in (u.get("userPrincipalName") or "")


def home_domain(upn: str) -> str:
    if "#EXT#" not in (upn or ""):
        return "?"
    left = upn.split("#EXT#")[0]
    return left.rsplit("_", 1)[-1].lower() if "_" in left else "?"


def summarize(users: list) -> dict:
    members = [u for u in users if not is_guest(u)]
    guests = [u for u in users if is_guest(u)]
    total = len(members)
    mfa = sum(1 for u in members if u.get("isMfaRegistered"))
    not_registered = [u.get("userPrincipalName") for u in members if not u.get("isMfaRegistered")]
    g_missing = [u for u in guests if not u.get("isMfaRegistered")]
    by_home = Counter(home_domain(u.get("userPrincipalName")) for u in g_missing)
    return {
        "available": True,
        "scope": "members",
        "total": total,
        "mfaRegistered": mfa,
        "percent": round(mfa / total * 100, 1) if total else 0,
        "notRegistered": not_registered[:25],
        "guestsTotal": len(guests),
        "guestsNotRegistered": len(g_missing),
        "guestsNotRegisteredByHome": dict(by_home.most_common()),
        "guestsNotRegisteredUntrusted": sum(n for d, n in by_home.items() if d not in MFA_TRUSTED_HOMES),
        "mfaTrustedHomes": sorted(MFA_TRUSTED_HOMES),
    }


async def fetch() -> dict:
    data = await graph_get(
        "/reports/authenticationMethods/userRegistrationDetails",
        {"$top": 999},
    )
    return summarize(data.get("value", []))
