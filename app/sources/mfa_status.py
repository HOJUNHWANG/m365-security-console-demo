"""MFA registration status - who has not registered for MFA, at a glance."""
from ..graph_client import graph_get


async def fetch() -> dict:
    data = await graph_get(
        "/reports/authenticationMethods/userRegistrationDetails",
        {"$top": 999},
    )
    users = data.get("value", [])
    total = len(users)
    mfa = sum(1 for u in users if u.get("isMfaRegistered"))
    not_registered = [
        u.get("userPrincipalName")
        for u in users
        if not u.get("isMfaRegistered")
    ]
    return {
        "available": True,
        "total": total,
        "mfaRegistered": mfa,
        "percent": round(mfa / total * 100, 1) if total else 0,
        "notRegistered": not_registered[:25],
    }
