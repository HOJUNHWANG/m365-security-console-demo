from datetime import date, datetime, timedelta
from pathlib import Path
import json

from ..graph_client import graph_get

RECORD = Path(__file__).resolve().parents[2] / "data" / "ca-exceptions.json"
EXPIRING_SOON_DAYS = 7

AUTO_EXPIRY_REASON = (
    "Entra does not enforce these dates. Membership expiry and access reviews need Entra ID "
    "Governance / P2, and on a P1-only tenant (e.g. Business Premium) an exception stays in place "
    "until a person removes it. The date below is a note, not a mechanism."
)


def _parse_day(s):
    try:
        return datetime.strptime((s or "")[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def _load_record():
    if not RECORD.exists():
        return {}, {}, False, None
    try:
        rec = json.loads(RECORD.read_text(encoding="utf-8"))
    except Exception as exc:
        return {}, {}, True, f"{type(exc).__name__}: {str(exc)[:120]}"
    timed = {(e.get("upn") or "").lower(): e for e in rec.get("exceptions", []) if e.get("upn")}
    perm = {(e.get("upn") or "").lower(): e for e in rec.get("permanent", []) if e.get("upn")}
    return timed, perm, True, None


async def _safe(path, params=None):
    try:
        return await graph_get(path, params=params)
    except Exception as exc:
        return {"_error": str(exc)[:120]}


async def fetch() -> dict:
    pols = (await graph_get("/identity/conditionalAccess/policies"))["value"]

    timed, perm, rec_exists, rec_error = _load_record()
    today = date.today()
    soon = today + timedelta(days=EXPIRING_SOON_DAYS)

    seen_users = {}

    async def upn_of(uid):
        if uid not in seen_users:
            u = await _safe(f"/users/{uid}", {"$select": "userPrincipalName"})
            seen_users[uid] = (u.get("userPrincipalName") or f"{uid[:8]}… (deleted account?)").lower()
        return seen_users[uid]

    overdue, undocumented, expiring, ok_rows = [], [], [], []
    in_tenant = set()
    policies_with_exclusions = []

    def classify(upn, where, source):
        in_tenant.add(upn)
        if upn in perm:
            ok_rows.append({"upn": upn, "policy": where, "via": source,
                            "note": "approved permanent: " + (perm[upn].get("reason") or ""),
                            "permanent": True})
            return
        e = timed.get(upn)
        if not e:
            undocumented.append({"upn": upn, "policy": where, "via": source})
            return
        exp = _parse_day(e.get("expires"))
        row = {"upn": upn, "policy": where, "via": source,
               "expires": e.get("expires"), "reason": e.get("reason") or "",
               "device": e.get("device") or "", "granted": e.get("granted") or "",
               "approvedBy": e.get("approvedBy") or ""}
        if exp is None:
            undocumented.append({**row, "policy": where + "  [expires missing or malformed]"})
        elif exp < today:
            overdue.append({**row, "daysOver": (today - exp).days})
        elif exp <= soon:
            expiring.append({**row, "daysLeft": (exp - today).days})
        else:
            ok_rows.append({**row, "note": f"until {exp}", "permanent": False})

    for p in sorted(pols, key=lambda x: x.get("displayName") or ""):
        name = p.get("displayName") or "(unnamed)"
        us = (p.get("conditions") or {}).get("users") or {}
        eu = us.get("excludeUsers") or []
        eg = us.get("excludeGroups") or []
        if not eu and not eg:
            continue
        policies_with_exclusions.append(
            {"policy": name, "state": p.get("state"), "users": len(eu), "groups": len(eg)})
        for uid in eu:
            classify(await upn_of(uid), name, "user")
        for gid in eg:
            g = await _safe(f"/groups/{gid}", {"$select": "displayName"})
            gn = g.get("displayName") or gid[:8]
            members = await _safe(f"/groups/{gid}/members", {"$select": "userPrincipalName"})
            if "_error" in members:
                undocumented.append({"upn": f"(group {gn} members unreadable)", "policy": name,
                                     "via": "group", "error": members["_error"]})
                continue
            for m in members.get("value", []):
                upn = (m.get("userPrincipalName") or "").lower()
                if upn:
                    classify(upn, f"{name}/{gn}", "group")

    stale = [{"upn": u, "expires": (timed[u].get("expires") or ""),
              "reason": timed[u].get("reason") or ""}
             for u in sorted(timed) if u not in in_tenant]

    def people(rows):
        return sorted({r["upn"] for r in rows})

    overdue_people = people(overdue)
    undoc_people = people(undocumented)
    action_needed = len(overdue_people) + len(undoc_people)

    return {
        "available": True,
        "recordExists": rec_exists,
        "recordError": rec_error,
        "recordPath": "data/ca-exceptions.json",
        "today": today.isoformat(),
        "expiringSoonDays": EXPIRING_SOON_DAYS,

        "autoExpires": False,
        "autoExpiryReason": AUTO_EXPIRY_REASON,

        "overdue": sorted(overdue, key=lambda r: -r.get("daysOver", 0)),
        "undocumented": undocumented,
        "expiring": sorted(expiring, key=lambda r: r.get("daysLeft", 0)),
        "stale": stale,
        "ok": ok_rows,

        "overdueCount": len(overdue_people),
        "undocumentedCount": len(undoc_people),
        "expiringCount": len(people(expiring)),
        "staleCount": len(stale),
        "permanentCount": len({r["upn"] for r in ok_rows if r.get("permanent")}),
        "actionNeeded": action_needed,

        "policies": policies_with_exclusions,
        "policyCount": len(policies_with_exclusions),
        "revokeCommand": (
            "pwsh -File .\\scripts\\ca-cutover\\Grant-CaTempException.ps1 "
            "-Upn <upn> -Revoke -Apply"),
    }
