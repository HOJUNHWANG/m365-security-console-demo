from datetime import datetime, timezone

from ..config import settings
from ..graph_client import graph_post
from . import exchange_eop

WARN = 0.80
HIGH = 0.95
ROWS = 15


def _kql_list(items) -> str:
    return ", ".join("'" + str(x).replace("'", "") + "'" for x in sorted(items))


def build_query(own_domains) -> str:
    return f"""
let own = dynamic([{_kql_list(own_domains)}]);
let base = EmailEvents
| where Timestamp > ago(30d)
| where EmailDirection in ("Outbound", "Intra-org")
| where tolower(SenderFromDomain) in (own)
| project Timestamp, S = tolower(SenderFromAddress), Ext = EmailDirection == "Outbound";
let daily = base
| summarize R = count() by S, Day = bin(Timestamp - 5h, 1d)
| summarize arg_max(R, Day), ActiveDays = count() by S
| project S, Max30 = R, Max30Day = Day, ActiveDays;
let recent = base
| where Timestamp > ago(24h)
| summarize Last24h = count(), Ext24h = countif(Ext), Last1h = countif(Timestamp > ago(1h)) by S2 = S;
let hourly = base
| where Timestamp > ago(24h) and Ext
| summarize H = count() by S3 = S, bin(Timestamp, 1h)
| summarize ExtPeak1h = max(H) by S3;
daily
| join kind=leftouter recent on $left.S == $right.S2
| join kind=leftouter hourly on $left.S == $right.S3
| project S, Max30, Max30Day, ActiveDays, Last24h = coalesce(Last24h, 0), Ext24h = coalesce(Ext24h, 0),
          Last1h = coalesce(Last1h, 0), ExtPeak1h = coalesce(ExtPeak1h, 0)
| where Last24h >= 100 or Max30 >= 200
| top 60 by Last24h desc
"""


def resolve_limits(ol: dict | None):
    if not ol:
        return None, [], []
    pols = {p.get("name"): p for p in ol.get("policies") or []}
    default = next((p for p in pols.values() if p.get("isDefault")), None)
    rules, group_rules = [], []
    for r in sorted(ol.get("rules") or [], key=lambda r: r.get("priority", 0)):
        if (r.get("state") or "").lower() != "enabled":
            continue
        pol = pols.get(r.get("policy"))
        if not pol:
            continue
        def _vals(key):
            return {str(x).strip().lower() for x in r.get(key) or [] if str(x or "").strip()}
        if _vals("fromMemberOf"):
            group_rules.append(r.get("name"))
        rules.append({"from": _vals("from"), "domains": _vals("senderDomainIs"), "policy": pol})
    return default, rules, group_rules


def limit_for(addr: str, default, rules) -> dict | None:
    a = (addr or "").lower()
    dom = a.rpartition("@")[2]
    for r in rules:
        if a in r["from"] or dom in r["domains"]:
            return r["policy"]
    return default


def _pct(n, lim):
    return round(n / lim, 3) if lim else None


def level_of(row: dict) -> str:
    if row.get("blocked"):
        return "blocked"
    worst = max(x for x in (row.get("pct24") or 0, row.get("extPct1h") or 0))
    if worst >= HIGH:
        return "high"
    if worst >= WARN:
        return "warn"
    if (row.get("max30Pct") or 0) >= WARN:
        return "history"
    return "ok"


def build(results: list[dict], ol: dict | None, now: datetime | None = None) -> dict:
    default, rules, group_rules = resolve_limits(ol)
    blocked = {b.get("address"): b for b in (ol or {}).get("blocked") or [] if b.get("address")}
    rows = []
    seen = set()
    for r in results:
        s = (r.get("S") or "").lower()
        if not s:
            continue
        seen.add(s)
        pol = limit_for(s, default, rules)
        per_day = (pol or {}).get("perDay") or None
        ext_h = (pol or {}).get("extPerHour") or None
        row = {
            "sender": s,
            "policy": (pol or {}).get("name"),
            "limit": per_day,
            "extPerHour": ext_h,
            "last24h": int(r.get("Last24h") or 0),
            "ext24h": int(r.get("Ext24h") or 0),
            "last1h": int(r.get("Last1h") or 0),
            "extPeak1h": int(r.get("ExtPeak1h") or 0),
            "max30": int(r.get("Max30") or 0),
            "max30Day": r.get("Max30Day"),
            "activeDays": int(r.get("ActiveDays") or 0),
            "blocked": s in blocked,
        }
        row["pct24"] = _pct(row["last24h"], per_day)
        row["extPct1h"] = _pct(row["extPeak1h"], ext_h)
        row["max30Pct"] = _pct(row["max30"], per_day)
        row["level"] = level_of(row)
        rows.append(row)
    for a, b in blocked.items():
        if a in seen:
            continue
        pol = limit_for(a, default, rules)
        rows.append({"sender": a, "policy": (pol or {}).get("name"), "limit": (pol or {}).get("perDay"),
                     "extPerHour": (pol or {}).get("extPerHour"), "last24h": 0, "ext24h": 0, "last1h": 0,
                     "extPeak1h": 0, "max30": 0, "max30Day": None, "activeDays": 0, "blocked": True,
                     "pct24": None, "extPct1h": None, "max30Pct": None, "level": "blocked"})
    order = {"blocked": 0, "high": 1, "warn": 2, "history": 3, "ok": 4}
    rows.sort(key=lambda x: (order[x["level"]], -(x["pct24"] or 0), -(x["max30Pct"] or 0)))
    counts = {k: sum(1 for x in rows if x["level"] == k) for k in ("blocked", "high", "warn", "history")}
    return {
        "available": True,
        "limitsKnown": default is not None,
        "policies": [{k: p.get(k) for k in ("name", "isDefault", "perDay", "extPerHour", "intPerHour", "action")}
                     for p in (ol or {}).get("policies") or []],
        "groupRulesUnresolved": group_rules,
        "warnPct": int(WARN * 100),
        "counts": counts,
        "rows": rows[:ROWS],
        "rowsTotal": len(rows),
        "blockedDetail": list(blocked.values()),
        "measuredAt": (now or datetime.now(timezone.utc)).isoformat(timespec="seconds"),
    }


def _snapshot_limits() -> dict | None:
    import json
    if not exchange_eop.SNAPSHOT.exists():
        return None
    try:
        data = json.loads(exchange_eop.SNAPSHOT.read_text(encoding="utf-8-sig"))
    except Exception:
        return None
    return data.get("outboundLimits")


def _own_domains() -> set[str]:
    al = exchange_eop.read_allowlist() or {}
    own = {str(x).strip().lower() for x in al.get("ownDomains") or [] if str(x).strip()}
    own |= {x.strip().lower() for x in (settings.hunt_own_domains or "").split(",") if x.strip()}
    return {d for d in own if not d.endswith(".onmicrosoft.com")}


async def fetch() -> dict:
    own = _own_domains()
    if not own:
        return {"available": False, "reason": "Own-domain list is empty (EXO snapshot allowlist.ownDomains / HUNT_OWN_DOMAINS)."}
    res = await graph_post("/security/runHuntingQuery", {"Query": build_query(own)})
    out = build(res.get("results", []), _snapshot_limits())
    if not out["limitsKnown"]:
        out["reason"] = "EXO snapshot has no outboundLimits yet - re-run scripts/exo_collector.ps1."
    return out
