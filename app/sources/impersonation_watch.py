from __future__ import annotations

import json
import re
from collections import Counter
from datetime import date, datetime, timedelta, timezone
from pathlib import Path

from ._i18n import finding

DATA = Path(__file__).resolve().parent.parent.parent / "data"
STATE = DATA / "mail_domains.json"
INTENT = DATA / "lookalike-intent.json"
AUDIT = DATA / "lookalike-intent.log"
AGE = DATA / "domain_age.json"

NEW_AGE_DAYS = 30
NEW_LOOKBACK_DAYS = 30

PUBLIC = {
    "gmail.com", "googlemail.com", "outlook.com", "hotmail.com", "live.com", "msn.com", "yahoo.com", "aol.com",
    "icloud.com", "me.com", "mac.com", "proton.me", "protonmail.com", "naver.com", "daum.net", "hanmail.net",
    "q.com", "sbcglobal.net", "comcast.net", "att.net", "verizon.net", "gmx.com", "wp.pl",
}
INFRA = {
    "microsoft.com", "office.com", "office365.com", "microsoftonline.com", "sharepoint.com", "onmicrosoft.com",
    "outlook.com", "google.com", "amazonses.com", "sendgrid.net", "mailchimp.com", "salesforce.com",
    "docusign.net", "docusign.com", "slack.com", "zoom.us",
}
SUFFIX2 = {
    "co.kr", "or.kr", "ne.kr", "go.kr", "ac.kr", "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "com.mx",
    "com.br", "com.cn", "com.tw", "com.vn", "com.ec", "com.sg", "com.my", "co.jp", "ne.jp", "or.jp", "co.in",
    "co.za", "com.tr", "com.ar", "com.co", "com.pe", "com.ph", "co.id", "co.nz", "us.com", "onmicrosoft.com",
}
SUFFIX3 = {"mail.onmicrosoft.com", "mail.protection.outlook.com"}
HOMO = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("5", "s"), ("4", "a"), ("7", "t"), ("i", "l")]

EST_OUT, EST_STAFF, EST_IN = 10, 2, 5
GENERIC_LP = {"info", "sales", "admin", "noreply", "no-reply", "support", "contact", "office", "accounts", "ap",
              "ar", "billing", "invoice", "invoices", "service", "hr", "news", "newsletter", "marketing", "mail",
              "notifications", "notification", "donotreply", "do-not-reply", "team", "hello"}
SMALL_RATIO = 0.1


def registrable(d: str) -> str:
    d = (d or "").strip().lower().strip(".")
    parts = d.split(".")
    for n, sfx in ((3, SUFFIX3), (2, SUFFIX2)):
        if len(parts) > n and ".".join(parts[-n:]) in sfx:
            return ".".join(parts[-(n + 1):])
    return ".".join(parts[-2:]) if len(parts) >= 2 else d


def label(reg: str) -> str:
    return reg.split(".", 1)[0]


def norm(s: str) -> str:
    for a, b in HOMO:
        s = s.replace(a, b)
    return s


def lev(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 3
    d = [[0] * (len(b) + 1) for _ in range(len(a) + 1)]
    for i in range(len(a) + 1):
        d[i][0] = i
    for j in range(len(b) + 1):
        d[0][j] = j
    for i in range(1, len(a) + 1):
        for j in range(1, len(b) + 1):
            c = a[i - 1] != b[j - 1]
            d[i][j] = min(d[i - 1][j] + 1, d[i][j - 1] + 1, d[i - 1][j - 1] + c)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + 1)
    return d[-1][-1]


def similar(a: str, p: str) -> str | None:
    ra, rp = registrable(a), registrable(p)
    if ra == rp:
        return None
    sa, sp = label(ra), label(rp)
    if len(sp) < 5:
        return None
    if sa == sp:
        return "tld"
    if norm(sa) == norm(sp):
        return "homoglyph"
    if len(sp) >= 8 and lev(sa, sp) == 1:
        return "edit1"
    if len(sp) >= 6 and sp in re.split(r"[-.]", sa):
        return "contains"
    return None


def _deletes(s: str, depth: int) -> set:
    out, frontier = {s}, {s}
    for _ in range(depth):
        nxt = set()
        for w in frontier:
            for i in range(len(w)):
                nxt.add(w[:i] + w[i + 1:])
        out |= nxt
        frontier = nxt
    return out


class _Index:
    def __init__(self, refs):
        self.by_key = {}
        self.by_label = {}
        for r in refs:
            lb = label(r)
            self.by_label.setdefault(lb, set()).add(r)
            self.by_label.setdefault(norm(lb), set()).add(r)
            if len(lb) >= 8:
                for k in _deletes(lb, 1):
                    self.by_key.setdefault(k, set()).add(r)

    def candidates(self, reg_a):
        la = label(reg_a)
        out = set(self.by_label.get(la, ())) | set(self.by_label.get(norm(la), ()))
        for k in _deletes(la, 1):
            out |= self.by_key.get(k, set())
        for tok in re.split(r"[-.]", la):
            out |= self.by_label.get(tok, set())
        return out


def _aggregate(state: dict, own: list):
    days = sorted((state or {}).get("days", {}).keys())
    agg = {}

    def slot(reg):
        return agg.setdefault(reg, {"in": 0, "st": Counter(), "r": set(), "s": set(), "lp": set(), "sub": [], "f": None,
                                    "l": None, "out": 0, "auto": 0, "staff": set(), "of": None, "ol": None, "hosts": set()})

    def is_own(dom):
        return any(dom == o or dom.endswith("." + o) for o in own)

    for day in days:
        cell = state["days"][day] or {}
        for dom, v in (cell.get("in") or {}).items():
            if not dom or is_own(dom):
                continue
            a = slot(registrable(dom))
            a["hosts"].add(dom)
            a["in"] += int(v.get("n") or 0)
            a["st"].update(v.get("st") or {})
            a["r"].update((v.get("r") or [])[:25])
            a["s"].update((v.get("s") or [])[:10])
            a["lp"].update(x.split("@", 1)[0].lower() for x in (v.get("s") or []) if "@" in x)
            for sj in v.get("sub") or []:
                if sj and sj not in a["sub"] and len(a["sub"]) < 3:
                    a["sub"].append(sj)
            a["f"] = min(x for x in (a["f"], v.get("f") or day) if x)
            a["l"] = max(x for x in (a["l"], v.get("l") or day) if x)
        for dom, v in (cell.get("out") or {}).items():
            if not dom or is_own(dom):
                continue
            a = slot(registrable(dom))
            a["hosts"].add(dom)
            a["out"] += int(v.get("n") or 0)
            a["auto"] += int(v.get("auto") or 0)
            if not int(v.get("n") or 0):
                continue
            a["lp"].update(x.split("@", 1)[0].lower() for x in (v.get("to") or []) if "@" in x)
            a["staff"].update(v.get("s") or [])
            a["of"] = min(x for x in (a["of"], v.get("f") or day) if x)
            a["ol"] = max(x for x in (a["ol"], v.get("l") or day) if x)
    return days, agg


def _seen(state: dict, reg: str, after: str | None = None, until: str | None = None):
    senders, hosts = set(), set()
    for day in sorted((state or {}).get("days", {})):
        if (after and day <= after) or (until and day > until):
            continue
        for dom, v in ((state["days"][day] or {}).get("in") or {}).items():
            if dom and registrable(dom) == reg:
                hosts.add(dom.lower())
                senders.update(str(x).lower() for x in (v.get("s") or []) if "@" in str(x))
    return senders, hosts


def first_contact_candidates(agg: dict, days: list, lookback: int = NEW_LOOKBACK_DAYS) -> list:
    if not days:
        return []
    since = (date.fromisoformat(days[-1][:10]) - timedelta(days=lookback)).isoformat()
    out = []
    for reg, a in agg.items():
        if a["in"] <= 0 or reg in PUBLIC or reg in INFRA or label(reg) in ("", "www"):
            continue
        first = str(a["f"] or "")
        if not first or first[:10] <= days[0][:10] or first[:10] < since:
            continue
        if a["of"] and str(a["of"]) < first:
            continue
        if int(a["st"].get("Delivered", 0)) <= 0 and a["out"] <= 0:
            continue
        out.append(reg)
    return sorted(out)


def load_age():
    try:
        raw = json.loads(AGE.read_text(encoding="utf-8-sig")) if AGE.exists() else None
    except Exception:
        return None
    return raw if isinstance(raw, dict) else None


def _lists(snapshot: dict):
    imp = (snapshot or {}).get("impersonation") or {}
    block = imp.get("blockList")
    pols = imp.get("antiPhish")
    protect_d, protect_u, trust_d, trust_s = set(), [], set(), set()
    for p in pols or []:
        if not p.get("enabled", True):
            continue
        protect_d |= {str(x).lower() for x in p.get("protectDomains") or []}
        protect_u += [str(x) for x in p.get("protectUsers") or []]
        trust_d |= {str(x).lower() for x in p.get("trustDomains") or []}
        trust_s |= {str(x).lower() for x in p.get("trustSenders") or []}
    return block, pols, protect_d, protect_u, trust_d, trust_s


def _blocked(reg: str, hosts: set, block) -> bool:
    for b in block or []:
        if str(b.get("action", "")).lower() != "block":
            continue
        v = str(b.get("value", "")).lower()
        if not v:
            continue
        dom = v.rsplit("@", 1)[-1]
        if dom == reg or dom in hosts or registrable(dom) == reg:
            return True
    return False


def _mask(addr: str) -> str:
    if "@" not in (addr or ""):
        return addr or ""
    u, d = addr.split("@", 1)
    return f"{u[:1]}***@{d}"


def load_state():
    try:
        return json.loads(STATE.read_text(encoding="utf-8-sig")) if STATE.exists() else None
    except Exception:
        return None


def load_intent():
    try:
        raw = json.loads(INTENT.read_text(encoding="utf-8-sig")) if INTENT.exists() else {}
    except Exception:
        return {}
    items = raw.get("domains", raw) if isinstance(raw, dict) else {}
    return {str(k).lower(): (v if isinstance(v, dict) else {"reason": str(v)}) for k, v in items.items()}


def review(snapshot: dict, state: dict | None = None, intent: dict | None = None, age: dict | None = None) -> dict:
    own = [d.lower() for d in ((snapshot.get("allowlist") or {}).get("ownDomains") or [])]
    block, pols, protect_d, protect_u, trust_d, trust_s = _lists(snapshot)
    out = {
        "listsCollected": block is not None and pols is not None,
        "traceCollected": bool(state and state.get("days")),
        "blockList": [],
        "policies": [],
        "protectDomains": sorted(protect_d),
        "protectUsers": [],
        "trustDomains": sorted(trust_d),
        "trustSenders": sorted(trust_s),
        "suspects": [], "similarPartners": [], "protectGaps": [], "confirmedReal": [],
        "newDomains": [], "newDomainLookup": {},
        "counts": {},
    }
    f = []

    for p in pols or []:
        out["policies"].append({k: p.get(k) for k in ("name", "isDefault", "enabled", "protectDomainsOn", "domainAction",
                                                       "protectUsersOn", "userAction", "orgDomainsOn", "mailboxIntel",
                                                       "firstContactTip")} | {
            "protectDomainCount": len(p.get("protectDomains") or []),
            "protectUserCount": len(p.get("protectUsers") or [])})
    for u in protect_u:
        name, _, addr = u.rpartition(";")
        out["protectUsers"].append({"name": name or addr, "address": _mask(addr)})

    if not own:
        out["note"] = "ownDomainsUnknown"
        return {"impersonation": out, "findings": f}
    if state is None:
        state = load_state()
    if intent is None:
        intent = load_intent()
    out["traceCollected"] = bool(state and state.get("days"))
    days, agg = _aggregate(state or {}, own)
    out["windowStart"] = days[0] if days else None
    out["windowEnd"] = days[-1] if days else None
    out["windowDays"] = len(days)

    def est(a):
        return a["out"] >= EST_OUT and len(a["staff"]) >= EST_STAFF and a["in"] >= EST_IN

    def vol(a):
        return a["out"] + a["in"]

    usable = {r: a for r, a in agg.items() if r not in PUBLIC and r not in INFRA and label(r) not in ("", "www")}
    refs = {r for r, a in usable.items() if est(a)}
    refs |= {registrable(d) for d in protect_d} | {registrable(d) for d in trust_d}
    refs = {r for r in refs if r not in PUBLIC and r not in INFRA and not _blocked(r, agg.get(r, {}).get("hosts", set()), block)}
    idx = _Index(refs)
    declared_real = {registrable(d) for d in protect_d | trust_d} | {registrable(k) for k in intent}
    intent_reg = {registrable(k): v for k, v in intent.items()}

    for reg, a in usable.items():
        if a["in"] == 0:
            continue
        best = None
        for p in idx.candidates(reg):
            if p == reg:
                continue
            why = similar(reg, p)
            if not why:
                continue
            pv = vol(agg[p]) if p in agg else 0
            if pv <= vol(a) and p not in declared_real:
                continue
            if best is None or pv > best[2]:
                best = (p, why, pv)
        if not best:
            continue
        p, why, pv = best
        blocked = _blocked(reg, a["hosts"], block)
        if reg in intent_reg and not blocked:
            it = intent_reg[reg]
            checked = str(it.get("checkedAt") or "")[:10]
            if "knownSenders" in it or "knownHosts" in it:
                known_s = {str(x).lower() for x in it.get("knownSenders") or []}
                known_h = {str(x).lower() for x in it.get("knownHosts") or []}
                now_s, now_h = _seen(state, reg)
            elif checked:
                known_s, known_h = _seen(state, reg, until=checked)
                now_s, now_h = _seen(state, reg, after=checked)
            else:
                known_s = known_h = now_s = now_h = set()
            new_s, new_h = sorted(now_s - known_s), sorted(now_h - known_h)
            out["confirmedReal"].append({
                "domain": reg, "looksLike": p, "why": why, "reason": it.get("reason"), "checkedAt": checked or None,
                "by": it.get("by"), "lastSeen": a["l"], "inbound": a["in"], "replies": a["out"], "autoReplies": a["auto"],
                "newSenders": new_s[:10], "newHosts": new_h[:10], "newSinceCheck": bool(new_s or new_h)})
            continue
        if reg in declared_real and not blocked:
            continue
        same = sorted(x for x in (a["lp"] & (agg[p]["lp"] if p in agg else set())) if x not in GENERIC_LP)[:5]
        own_tenant = (reg.endswith(".onmicrosoft.com") and label(reg) == label(p))
        first = min((x for x in (a["f"], a["of"]) if x), default=None)
        is_new = bool(first and days and first[:10] > days[0])
        small = pv and vol(a) < SMALL_RATIO * pv
        row = {
            "domain": reg, "hosts": sorted(a["hosts"])[:5], "looksLike": p, "why": why,
            "firstSeen": first, "lastSeen": max((x for x in (a["l"], a["ol"]) if x), default=None),
            "inbound": a["in"], "status": dict(a["st"]), "delivered": int(a["st"].get("Delivered", 0)),
            "replies": a["out"], "autoReplies": a["auto"], "repliedBy": sorted(a["staff"])[:25], "recipients": sorted(a["r"])[:50],
            "recipientCount": len(a["r"]), "senders": sorted(a["s"])[:5], "subjects": a["sub"][:3],
            "blocked": blocked, "partnerVolume": pv, "volume": vol(a),
        }
        row["sameLocalParts"] = same
        if not blocked and not same and (own_tenant or (est(a) and not small)):
            out["similarPartners"].append(row)
            continue
        if not blocked and not same and why == "edit1" and not is_new:
            out["similarPartners"].append(row)
            continue
        row["level"] = ("blocked" if blocked else "replied" if a["out"] > 0
                        else "delivered" if row["delivered"] > 0 else "quarantined")
        out["suspects"].append(row)

    order = {"replied": 0, "delivered": 1, "quarantined": 2, "blocked": 3}
    out["suspects"].sort(key=lambda r: (order[r["level"]], r["firstSeen"] or ""), reverse=False)
    out["similarPartners"].sort(key=lambda r: -r["volume"])

    gaps = sorted((r for r in usable if est(usable[r]) and r not in {registrable(d) for d in protect_d}
                   and len(label(r)) >= 5), key=lambda r: -(min(usable[r]["out"], usable[r]["in"]) * len(usable[r]["staff"])))
    out["protectGaps"] = [{"domain": r, "sent": usable[r]["out"], "received": usable[r]["in"],
                           "staff": len(usable[r]["staff"])} for r in gaps[:10]]

    if age is None:
        age = load_age()
    sus_by = {r["domain"]: r for r in out["suspects"]}
    cands = first_contact_candidates(agg, days)
    known_age = (age or {}).get("domains") or {}
    pending = failed = nodate = 0
    order_new = {"replied": 0, "delivered": 1, "quarantined": 2, "blocked": 3, "confirmed": 4}
    for reg in cands:
        info = known_age.get(reg)
        if not info:
            pending += 1
            continue
        if info.get("status") == "error":
            failed += 1
            continue
        created = str(info.get("created") or "")[:10]
        a = agg[reg]
        try:
            age_days = (date.fromisoformat(str(a["f"])[:10]) - date.fromisoformat(created)).days
        except ValueError:
            nodate += 1
            continue
        if age_days > NEW_AGE_DAYS:
            continue
        blocked = _blocked(reg, a["hosts"], block)
        it = intent_reg.get(reg)
        delivered = int(a["st"].get("Delivered", 0))
        level = ("blocked" if blocked else "confirmed" if (it or reg in declared_real)
                 else "replied" if a["out"] > 0 else "delivered" if delivered > 0 else "quarantined")
        lk = sus_by.get(reg)
        out["newDomains"].append({
            "domain": reg, "hosts": sorted(a["hosts"])[:5], "created": created, "ageDays": age_days,
            "registrar": info.get("registrar"), "firstSeen": a["f"],
            "lastSeen": max((x for x in (a["l"], a["ol"]) if x), default=None),
            "inbound": a["in"], "delivered": delivered, "status": dict(a["st"]),
            "replies": a["out"], "autoReplies": a["auto"], "repliedBy": sorted(a["staff"])[:25], "recipients": sorted(a["r"])[:50],
            "recipientCount": len(a["r"]), "senders": sorted(a["s"])[:5], "subjects": a["sub"][:3],
            "blocked": blocked, "level": level, "looksLike": lk["looksLike"] if lk else None,
            "reason": (it or {}).get("reason"), "checkedAt": (it or {}).get("checkedAt"), "by": (it or {}).get("by")})
    out["newDomains"].sort(key=lambda r: str(r["firstSeen"] or ""), reverse=True)
    out["newDomains"].sort(key=lambda r: order_new[r["level"]])
    out["newDomainLookup"] = {
        "collected": age is not None, "lastRun": (age or {}).get("lastRun"), "candidates": len(cands),
        "pending": pending, "failed": failed, "noDate": nodate,
        "maxAgeDays": NEW_AGE_DAYS, "lookbackDays": NEW_LOOKBACK_DAYS}

    sus = {r["domain"] for r in out["suspects"]}
    new_set = {r["domain"] for r in out["newDomains"]}
    for b in block or []:
        v = str(b.get("value", ""))
        dom = v.rsplit("@", 1)[-1].lower()
        out["blockList"].append({"value": v, "kind": "address" if "@" in v else "domain", "action": b.get("action"),
                                 "modified": b.get("modified"), "expires": b.get("expires"), "notes": b.get("notes"),
                                 "lookalike": registrable(dom) in sus, "newDomain": registrable(dom) in new_set})
    out["blockList"].sort(key=lambda r: r.get("modified") or "", reverse=True)

    out["confirmedReal"].sort(key=lambda r: (not r["newSinceCheck"], r["domain"]))
    c = Counter(r["level"] for r in out["suspects"])
    out["counts"] = {"replied": c["replied"], "delivered": c["delivered"], "quarantined": c["quarantined"],
                     "blocked": c["blocked"], "similarPartners": len(out["similarPartners"]),
                     "confirmedReal": len(out["confirmedReal"]),
                     "blockList": len(out["blockList"]), "protectDomains": len(protect_d),
                     "protectUsers": len(protect_u), "trustDomains": len(trust_d)}
    cn = Counter(r["level"] for r in out["newDomains"])
    out["counts"].update({"newReplied": cn["replied"], "newDelivered": cn["delivered"], "newQuarantined": cn["quarantined"],
                          "newBlocked": cn["blocked"], "newConfirmed": cn["confirmed"]})

    for r in out["suspects"]:
        if r["level"] == "replied":
            f.append(finding(
                "high",
                en=f"Lookalike sender domain {r['domain']} (looks like {r['looksLike']}) — our staff have SENT {r['replies']} "
                   f"message(s) to it and it is not blocked. This is the Partner A pattern: confirm with "
                   f"the partner by phone and block it in the Tenant Allow/Block List.",
                ko=f"닮은 발신 도메인 {r['domain']}({r['looksLike']} 와 닮음) — 우리 직원이 그 주소로 {r['replies']}통을 "
                   f"**보냈고** 아직 차단되지 않았습니다. Partner A 과 같은 모양입니다: 거래처에 전화로 "
                   f"확인하고 테넌트 허용/차단 목록에서 차단하십시오."))
        elif r["level"] == "delivered":
            f.append(finding(
                "med",
                en=f"Lookalike sender domain {r['domain']} (looks like {r['looksLike']}) reached {r['recipientCount']} inbox(es) "
                   f"— {r['delivered']} delivered, nobody has replied yet. Block it, or record it in data/lookalike-intent.json "
                   f"if it is a real partner.",
                ko=f"닮은 발신 도메인 {r['domain']}({r['looksLike']} 와 닮음)이 받은편지함 {r['recipientCount']}곳에 도착했습니다 "
                   f"— 배달 {r['delivered']}통, 아직 회신 없음. 차단하거나, 진짜 거래처면 data/lookalike-intent.json 에 기록하십시오."))
    for r in out["newDomains"]:
        lk = sus_by.get(r["domain"])
        if lk and lk["level"] in ("replied", "delivered"):
            continue
        if r["level"] == "replied":
            f.append(finding(
                "high",
                en=f"Newly registered sender domain {r['domain']} (registered {r['ageDays']} day(s) before its first mail, "
                   f"{r['created']}) contacted us with no prior history, and our staff have SENT {r['replies']} message(s) to it. "
                   f"Not blocked. Confirm the company is real (the a supplier look-alike had the same shape); "
                   f"block it if not.",
                ko=f"새로 등록된 발신 도메인 {r['domain']}(첫 메일 {r['ageDays']}일 전 등록 · {r['created']})이 교신 이력 없이 "
                   f"먼저 연락해 왔고 우리 직원이 {r['replies']}통을 **보냈습니다**. 차단 안 됨. 진짜 회사인지 확인하고"
                   f"(a supplier 사칭과 같은 모양), 아니면 차단하십시오."))
        elif r["level"] == "delivered":
            f.append(finding(
                "med",
                en=f"Newly registered sender domain {r['domain']} (registered {r['ageDays']} day(s) before its first mail) "
                   f"reached {r['recipientCount']} inbox(es) with no prior history — nobody has replied. Block it, or record "
                   f"it as real (✓ on the dashboard PC or scripts/record_lookalike.py) once someone has checked.",
                ko=f"새로 등록된 발신 도메인 {r['domain']}(첫 메일 {r['ageDays']}일 전 등록)이 교신 이력 없이 받은편지함 "
                   f"{r['recipientCount']}곳에 도착했습니다 — 아직 회신 없음. 차단하거나, 확인 뒤 진짜면 정상으로 기록하십시오"
                   f"(대시보드 PC 의 ✓ 또는 scripts/record_lookalike.py)."))
    return {"impersonation": out, "findings": f}


DOMAIN_RE = re.compile(r"(?=.{4,253}$)([a-z0-9-]+\.)+[a-z]{2,}")
INTENT_COMMENT = ("사칭 감시에서 '닮았지만 진짜' 로 확인한 도메인. 여기 있는 도메인은 다시 경고하지 않습니다"
                  "(차단 목록에 있으면 차단으로 표시). 확인 근거를 reason 에 적으십시오 — 근거 없는 기록은 다음 사칭을 숨깁니다.")
REASON_MIN, REASON_MAX, BY_MAX = 8, 300, 80
KNOWN_MAX = 100


def _msg(code, ko, en):
    return {"ok": code == "ok", "code": code, "ko": ko, "en": en}


def _load_raw(path):
    path = Path(path)
    if not path.exists():
        return {"_comment": INTENT_COMMENT, "domains": {}}
    raw = json.loads(path.read_text(encoding="utf-8-sig"))
    raw.setdefault("domains", {})
    return raw


def _save_raw(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(path)


def record_intent(domain, reason, by="IT", own=(), path=None, allowed=None, today=None, state=None):
    d = (domain or "").strip().lower().lstrip("@")
    reason = (reason or "").strip()
    by = (by or "").strip()[:BY_MAX] or "IT"
    if not DOMAIN_RE.fullmatch(d):
        return _msg("bad-domain", f"도메인 형식이 아닙니다: {d}", f"Not a domain: {d}")
    if d in PUBLIC or registrable(d) in PUBLIC:
        return _msg("public", f"{d} 는 공용 메일입니다 — 기록하면 그 메일의 사칭 전부가 판정 밖으로 나갑니다.",
                    f"{d} is a public mail service - recording it would hide every impersonation sent from it.")
    if any(d == o or d.endswith("." + o) for o in (x.lower() for x in own)):
        return _msg("own", f"{d} 는 우리 도메인입니다.", f"{d} is one of our own domains.")
    if allowed is not None and registrable(d) not in {registrable(x) for x in allowed}:
        return _msg("not-suspect", f"{d} 는 지금 사칭 의심 목록에 없습니다 — 화면에 떠 있는 도메인만 기록할 수 있습니다.",
                    f"{d} is not on the current suspect list - only domains shown there can be recorded.")
    if len(reason) < REASON_MIN:
        return _msg("no-reason", f"근거가 필요합니다({REASON_MIN}자 이상) — 누가 · 어떻게 확인했는지 적으십시오.",
                    f"A reason is required (at least {REASON_MIN} characters) - who confirmed it and how.")
    reason = reason[:REASON_MAX]
    path = Path(path or INTENT)
    data = _load_raw(path)
    was = d in data["domains"]
    entry = {"reason": reason, "checkedAt": (today or date.today()).isoformat(), "by": by}
    st = state if state is not None else load_state()
    if st and st.get("days"):
        known_s, known_h = _seen(st, registrable(d))
        entry["knownSenders"], entry["knownHosts"] = sorted(known_s)[:KNOWN_MAX], sorted(known_h)[:KNOWN_MAX]
    data["domains"][d] = entry
    data.setdefault("_comment", INTENT_COMMENT)
    _save_raw(path, data)
    return _msg("ok", f"{d} {'기록을 고쳤습니다' if was else '를 확인된 정상으로 기록했습니다'}.",
                f"{d} {'record updated' if was else 'recorded as real'}.")


def remove_intent(domain, path=None):
    d = (domain or "").strip().lower()
    path = Path(path or INTENT)
    data = _load_raw(path)
    if d not in data["domains"]:
        return _msg("missing", f"{d} 는 기록에 없습니다.", f"{d} is not recorded.")
    data["domains"].pop(d)
    _save_raw(path, data)
    return _msg("ok", f"{d} 기록을 지웠습니다 — 다시 판정합니다.", f"{d} removed - it will be judged again.")


def audit(action, domain, result, via, extra=None, path=None):
    try:
        line = {"at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), "action": action,
                "domain": (domain or "")[:253], "result": result, "via": via}
        line.update(extra or {})
        p = Path(path or AUDIT)
        p.parent.mkdir(parents=True, exist_ok=True)
        with p.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(line, ensure_ascii=False) + "\n")
    except Exception:
        pass
