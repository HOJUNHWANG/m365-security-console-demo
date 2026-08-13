"""Audit the demo fixture for internal contradictions.

The verifier next door answers "did any real data survive". This answers the other question:
"does the synthetic data contradict itself". Different failure, same cause - a generator that
produces one value at a time cannot see relationships, so a fixture can be perfectly sanitised and
still claim 47 devices above a table of 29, report a 73% failure rate beside 130 failures out of
3,371, or put a sender in the tenant's own domain on a row labelled External.

Every check here is a relationship BETWEEN fields, and each was written because it caught something:
the first run found 64 contradictions in 6 categories.

    python demo/audit_fixture.py [path-to-fixture]

Exits non-zero on any finding, so it gates CI. When a finding turns out to be a false positive,
tighten the check rather than delete it - a heuristic that flags a correct row will otherwise be
dropped along with the ones that matter.
"""
import json
import pathlib
import re
import sys
from collections import Counter
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIX = sys.argv[1] if len(sys.argv) > 1 else str(ROOT / "app" / "static" / "demo-summary.json")
d = json.load(open(FIX, encoding="utf-8"))
NOW = datetime.now(timezone.utc)
ISO = re.compile(r"^\d{4}-\d{2}-\d{2}([T ][\d:.]+([+-]\d{2}:?\d{2}|Z)?)?$")

findings = []


def f(cat, msg):
    findings.append((cat, msg))


# ---------------------------------------------------------------------------------------------
# 1) A number named like a count must match the list it counts.
# ---------------------------------------------------------------------------------------------
COUNT_HINT = re.compile(r"(count|total|^n$|num)", re.I)


def singular(s):
    for suf, rep in (("ies", "y"), ("ses", "s"), ("s", "")):
        if s.endswith(suf):
            return s[: -len(suf)] + rep
    return s


def walk(node, path=""):
    if isinstance(node, dict):
        lists = {k: v for k, v in node.items() if isinstance(v, list)}
        nums = {k: v for k, v in node.items() if isinstance(v, int) and not isinstance(v, bool)}
        for nk, nv in nums.items():
            if not COUNT_HINT.search(nk):
                continue
            stem = singular(re.sub(COUNT_HINT, "", nk).strip("_").lower()) or ""
            if not stem:
                continue
            cand = {lk: len(lv) for lk, lv in lists.items()
                    if stem in singular(lk.lower()) or singular(lk.lower()) in stem}
            if cand and nv not in cand.values():
                f("count-vs-list", f"{path}.{nk}={nv} matches none of "
                                   + ", ".join(f"{k}={v}" for k, v in cand.items()))
        for k, v in node.items():
            walk(v, f"{path}.{k}" if path else k)
    elif isinstance(node, list):
        for i, v in enumerate(node):
            walk(v, f"{path}[]")


walk(d)

# ---------------------------------------------------------------------------------------------
# 2) Histograms must sum to their total.
# ---------------------------------------------------------------------------------------------
def hist_sum(container, keyname):
    v = container.get(keyname)
    if isinstance(v, dict) and v and all(isinstance(x, int) for x in v.values()):
        return sum(v.values())
    if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
        for ck in ("count", "n", "value", "total"):
            if all(ck in x for x in v):
                return sum(x[ck] for x in v)
    return None


for src, body in d.items():
    if not isinstance(body, dict):
        continue
    for hk in list(body):
        if not hk.startswith("by"):
            continue
        s = hist_sum(body, hk)
        if s is None:
            continue
        for tk in ("total", "count", "enrolled", "users", "records", "logins", "delivered"):
            if isinstance(body.get(tk), int) and body[tk] and s != body[tk]:
                f("histogram-sum", f"{src}.{hk} sums to {s} but {src}.{tk}={body[tk]}")
                break

# ---------------------------------------------------------------------------------------------
# 3) Things that must be unique.
# ---------------------------------------------------------------------------------------------
UNIQ_KEYS = ("id", "name", "device", "user", "upn", "policy", "mailbox", "sku", "key")
for src, body in d.items():
    if not isinstance(body, dict):
        continue
    for lk, lv in body.items():
        if not (isinstance(lv, list) and lv and isinstance(lv[0], dict)):
            continue
        entity = all("id" in x for x in lv)
        for uk in UNIQ_KEYS:
            if not all(uk in x for x in lv):
                continue
            if uk != "id" and not entity:
                continue          # not an entity list - repeats are legitimate
            vals = [x[uk] for x in lv if isinstance(x[uk], str)]
            dups = [v for v, c in Counter(vals).items() if c > 1]
            if dups and uk in ("id", "device", "name", "policy", "sku", "key"):
                f("duplicate", f"{src}.{lk}[].{uk}: {len(dups)} repeated value(s), "
                               f"e.g. {dups[:3]}")

# scalar lists that should be sets
for src, body in d.items():
    if not isinstance(body, dict):
        continue
    for lk, lv in body.items():
        if isinstance(lv, list) and lv and all(isinstance(x, str) for x in lv):
            dups = [v for v, c in Counter(lv).items() if c > 1]
            if dups:
                f("duplicate", f"{src}.{lk}[] repeats {dups[:3]}")

# nested scalar lists inside rows (controls[], editions[], apps[])
def nested_dups(node, path=""):
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, list) and v and all(isinstance(x, str) for x in v):
                dups = [x for x, c in Counter(v).items() if c > 1]
                if dups:
                    f("duplicate", f"{path}.{k}[] repeats {dups[:2]}")
            else:
                nested_dups(v, f"{path}.{k}" if path else k)
    elif isinstance(node, list):
        for v in node[:80]:
            nested_dups(v, f"{path}[]")


nested_dups(d)

# ---------------------------------------------------------------------------------------------
# 4) Dates: nothing in the future, and first <= last.
# ---------------------------------------------------------------------------------------------
future = []


def dates(node, path=""):
    if isinstance(node, dict):
        for k, v in node.items():
            dates(v, f"{path}.{k}" if path else k)
        pairs = [("first", "last"), ("invited", "lastActivity"), ("created", "resolved"),
                 ("coverageFrom", "coverageTo"), ("firstBlock", "lastBlock")]
        for a, b in pairs:
            ka = next((k for k in node if k.lower().startswith(a.lower())), None)
            kb = next((k for k in node if k.lower().startswith(b.lower())), None)
            if ka and kb and isinstance(node[ka], str) and isinstance(node[kb], str) \
                    and ISO.match(node[ka]) and ISO.match(node[kb]) and node[ka] > node[kb]:
                f("date-order", f"{path}.{ka} ({node[ka][:16]}) later than .{kb} ({node[kb][:16]})")
    elif isinstance(node, list):
        for v in node[:80]:
            dates(v, f"{path}[]")
    elif isinstance(node, str) and ISO.match(node) and len(node) > 10:
        try:
            t = datetime.fromisoformat(node.replace("Z", "+00:00"))
            if t.tzinfo is None:
                t = t.replace(tzinfo=timezone.utc)
            if (t - NOW).total_seconds() > 300:
                future.append(f"{path} = {node[:19]}")
        except ValueError:
            pass


dates(d)
if future:
    f("future-date", f"{len(future)} timestamp(s) in the future, e.g. {future[:3]}")

# ---------------------------------------------------------------------------------------------
# 5) Rates must match their numerator and denominator.
# ---------------------------------------------------------------------------------------------
rs = d.get("riskySignins", {})
if isinstance(rs, dict) and rs.get("logins"):
    want = round(rs.get("failed", 0) / rs["logins"] * 100, 1)
    got = rs.get("failRate")
    if isinstance(got, (int, float)) and abs(got - want) > 1.0:
        f("rate", f"riskySignins.failRate={got} but failed/logins = {want} "
                  f"({rs.get('failed')}/{rs['logins']})")
    if rs.get("failed", 0) > rs["logins"]:
        f("rate", f"riskySignins.failed={rs['failed']} exceeds logins={rs['logins']}")

mfa = d.get("mfaStatus", {})
if isinstance(mfa, dict):
    tot, reg = mfa.get("total"), mfa.get("registered")
    if isinstance(tot, int) and isinstance(reg, int):
        if reg > tot:
            f("rate", f"mfaStatus.registered={reg} exceeds total={tot}")
        pct = mfa.get("percent")
        if isinstance(pct, (int, float)) and tot and abs(pct - round(reg / tot * 100, 1)) > 1.0:
            f("rate", f"mfaStatus.percent={pct} but registered/total = "
                      f"{round(reg / tot * 100, 1)} ({reg}/{tot})")

# subset relationships
def subset(src, small, big):
    b = d.get(src, {})
    if isinstance(b, dict) and isinstance(b.get(small), int) and isinstance(b.get(big), int) \
            and b[small] > b[big]:
        f("subset", f"{src}.{small}={b[small]} exceeds {src}.{big}={b[big]}")


for src, small, big in [("intuneDevices", "compliant", "total"),
                        ("intuneDevices", "noncompliant", "total"),
                        ("intuneDevices", "encrypted", "total"),
                        ("accountSummary", "guests", "total"),
                        ("accountSummary", "disabled", "total"),
                        ("deviceIdentity", "ok", "enrolled"),
                        ("deviceIdentity", "problems", "enrolled"),
                        ("browserClaims", "proven", "pilotMembers"),
                        ("licenses", "used", "total")]:
    subset(src, small, big)

it = d.get("intuneDevices", {})
if isinstance(it, dict) and all(isinstance(it.get(k), int) for k in ("compliant", "noncompliant", "total")):
    if it["compliant"] + it["noncompliant"] != it["total"]:
        f("subset", f"intuneDevices compliant+noncompliant = "
                    f"{it['compliant'] + it['noncompliant']} but total={it['total']}")

# ---------------------------------------------------------------------------------------------
# 6) Cross-source: the same fleet, seen from three angles.
# ---------------------------------------------------------------------------------------------
sizes = {}
if isinstance(d.get("intuneDevices"), dict):
    sizes["intuneDevices.total"] = d["intuneDevices"].get("total")
    sizes["intuneDevices.devices[]"] = len(d["intuneDevices"].get("devices") or [])
if isinstance(d.get("deviceIdentity"), dict):
    sizes["deviceIdentity.enrolled"] = d["deviceIdentity"].get("enrolled")
    sizes["deviceIdentity.devices[]"] = len(d["deviceIdentity"].get("devices") or [])
vals = [v for v in sizes.values() if isinstance(v, int)]
if vals and max(vals) - min(vals) > 0:
    f("cross-source", f"fleet size disagrees across sources: {sizes}")

if isinstance(d.get("adminAccounts"), dict) and isinstance(d.get("accountSummary"), dict):
    ga = d["adminAccounts"].get("globalAdminCount")
    tot = d["accountSummary"].get("total")
    if isinstance(ga, int) and isinstance(tot, int) and ga > tot:
        f("cross-source", f"globalAdminCount={ga} exceeds accountSummary.total={tot}")

# ---------------------------------------------------------------------------------------------
# 7) Data Health must describe the snapshot it ships with.
# ---------------------------------------------------------------------------------------------
dh = d.get("_dataHealth", {})
if isinstance(dh, dict):
    srcs = [k for k, v in d.items()
            if not k.startswith("_") and isinstance(v, dict) and "available" in v]
    hs = {s["key"] for s in dh.get("sources", [])}
    if hs != set(srcs):
        f("dataHealth", f"health lists {len(hs)} sources, snapshot has {len(srcs)}: "
                        f"missing {sorted(set(srcs) - hs)[:4]}, extra {sorted(hs - set(srcs))[:4]}")
    for c in dh.get("collection", {}).get("cycles", []):
        if c.get("fresh", 0) + c.get("carried", 0) + c.get("down", 0) != c.get("total"):
            f("dataHealth", f"cycle {c.get('at', '')[:16]}: fresh+carried+down != total")
            break

# ---------------------------------------------------------------------------------------------
print(f"audited {FIX}\n")
by = {}
for cat, msg in findings:
    by.setdefault(cat, []).append(msg)
for cat in sorted(by):
    print(f"[{cat}]  {len(by[cat])}")
    for m in by[cat][:14]:
        print(f"    {m}")
    if len(by[cat]) > 14:
        print(f"    ... {len(by[cat]) - 14} more")
    print()
if findings:
    print(f"{len(findings)} contradiction(s) FOUND")
    sys.exit(1)
print("no contradictions found")
