"""Prove the published demo carries no tenant data.

Two checks, and the difference between them matters.

CHECK 1 (allowlist, runs anywhere) asks: is every string in the committed fixture accounted for?
Each one must be an authored pool value from the generator, a synthetic identifier in a form the
generator mints (contoso.com, LAPTOP-DEMO###, 203.0.113.x, 2001:db8::), a timestamp, or a literal
that appears in the application's own source. Anything else is unexplained and fails. This is the
check that can run in CI on a public repo, because it needs no access to real data.

CHECK 2 (blocklist, needs the private snapshot) asks the complementary question: does any string
from the REAL data appear anywhere in this repository - not just the fixture, but source, comments
and docs too? An allowlist can be wrong if the allowlist itself was built from something tainted;
this catches that. Skipped with a loud notice when no snapshot path is given.

    python demo/verify_demo.py
    python demo/verify_demo.py --snapshot ../ms365-security-dashboard/data/graph_snapshot.json

Exit code is non-zero on any failure, so it works as a pre-push gate.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "app" / "static" / "demo-summary.json"

SYNTHETIC = [
    re.compile(r"^[a-z]+\.[a-z]+@contoso\.com$"),
    re.compile(r"^[a-z-]+\d*@contoso\.com$"),
    re.compile(r"^[a-z.]+_[a-z.]+#EXT#@contoso\.onmicrosoft\.com$"),
    re.compile(r"^[A-Z][a-z]+ [A-Z][a-z]+$"),
    re.compile(r"^LAPTOP-DEMO\d{3}$"),
    re.compile(r"^203\.0\.113\.\d+$|^198\.51\.100\.\d+$|^192\.0\.2\.\d+$"),
    re.compile(r"^2001:db8:[0-9a-f:]+$"),
    re.compile(r"^[0-9a-f]{8}-1111-4222-8333-[0-9a-f]{12}$"),
    re.compile(r"^[0-9a-f]{8}11114222[0-9a-f]*$"),
    re.compile(r"^\d{4}-\d{2}-\d{2}([T ][\d:.+-]+(Z|[+-]\d{2}:?\d{2})?)?$"),
    re.compile(r"^\d{1,10}$"),
    re.compile(r"^[\d.]+$"),
    re.compile(r"^(smtp:)?[a-z0-9._-]+@[a-z0-9.-]+\.example$"),
    re.compile(r"^[a-z0-9-]+\.example$"),
    re.compile(r"^[A-Za-z][A-Za-z ]+ \d+$"),
    re.compile(r"^[A-Za-z][A-Za-z ]+ \d+ - synthetic text generated for the public demo; "
               r"no tenant data is used\.$"),
    re.compile(r"^$"),
]


def source_literals() -> set[str]:
    """Same extraction the generator uses, so rule 3 is checked against the same corpus."""
    pat = re.compile(r"""(?:'([^'\n]{1,80})'|"([^"\n]{1,80})"|`([^`\n]{1,80})`)""")
    out: set[str] = set()
    for p in list((ROOT / "app").rglob("*.py")) + list((ROOT / "app").rglob("*.html")) \
            + list((ROOT / "app").rglob("*.js")):
        try:
            text = p.read_text(encoding="utf-8")
        except OSError:
            continue
        for m in pat.finditer(text):
            for g in m.groups():
                if g:
                    out.add(g.strip().lower())
    return out


def generator_pools() -> set[str]:
    """Every string the generator can author, read out of the generator itself."""
    gen = (ROOT / "demo" / "generate_demo_snapshot.py").read_text(encoding="utf-8")
    out = set()
    for m in re.finditer(r'"([^"\n]{1,400})"|\'([^\'\n]{1,400})\'', gen):
        s = (m.group(1) or m.group(2)).strip()
        if s:
            out.add(s.lower())
    for m in re.finditer(r'=\s*\(\s*((?:"[^"]*"\s*)+)\)', gen):
        joined = "".join(re.findall(r'"([^"]*)"', m.group(1))).strip().lower()
        if joined:
            out.add(joined)
    return out


def walk_strings(node, path=""):
    if isinstance(node, dict):
        for k, v in node.items():
            yield f"{path}<key>", k
            yield from walk_strings(v, f"{path}.{k}" if path else k)
    elif isinstance(node, list):
        for v in node:
            yield from walk_strings(v, f"{path}[]")
    elif isinstance(node, str):
        yield path, node


FIELD_NAME = re.compile(r"^[A-Za-z_@][A-Za-z0-9_]*$")


def check_allowlist() -> list[str]:
    fixture = json.loads(FIXTURE.read_text(encoding="utf-8"))
    allowed = source_literals() | generator_pools()
    bad = []
    for path, s in walk_strings(fixture):
        if path.endswith("<key>") and FIELD_NAME.match(s):
            continue
        if any(r.match(s) for r in SYNTHETIC):
            continue
        if s.lower() in allowed:
            continue
        if any(a in s.lower() for a in allowed if len(a) > 24):
            continue
        bad.append(f"{path}  ->  {s[:90]}")
    return bad


PUBLIC_DOMAINS = {
    "microsoft.com", "graph.microsoft.com", "login.microsoftonline.com", "microsoftonline.com",
    "office.com", "office365.com", "outlook.com", "windows.com", "azure.com", "live.com",
    "sharepoint.com", "onmicrosoft.com", "github.com", "githubusercontent.com", "github.io", "cloudflare.com",
    "python.org", "pypi.org", "groq.com", "openai.com", "contoso.com", "example.com",
    "example.org", "schema.org", "w3.org", "ietf.org", "mozilla.org", "google.com",
    "salesforce.com", "zoom.us", "atlassian.com", "hubspot.com", "docusign.com",
    "grammarly.com", "dropbox.com", "slack.com",
}
DOMAINISH = re.compile(r"\b([a-z0-9][a-z0-9-]{2,}(?:\.[a-z0-9-]{2,})*\.(?:com|net|org|io|kr|co\.kr"
                       r"|dev|app|cloud|ai))\b", re.I)


def harvest(text: str) -> set[str]:
    """Identifier-shaped strings: anything that could name a tenant, a person or a machine."""
    terms: set[str] = set()
    terms |= set(re.findall(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}", text))
    terms |= set(re.findall(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
                            r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b", text))
    terms |= set(re.findall(r"\b(?:WIN|BOOK|DESKTOP|LAPTOP|PC|NB)[-_][A-Z0-9]{4,}\b", text))
    terms |= set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text))
    terms |= {m.group(1) for m in DOMAINISH.finditer(text)
              if m.group(1).lower() not in PUBLIC_DOMAINS
              and not any(m.group(1).lower().endswith("." + d) for d in PUBLIC_DOMAINS)
              and (m.start() == 0 or text[m.start() - 1] not in "._")}
    return terms


PUBLIC_GUIDS = {
    "f8cdef31-a31e-4b4a-93e4-5f571e91255a",
    "72f988bf-86f1-41af-91ab-2d7cd011db47",
    "cdc5aeea-15c5-4db6-b079-fcadd2505dc2",
}
FIRST_PARTY_APP = re.compile("^0000000[0-9]-0000-0000-c000-000000000000$")


def check_blocklist(snapshot: pathlib.Path, extra: list[pathlib.Path]) -> list[str]:
    terms = harvest(snapshot.read_text(encoding="utf-8"))
    for d in extra:
        for p in d.rglob("*"):
            if not p.is_file() or ".git" in p.parts or ".venv" in p.parts:
                continue
            if p.suffix.lower() not in {".py", ".html", ".js", ".json", ".md", ".txt", ".yml",
                                        ".yaml", ".cmd", ".ps1", ".example", ".env"}:
                continue
            try:
                terms |= harvest(p.read_text(encoding="utf-8", errors="replace"))
            except OSError:
                continue

    dummy = re.compile(r"^[a-z]{1,3}@|@(x|y|z|test|foo|bar|dummy)\.[a-z]+$|example", re.I)
    terms = {t for t in terms if len(t) >= 6 and not t.startswith(("203.0.113.", "198.51.100.",
                                                                   "192.0.2.", "0.0.0.0", "127.0.0",
                                                                   "2001:db8"))
             and t.lower() not in PUBLIC_DOMAINS
             and t.lower() not in ("contoso.onmicrosoft.com",)
             and not dummy.search(t)
             and t.lower() not in PUBLIC_GUIDS
             and not FIRST_PARTY_APP.match(t.lower())}
    print(f"  blocklist: {len(terms)} identifiers harvested from the private material")

    hits = []
    lowered = {t.lower() for t in terms}
    for p in sorted(ROOT.rglob("*")):
        if not p.is_file() or ".git" in p.parts:
            continue
        if p.suffix.lower() not in {".py", ".html", ".js", ".json", ".md", ".txt", ".yml",
                                    ".yaml", ".cmd", ".ps1", ".example", ""}:
            continue
        try:
            text = p.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        for t in lowered:
            if t in text:
                hits.append(f"{p.relative_to(ROOT)}  contains  {t}")
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot", default=None,
                    help="path to a REAL snapshot, to run the blocklist check as well")
    ap.add_argument("--harvest", action="append", default=[],
                    help="extra private directory to harvest identifiers from (repeatable)")
    a = ap.parse_args()

    failed = 0

    print("CHECK 1 - every string in the fixture is accounted for")
    if not FIXTURE.exists():
        print(f"  FAIL  {FIXTURE} is missing")
        failed += 1
    else:
        bad = check_allowlist()
        if bad:
            print(f"  FAIL  {len(bad)} unexplained string(s):")
            for line in bad[:25]:
                print(f"        {line}")
            failed += 1
        else:
            print("  ok    no unexplained strings")

    print("\nCHECK 2 - no identifier from the real snapshot appears anywhere in this repo")
    if not a.snapshot:
        print("  SKIP  no --snapshot given. Run this with the private snapshot before publishing.")
    else:
        snap = pathlib.Path(a.snapshot)
        if not snap.exists():
            print(f"  FAIL  {snap} not found")
            failed += 1
        else:
            hits = check_blocklist(snap, [pathlib.Path(x) for x in a.harvest])
            if hits:
                print(f"  FAIL  {len(hits)} leak(s):")
                for line in hits[:25]:
                    print(f"        {line}")
                failed += 1
            else:
                print("  ok    no real identifier found in any file")

    print()
    if failed:
        print(f"{failed} check(s) FAILED")
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
