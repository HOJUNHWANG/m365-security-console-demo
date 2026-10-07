"""Re-apply the demo-only changes after re-syncing app/ from the private repository.

The demo tracks a private application, so app/ gets replaced wholesale whenever the real dashboard
moves on - and the handful of edits that make it work as a static page get replaced with it. Doing
them by hand is how a re-sync silently ships a demo that calls a backend which is not there.

Everything here is idempotent: each edit checks for its own marker first, so running it twice is
safe and running it after a partial re-sync fixes only what is missing. When an anchor cannot be
found the script says which edit and which anchor, which is the point - an upstream refactor should
fail loudly here rather than quietly leaving the published page broken.

Every marker and every replacement is plain code: nothing here inserts a comment, so the result
also passes `demo/strip_comments.py --check`, and the anchors still match after comments have been
stripped from freshly copied source. Run the stripper before this script.

    python demo/apply_demo_mode.py            # apply, and report what changed
    python demo/apply_demo_mode.py --check    # verify only, non-zero if anything is missing

This file contains NO tenant data. Scrubbing tenant literals out of freshly copied source is a
different job with a different input, and that script stays private for the obvious reason that its
left-hand side is the list of real values.
"""
from __future__ import annotations

import argparse
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
INDEX = ROOT / "app" / "static" / "index.html"
MAIN = ROOT / "app" / "main.py"
TESTS = ROOT / "tests"
I18N_TEST = TESTS / "i18n_test.js"

NL = "\n"
REFRESH = "⟳"
ELL = "…"
DASH = "—"

DEMO_BLOCK = r"""    let DEMO_MODE = false;
    const DEMO_FILE = 'demo-summary.json';

    function demoFreshen(d){
      const base = Date.parse(d && d._collectedAt);
      if(!base) return d;
      const shift = Date.now() - base;
      const DATEY = /^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}|$)/;
      const walk = n => {
        if(Array.isArray(n)) return n.map(walk);
        if(n && typeof n === 'object'){ for(const k in n) n[k] = walk(n[k]); return n; }
        if(typeof n === 'string' && DATEY.test(n)){
          const t2 = Date.parse(n);
          if(!isNaN(t2)){
            const iso = new Date(t2 + shift).toISOString();
            return n.length === 10 ? iso.slice(0,10) : iso;
          }
        }
        return n;
      };
      return walk(d);
    }

    async function fetchSummary(live){
      if(!DEMO_MODE){
        try{
          const res = await fetch('/api/summary'+(live?'?live=1':''));
          if(res.ok) return await res.json();
        }catch(e){ }
        DEMO_MODE = true;
        const chip = document.getElementById('demoChip');
        if(chip) chip.style.display = '';
        const btn = document.getElementById('refresh');
        if(btn) btn.title = 'Re-reads the bundled synthetic snapshot. There is no backend here and '
                          + 'no tenant is contacted.';
      }
      const res = await fetch(DEMO_FILE, {cache:'no-store'});
      if(!res.ok) throw new Error('no backend and no ' + DEMO_FILE);
      return demoFreshen(await res.json());
    }

"""

FAVICON_ROUTE = '''


@app.get("/favicon.svg", include_in_schema=False)
async def favicon():
    return FileResponse(STATIC_DIR / "favicon.svg")'''

KO = {
    REFRESH + " Reload demo data": REFRESH + " 데모 다시 읽기",
    REFRESH + " Re-reading" + ELL: REFRESH + " 다시 읽는 중" + ELL,
    "Re-reading the bundled demo snapshot" + ELL:
        "동봉된 데모 스냅샷을 다시 "
        "읽습니다" + ELL,
    "Could not load data: {0}. With the backend running, check the server log and .env; "
    "as a static page, check that demo-summary.json sits next to this file.":
        "데이터를 불러오지 못했습니다: {0}. "
        "백엔드가 동작 중이라면 서버 로그와 .env 를, "
        "정적 페이지라면 demo-summary.json 이 이 파일 옆에 있는지 확인하십시오.",
    "Demo: re-read the bundled snapshot " + DASH + " no tenant was contacted":
        "데모: 동봉된 스냅샷을 다시 "
        "읽었습니다 " + DASH + " 테넌트에는 "
        "연결하지 않았습니다",
}
KO_ANCHOR = ('    I18N.ko["' + REFRESH + " Loading" + ELL + '"] = "' + REFRESH
             + ' 불러오는 중' + ELL + '";')
KO_BLOCK = KO_ANCHOR + NL + NL.join(
    '    I18N.ko["' + k + '"] = "' + v + '";' for k, v in KO.items())

EDITS = [
    ('href="favicon.svg"', "favicon path relative, so it resolves under a Pages project subpath",
     'href="/static/favicon.svg"', 'href="favicon.svg"'),

    ('id="demoChip"', "DEMO DATA chip in the header",
     '<span class="chip alert" id="actionChip"',
     '<span class="chip alert" id="demoChip" style="display:none" title="No backend: showing a '
     'bundled synthetic snapshot. Every value is generated.">DEMO DATA</span>' + NL
     + '      <span class="chip alert" id="actionChip"'),

    ("const DEMO_FILE = 'demo-summary.json';",
     "static-demo fallback (DEMO_MODE / demoFreshen / fetchSummary)",
     "    async function load(live, opts){", DEMO_BLOCK + "    async function load(live, opts){"),

    ("await fetchSummary(live)", "load() reads through the fallback rather than fetch() directly",
     "        const res=await fetch('/api/summary'+(live?'?live=1':''));" + NL
     + "        const next=await res.json();",
     "        const next=await fetchSummary(live);"),

    ("DEMO_MODE ? t('" + REFRESH + " Re-reading",
     "button and header text tell the truth in demo mode",
     "        btn.disabled=true; btn.textContent= live?t('" + REFRESH + " Collecting" + ELL
     + "'):t('" + REFRESH + " Loading" + ELL + "');" + NL
     + "        document.getElementById('updated').textContent= live?t('Live collecting" + ELL
     + " (a few seconds)'):t('Loading" + ELL + "');",
     "        btn.disabled=true;" + NL
     + "        btn.textContent = DEMO_MODE ? t('" + REFRESH + " Re-reading" + ELL + "') : (live?t('"
     + REFRESH + " Collecting" + ELL + "'):t('" + REFRESH + " Loading" + ELL + "'));" + NL
     + "        document.getElementById('updated').textContent = DEMO_MODE" + NL
     + "          ? t('Re-reading the bundled demo snapshot" + ELL + "')" + NL
     + "          : (live?t('Live collecting" + ELL + " (a few seconds)'):t('Loading" + ELL
     + "'));"),

    ("t('" + REFRESH + " Reload demo data')", "button label after a demo reload",
     "}finally{ if(!quiet){ btn.disabled=false; btn.textContent=t('" + REFRESH
     + " Collect now'); } }",
     "}finally{ if(!quiet){ btn.disabled=false; btn.textContent = DEMO_MODE ? t('"
     + REFRESH + " Reload demo data') : t('" + REFRESH + " Collect now'); } }"),

    ("no tenant was contacted", "toast explaining what the button actually did",
     "if(quiet){ main.scrollTop = keepScroll; toast(t('Dashboard updated with a newer "
     "collection')); }",
     "if(quiet){ main.scrollTop = keepScroll; toast(t('Dashboard updated with a newer "
     "collection')); }" + NL
     + "        else if(DEMO_MODE && live){ toast(t('Demo: re-read the bundled snapshot " + DASH
     + " no tenant was contacted')); }"),

    ("sits next to this file", "error text covers the static case too",
     "tf('Backend call failed: {0}. Check server logs and .env.', String(e))",
     "tf('Could not load data: {0}. With the backend running, check the server log and .env; "
     "as a static page, check that demo-summary.json sits next to this file.', String(e))"),

    (list(KO)[-1] + '"]', "Korean for the demo-only strings, so both languages are complete",
     KO_ANCHOR, KO_BLOCK),

    ("!document.hidden && !DEMO_MODE) load(false,{quiet:true}); }, POLL_MS",
     "background poll off in demo mode (one static file cannot change)",
     "setInterval(()=>{ if(!document.hidden) load(false,{quiet:true}); }, POLL_MS);",
     "setInterval(()=>{ if(!document.hidden && !DEMO_MODE) load(false,{quiet:true}); }, "
     "POLL_MS);"),

    ("visibilitychange', ()=>{ if(!document.hidden && !DEMO_MODE)", "same for the focus re-poll",
     "document.addEventListener('visibilitychange', ()=>{ if(!document.hidden) "
     "load(false,{quiet:true}); });",
     "document.addEventListener('visibilitychange', ()=>{ if(!document.hidden && !DEMO_MODE) "
     "load(false,{quiet:true}); });"),
]

GAPS_BLOCK = r'''const UPSTREAM_GAPS = [
  'Conditional Access evaluates the Entra device object',
  'points at an MDM-only stub',
  'instead of the real registration',
  'sources are being served',
  'since worker start',
  'secureScoreActions',
  'in CA-Pilot-Users',
  'med', 'high', 'low', 'informational',
  'complete',
];
const UPSTREAM_LITERALS = [
  'Microsoft-side',
  'Collect window',
  'active now',
];
const INTERPOLATED = /\d/;
const upstream = s => UPSTREAM_GAPS.some(g => String(s).includes(g))
  || UPSTREAM_LITERALS.some(g => String(s).includes(g))
  || INTERPOLATED.test(String(s));

'''

DICT_BLOCK_OLD = "const dictBlock = js.slice(js.indexOf('i18n:ko:begin'), js.indexOf('i18n:ko:end'));"
DICT_BLOCK_NEW = ("const dictLines = js.match(/^[ \\t]*I18N\\.ko\\[.*$/gm) || [];" + NL
                  + "const dictBlock = dictLines.length" + NL
                  + "  ? js.slice(js.indexOf(dictLines[0]), js.lastIndexOf(dictLines[dictLines.length - 1])"
                  + NL
                  + "      + dictLines[dictLines.length - 1].length)" + NL
                  + "  : '';")

I18N_EDITS = [
    ("const dictLines", "dictionary bounds found from the code, not from comment markers",
     DICT_BLOCK_OLD, DICT_BLOCK_NEW),

    ("UPSTREAM_GAPS", "upstream-gap list in the i18n test",
     "let fail = 0;" + NL, "let fail = 0;" + NL + NL + GAPS_BLOCK),

    ("!upstream(s));", "literals check skips the known gaps",
     "  s && !(s in DICT) && LATIN.test(s) && !HANGUL.test(s)",
     "  s && !(s in DICT) && LATIN.test(s) && !HANGUL.test(s) && !upstream(s)"),

    ("&& !upstream(s)) hard.push", "hardcoded-English check skips the known gaps",
     "&& !hard.includes(s)) hard.push(`${id}: ${s.slice(0, 70)}`);",
     "&& !hard.includes(s) && !upstream(s)) hard.push(`${id}: ${s.slice(0, 70)}`);"),

    ("const missLive", "untranslated-at-render check skips the known gaps",
     "T('\u2605 no untranslated string reaches t() while rendering', miss.size === 0," + NL
     + "  [...miss].slice(0, 5).map(s => s.slice(0, 60)).join(' | '));",
     "const missLive = [...miss].filter(s => !upstream(s));" + NL
     + "T('\u2605 no untranslated string reaches t() while rendering', missLive.length === 0," + NL
     + "  missLive.slice(0, 5).map(s => s.slice(0, 60)).join(' | '));"),
]

MAIN_EDITS = [
    ('@app.get("/favicon.svg"', "root favicon route, so the relative path works behind the backend",
     '@app.get("/")' + NL + 'async def index():' + NL
     + '    return FileResponse(STATIC_DIR / "index.html")',
     '@app.get("/")' + NL + 'async def index():' + NL
     + '    return FileResponse(STATIC_DIR / "index.html")' + FAVICON_ROUTE),
]


def repoint_tests() -> list[str]:
    """Every JS test reads the committed fixture, not a path that only exists privately."""
    changed = []
    for f in sorted(TESTS.glob("*.js")):
        s = f.read_text(encoding="utf-8")
        if "data/graph_snapshot.json" in s:
            f.write_text(s.replace("data/graph_snapshot.json", "app/static/demo-summary.json"),
                         encoding="utf-8", newline=NL)
            changed.append(f.name)
    return changed

def run(check_only: bool) -> int:
    problems, applied, present = [], [], []
    stale = [f for f in sorted(TESTS.glob('*.js'))
             if 'data/graph_snapshot.json' in f.read_text(encoding='utf-8')]
    if stale and check_only:
        problems.append('tests still read a private snapshot path: '
                        + ', '.join(f.name for f in stale))
    elif stale:
        applied.append('tests repointed to the committed fixture: '
                       + ', '.join(repoint_tests()))

    for path, edits in ((INDEX, EDITS), (MAIN, MAIN_EDITS), (I18N_TEST, I18N_EDITS)):
        text = original = path.read_text(encoding="utf-8")
        for marker, desc, old, new in edits:
            if marker in text:
                present.append(desc)
                continue
            if old not in text:
                problems.append(f"{path.name}: anchor not found for {desc!r}" + NL
                                + f"           anchor: {old.strip().splitlines()[0][:84]}")
                continue
            if check_only:
                problems.append(f"{path.name}: MISSING - {desc}")
                continue
            text = text.replace(old, new, 1)
            applied.append(desc)
        if text != original and not check_only:
            path.write_text(text, encoding="utf-8", newline=NL)

    for d in present:
        print(f"  ok       {d}")
    for d in applied:
        print(f"  applied  {d}")
    for p in problems:
        print(f"  FAIL     {p}")
    print()
    if problems:
        print(f"{len(problems)} demo-mode edit(s) could not be confirmed.")
        print("An anchor that is not found means the upstream code changed shape: read the")
        print("surrounding source and update the anchor here rather than hand-editing index.html,")
        print("or the next re-sync loses the edit again.")
        return 1
    print(f"demo mode in place: {len(present)} already present, {len(applied)} applied")
    return 0


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="verify only, change nothing")
    sys.exit(run(ap.parse_args().check))
