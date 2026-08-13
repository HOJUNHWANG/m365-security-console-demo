// A grid2 whose sibling panel was filtered out by sub-tab routing must not leave the survivor in a
// half-width column. This was visible as Recent Failed Sign-ins rendering at ~50% width with its
// Error column behind a horizontal scrollbar.
//
// The fix is CSS (`.grid2 > :only-child { grid-column: 1 / -1 }`) rather than nine JS rewrites, so the
// test asserts two things: the rule exists, and sub-tab routing really does produce single-child
// grid2 wrappers (i.e. the rule is load-bearing, not decorative).
const fs = require('fs'), vm = require('vm');

const html = fs.readFileSync('app/static/index.html', 'utf8');
const js = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]).pop();
const snap = JSON.parse(fs.readFileSync('app/static/demo-summary.json', 'utf8'));
snap._history = [];
snap._dataHealth = { sources: [], signinWindow: {}, collection: {}, graph: {} };

let fails = [];
const check = (name, cond, extra) => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${name}${extra ? '  ' + extra : ''}`);
  if (!cond) fails.push(name);
};

// --- the rule must be present -------------------------------------------------------------------
check('.grid2 is a two-column grid', /\.grid2\s*\{[^}]*grid-template-columns:\s*1fr 1fr/.test(html));
check('a lone child spans both columns',
  /\.grid2\s*>\s*:only-child\s*\{\s*grid-column:\s*1\s*\/\s*-1/.test(html));
check('no leftover pair() helper', !/function pair\(/.test(js));

// --- and it must actually be needed: render every sub-tab and look for single-child grid2 ---------
const noop = () => {};
function makeEl() {
  return {
    _html: '',
    set innerHTML(v) { this._html = v; },
    get innerHTML() { return this._html; },
    querySelectorAll: () => [], addEventListener: noop, appendChild: noop, setAttribute: noop,
    getAttribute: () => null, removeAttribute: noop,
    classList: { add: noop, remove: noop, toggle: noop, contains: () => false },
    style: { setProperty: noop }, textContent: '', value: '', scrollTop: 0, dataset: {},
    querySelector: () => makeEl(), focus: noop, closest: () => null,
  };
}
const main = makeEl(), nav = makeEl(), doc = makeEl();
doc.documentElement = makeEl(); doc.body = makeEl();
doc.getElementById = id => (id === 'main' ? main : id === 'nav' ? nav : makeEl());
doc.querySelector = () => makeEl(); doc.querySelectorAll = () => []; doc.createElement = () => makeEl();
const sb = {
  window: { addEventListener: noop, matchMedia: () => ({ matches: false, addEventListener: noop }) },
  document: doc, location: { hash: '', href: '' },
  localStorage: { getItem: () => null, setItem: noop },
  setTimeout: noop, setInterval: noop, clearInterval: noop, history: { replaceState: noop },
  fetch: () => Promise.resolve({ json: () => Promise.resolve(snap), ok: true }), console,
};
sb.globalThis = sb;
const ctx = vm.createContext(sb);
vm.runInContext(js, ctx);
vm.runInContext('DATA = ' + JSON.stringify(snap), ctx);

// --- and it must be load-bearing: render every sub-tab the way renderMain does -------------------
// Replicating renderMain's _sub setup exactly (mine/claimed/isFirst) matters - an approximation would
// render everything and find nothing, which is how the first version of this test passed vacuously.
const ids = vm.runInContext(
  'PARENTS.flatMap(t => t.children ? t.children.map(c => c.id) : [t.id])', ctx);

function renderSub(id) {
  return vm.runInContext(`(function(){
    active = ${JSON.stringify(id)};
    const kids = childrenOf(active);
    _sub = kids.length ? {
      mine:    new Set((childOf(active)||{}).titles || []),
      claimed: new Set(kids.flatMap(c=>c.titles||[])),
      isFirst: kids[0] && kids[0].id === active,
    } : null;
    try { return VIEWS[parentOf(active)](DATA) || ''; } finally { _sub = null; }
  })()`, ctx);
}

// Count panels inside each grid2 wrapper by scanning with depth, since panels contain nested divs.
function gridChildCounts(out) {
  const counts = [];
  let idx = 0;
  while (true) {
    const open = out.indexOf('<div class="grid2">', idx);
    if (open < 0) return counts;
    let i = open + '<div class="grid2">'.length, depth = 1, panels = 0;
    while (i < out.length && depth > 0) {
      if (out.startsWith('<div', i)) {
        if (out.startsWith('<div class="panel"', i) && depth === 1) panels++;
        depth++; i += 4;
      } else if (out.startsWith('</div>', i)) { depth--; i += 6; }
      else i++;
    }
    counts.push(panels);
    idx = i;
  }
}

let singles = 0, totals = 0, rendered = 0, examples = [];
for (const id of ids) {
  let out = '';
  try { out = renderSub(id); } catch (e) { console.log(`    (render failed for ${id}: ${e.message})`); continue; }
  if (out) rendered++;
  for (const n of gridChildCounts(out)) {
    totals++;
    if (n === 1) { singles++; examples.push(id); }
  }
}
console.log(`  (rendered ${rendered}/${ids.length} sub-tabs, found ${totals} grid2 wrapper(s))`);
check('the harness actually rendered the tabs', rendered >= ids.length - 2, `${rendered}/${ids.length}`);
check('grid2 wrappers exist to be affected', totals > 0, `${totals}`);
check('★ sub-tab routing does produce single-child grid2 wrappers', singles > 0,
  singles ? `${singles}, e.g. ${[...new Set(examples)].slice(0, 3).join(', ')}`
          : 'none found - the CSS rule would be dead code, investigate');

console.log();
if (fails.length) { console.log(`${fails.length} check(s) FAILED: ${fails.join(', ')}`); process.exit(1); }
console.log('all checks passed');
