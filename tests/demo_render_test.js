// The published demo is a static page: whatever the fixture renders to is what a visitor sees, with
// no backend to fall back on and no operator watching a log. So this test renders every tab from the
// committed fixture and fails on the ways a synthetic snapshot degrades quietly.
//
// It checks three things the sanitisation itself cannot:
//   1. no source is missing or unavailable, which would show a visitor an empty card
//   2. no rendered cell says "undefined", "NaN" or "[object Object]" - the signature of a generated
//      value that reached the DOM in the wrong shape
//   3. every tab renders something substantial, so a broken panel cannot hide behind a heading
//
//     node tests/demo_render_test.js
const fs = require('fs'), vm = require('vm');
const html = fs.readFileSync('app/static/index.html', 'utf8');
const js = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]).pop();
const snap = JSON.parse(fs.readFileSync('app/static/demo-summary.json', 'utf8'));

const noop = () => {};
function makeEl() {
  return {
    _html: '', hidden: [],
    set innerHTML(v) { this._html = v; },
    get innerHTML() { return this._html; },
    querySelectorAll(sel) {
      if (sel !== '[data-pt]') return [];
      const self = this;
      return [...this._html.matchAll(/data-pt="([^"]*)"/g)].map(m => ({
        getAttribute: () => m[1],
        style: { set display(v) { self.hidden.push(m[1]); }, get display() { return ''; } },
      }));
    },
    addEventListener: noop, appendChild: noop, setAttribute: noop, getAttribute: () => null,
    removeAttribute: noop, classList: { add: noop, remove: noop, toggle: noop, contains: () => false },
    style: { setProperty: noop }, textContent: '', value: '', scrollTop: 0, dataset: {},
    querySelector: () => makeEl(), focus: noop, closest: () => null,
  };
}
const main = makeEl(), nav = makeEl();
const doc = makeEl();
doc.documentElement = makeEl(); doc.body = makeEl();
doc.getElementById = id => (id === 'main' ? main : id === 'nav' ? nav : makeEl());
doc.querySelector = () => makeEl();
doc.querySelectorAll = () => [];
doc.createElement = () => makeEl();
const sb = {
  window: { addEventListener: noop, matchMedia: () => ({ matches: false, addEventListener: noop }) },
  document: doc, location: { hash: '', href: '' },
  localStorage: { getItem: () => null, setItem: noop },
  setTimeout: noop, setInterval: noop, clearInterval: noop, history: { replaceState: noop },
  fetch: () => Promise.resolve({ json: () => Promise.resolve(snap), ok: true }), console,
};
sb.globalThis = sb;
const ctx = vm.createContext(sb);
vm.runInContext(js, ctx, { filename: 'app.js' });
const g = expr => vm.runInContext(expr, ctx);
const setActive = id => vm.runInContext(`active = ${JSON.stringify(id)}`, ctx);
g('DATA = ' + JSON.stringify(snap));

let fail = 0;
const T = (name, ok, extra) => {
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${name}${extra ? '  ' + extra : ''}`);
  if (!ok) fail++;
};

// ---------------------------------------------------------------------------------------------
// 1) Every source present and available.
// ---------------------------------------------------------------------------------------------
const sources = Object.entries(snap).filter(([k, v]) =>
  !k.startsWith('_') && v && typeof v === 'object' && 'available' in v);
const down = sources.filter(([, v]) => !v.available).map(([k]) => k);
T('fixture carries every source', sources.length >= 20, `${sources.length} sources`);
T('no source is unavailable', down.length === 0, down.join(', ') || 'all available');
T('fixture has a collection timestamp', typeof snap._collectedAt === 'string');
T('fixture has trend history', Array.isArray(snap._history) && snap._history.length > 20,
  `${(snap._history || []).length} points`);

// ---------------------------------------------------------------------------------------------
// 2) Render every sub-tab and look for the tells of a bad generated value.
// ---------------------------------------------------------------------------------------------
const ids = [];
for (const p of g('PARENTS')) {
  const kids = p.children ? p.children.map(c => c.id) : [p.id];
  for (const id of kids) ids.push(id);
}

const BAD = /undefined|NaN|\[object Object\]|Infinity/;
const tiny = [], dirty = [];
console.log('\n  rendered:');
for (const id of ids) {
  setActive(id);
  main.hidden = [];
  let out = '';
  try {
    ctx.renderMain();
    out = main.innerHTML;
  } catch (e) {
    dirty.push(`${id} THREW ${e.message}`);
    continue;
  }
  if (out.length < 400) tiny.push(`${id} (${out.length} B)`);
  // Strip the ids and class names the markup legitimately contains before looking for the tells.
  const text = out.replace(/<[^>]*>/g, ' ');
  const hit = text.match(BAD);
  if (hit) {
    const at = text.indexOf(hit[0]);
    dirty.push(`${id}: "${text.slice(Math.max(0, at - 45), at + 25).trim()}"`);
  }
  console.log(`    ${id.padEnd(20)} ${String(out.length).padStart(7)} B`);
}
console.log('');
T('every sub-tab renders', dirty.filter(d => d.includes('THREW')).length === 0,
  dirty.filter(d => d.includes('THREW')).join('; '));
T('no sub-tab renders empty', tiny.length === 0, tiny.join(', ') || `${ids.length} tabs`);
T('no undefined / NaN / [object Object] on any tab', dirty.length === 0,
  dirty.slice(0, 6).join('  |  '));

// ---------------------------------------------------------------------------------------------
// 3) The demo must look alive: action items and attention badges have to derive from the fixture,
//    otherwise the whole point of the dashboard is invisible to a visitor.
// ---------------------------------------------------------------------------------------------
const actions = g('buildActions')(snap);
const sev = actions.map(a => a[0]);
T('fixture produces action items', actions.length > 0, `${actions.length} items`);
T('action items span severities', new Set(sev).size >= 2, [...new Set(sev)].join('/'));
T('every action links to a real tab', actions.every(a => g('_validTab')(a[2])),
  actions.filter(a => !g('_validTab')(a[2])).map(a => a[2]).join(',') || 'all valid');

setActive('overview');
ctx.renderNav();
T('nav renders attention badges', /badge|chip|dot/.test(nav.innerHTML));

console.log('');
if (fail) { console.log(`${fail} check(s) FAILED`); process.exit(1); }
console.log('all checks passed');
