const fs = require('fs'), vm = require('vm');
const html = fs.readFileSync('app/static/index.html', 'utf8');
const js = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]).pop();
const snap = JSON.parse(fs.readFileSync('app/static/demo-summary.json', 'utf8'));
snap._history = [];

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
        getAttribute: () => m[1].replace(/&amp;/g, '&').replace(/&#39;/g, "'").replace(/&quot;/g, '"'),
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
  crypto: require('crypto').webcrypto,
};
sb.globalThis = sb;
const ctx = vm.createContext(sb);
vm.runInContext(js, ctx, { filename: 'app.js' });
const g = expr => vm.runInContext(expr, ctx);
const setActive = id => vm.runInContext(`active = ${JSON.stringify(id)}`, ctx);
g('DATA = ' + JSON.stringify(snap));

let fail = 0;
const T = (name, ok, extra) => { console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${name}${extra ? '  ' + extra : ''}`); if (!ok) fail++; };

const parents = g('PARENTS').map(t => t.id);
const children = g('PARENTS').flatMap(t => (t.children || []).map(c => c.id));
T('parents', parents.length === 17, `${parents.length}`);
T('every parent has a view', parents.every(id => typeof g('VIEWS')[id] === 'function'),
  parents.filter(id => typeof g('VIEWS')[id] !== 'function').join(',') || 'all present');
T('every parent has a title', parents.every(id => Array.isArray(g('TITLES')[id])),
  parents.filter(id => !Array.isArray(g('TITLES')[id])).join(',') || 'all present');
T('children', children.length > 0, `${children.length}: ${children.filter(c => c.includes('.')).join(', ')}`);
T('every child id valid', children.every(g('_validTab')));
T('every parent id valid', parents.every(g('_validTab')));
T('unknown id rejected', !g('_validTab')('nope.x'));

console.log('\n  sub-tab visible panels / bytes:');
const allIds = [];
for (const p of g('PARENTS')) {
  const kids = p.children ? p.children.map(c => c.id) : [p.id];
  for (const id of kids) allIds.push(id);
}
const coverage = {};
for (const id of allIds) {
  setActive(id);
  main.hidden = [];
  ctx.renderMain();
  const total = [...main.innerHTML.matchAll(/data-pt="([^"]*)"/g)].map(m => m[1]);
  const shown = total.filter(t => !main.hidden.includes(t));
  const bytes = main.innerHTML.length;
  coverage[g('parentOf')(id)] = coverage[g('parentOf')(id)] || { all: new Set(total), seen: new Set() };
  shown.forEach(t => coverage[g('parentOf')(id)].seen.add(t));
  const flag = bytes > 120000 ? '  <-- still large' : '';
  console.log(`    ${id.padEnd(20)} ${String(shown.length).padStart(2)}/${String(total.length).padStart(2)} panels  ${String(bytes).padStart(7)} B${flag}`);
}

console.log('');
for (const [pid, c] of Object.entries(coverage)) {
  const missing = [...c.all].filter(t => !c.seen.has(t));
  T(`${pid}: every panel reachable`, missing.length === 0, missing.length ? 'orphaned: ' + missing.join(' | ') : '');
}

for (const p of g('PARENTS').filter(t => t.children)) {
  const seen = {};
  let dup = [];
  for (const c of p.children) {
    setActive(c.id);
    main.hidden = [];
    ctx.renderMain();
    const total = [...main.innerHTML.matchAll(/data-pt="([^"]*)"/g)].map(m => m[1]);
    total.filter(t => !main.hidden.includes(t)).forEach(t => {
      if (seen[t]) dup.push(`${t} (${seen[t]} + ${c.id})`); else seen[t] = c.id;
    });
  }
  T(`${p.id}: no panel in two sub-tabs`, dup.length === 0, dup.join('; '));
}

setActive('hunting.who');
ctx.renderNav();
T('nav has nav-group', nav.innerHTML.includes('nav-group'));
T('nav group open for active child', nav.innerHTML.includes('nav-group open'));
T('nav has caret', nav.innerHTML.includes('caret'));
T('child label rendered', nav.innerHTML.includes('Senders &amp; Targets') || nav.innerHTML.includes('Senders & Targets'));

T('legacy id appcreds still routes', g('_validTab')('appcreds'));
T('alias resolves', g('resolveTab')('appcreds') === 'roles.creds');

setActive('mailsec.flow');
ctx.renderMain();
T('heading is parent > child', /Mail Security[^<]*›\s*Quarantine/.test(main.innerHTML));
setActive('overview');
ctx.renderMain();
T('parent-only heading unchanged', main.innerHTML.includes('>Overview<'));

console.log(fail ? `\n${fail} FAILURE(S)` : '\nall checks passed');
process.exit(fail ? 1 : 0);
