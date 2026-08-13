// The stale/carried banner only renders when a collection has already failed, so it is exactly the
// code that never gets exercised by looking at a healthy dashboard. On 2026-08-05 three tabs went
// blank for a morning; this banner is what replaces "blank" with "here is the data and how old it is",
// and a banner that throws or renders empty would silently restore the old behaviour.
const fs = require('fs'), vm = require('vm');
const html = fs.readFileSync('app/static/index.html', 'utf8');
const js = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]).pop();

const noop = () => {};
const el = () => ({
  set innerHTML(v) {}, get innerHTML() { return ''; },
  querySelectorAll: () => [], addEventListener: noop, appendChild: noop, setAttribute: noop,
  getAttribute: () => null, removeAttribute: noop,
  classList: { add: noop, remove: noop, toggle: noop, contains: () => false },
  style: { setProperty: noop }, textContent: '', value: '', dataset: {},
  querySelector: () => el(), closest: () => null, focus: noop,
});
const doc = el();
doc.documentElement = el(); doc.body = el();
doc.getElementById = () => el(); doc.querySelector = () => el();
doc.querySelectorAll = () => []; doc.createElement = () => el();
const sb = {
  window: { addEventListener: noop, matchMedia: () => ({ matches: false, addEventListener: noop }) },
  document: doc, location: { hash: '', href: '' },
  localStorage: { getItem: () => null, setItem: noop },
  setTimeout: noop, setInterval: noop, clearInterval: noop, history: { replaceState: noop },
  fetch: () => Promise.resolve({ json: () => Promise.resolve({}), ok: true }), console,
};
sb.globalThis = sb;
const ctx = vm.createContext(sb);
vm.runInContext(js, ctx);
// staleNote/fmtAge are lexical in the module script, so they must be reached through runInContext
// rather than off the sandbox object.
const call = (expr) => vm.runInContext(expr, ctx);

let fails = [];
const check = (name, cond) => { console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${name}`); if (!cond) fails.push(name); };

// --- healthy source: no banner at all ------------------------------------------------------------
check('fresh source renders nothing', call('staleNote({available:true})') === '');
check('signinData.stale=false renders nothing',
  call('staleNote({available:true, signinData:{stale:false, ageMin:12}})') === '');
check('undefined source renders nothing', call('staleNote(undefined)') === '');

// --- carried source ------------------------------------------------------------------------------
const carried = call('staleNote({available:true, carried:{ageMin:47, reason:"GraphThrottled: x"}})');
check('carried renders the banner class', carried.includes('stale-banner'));
check('carried states the age', carried.includes('47 min'));
check('carried carries the reason through', carried.includes('GraphThrottled'));

// Hours, not 200 minutes - the age has to be readable at a glance to be acted on. This also pins the
// bug that shipped first: a second local fmtAge() was shadowed by the page's own (later) declaration,
// and since that one already ends in "ago", the banner read "3h 20m ago ago".
const hours = call('staleNote({available:true, carried:{ageMin:200, reason:null}})');
check('ages past an hour are shown in hours', hours.includes('3h 20m ago') && !hours.includes('200'));
check('the age is not doubled ("ago ago")', !/ago\s+ago/.test(hours));
check('a null reason does not print "null"', !hours.includes('null'));

// --- the reason is attacker-controlled text in principle; it must be escaped ---------------------
const xss = call('staleNote({available:true, carried:{ageMin:5, reason:"<img src=x onerror=1>"}})');
check('reason is HTML-escaped', !xss.includes('<img') && xss.includes('&lt;img'));

// --- shared sign-in pull fell back ---------------------------------------------------------------
const stale = call('staleNote({available:true, signinData:{stale:true, ageMin:90}})');
check('stale sign-in pull renders the banner', stale.includes('stale-banner'));
check('stale sign-in pull states the age', stale.includes('1h 30m ago'));

// planned reuse inside MIN_REFRESH_MIN is NOT a warning - flagging normal operation makes the
// banner wallpaper, and then the real one goes unread
check('planned reuse renders nothing',
  call('staleNote({available:true, signinData:{stale:false, reused:true, ageMin:35}})') === '');

// --- carried wins over signinData so the tab shows one banner, not two ---------------------------
const both = call('staleNote({available:true, carried:{ageMin:10, reason:"r"}, signinData:{stale:true, ageMin:99}})');
check('carried takes precedence', both.includes('10 min') && !both.includes('99'));
check('only one banner element', (both.match(/stale-banner/g) || []).length === 1);

// --- the CSS the banner depends on must exist ----------------------------------------------------
check('.stale-banner is styled', /\.stale-banner\s*\{/.test(html));

// --- the header chip must not count a carried source as healthy ---------------------------------
// Same trap as the collect log: carried sources have available:true, so a naive count reports
// "21/21 sources" during an outage and the chip goes quiet exactly when it is being looked at.
const mk = (n, extra) => Object.fromEntries(
  Array.from({ length: n }, (_, i) => [`src${i}`, { available: true }]).concat(extra || []));
let h = call(`sourceHealth(${JSON.stringify(mk(3))})`);
check('all healthy -> ok equals total', h.total === 3 && h.ok === 3 && h.down.length === 0);

h = call(`sourceHealth(${JSON.stringify(mk(2, [['bad', { available: false, reason: 'GraphThrottled: x' }]]))})`);
check('a down source is counted down', h.total === 3 && h.ok === 2 && h.down.length === 1);

h = call(`sourceHealth(${JSON.stringify(mk(2, [['old', { available: true, carried: { ageMin: 42, reason: 'GraphThrottled: x' } }]]))})`);
check('a carried source is NOT counted as ok', h.ok === 2 && h.total === 3);
check('a carried source is listed as carried', h.carried.length === 1 && h.carried[0].age === 42);
check('a carried source is not listed as down', h.down.length === 0);

// meta keys and non-source values must not inflate the total
h = call(`sourceHealth(${JSON.stringify({ _collectedAt: 'x', _history: [1, 2], a: { available: true }, note: 'plain' })})`);
check('underscore and non-source keys are ignored', h.total === 1 && h.ok === 1);

console.log();
if (fails.length) { console.log(`${fails.length} check(s) FAILED: ${fails.join(', ')}`); process.exit(1); }
console.log('all checks passed');
