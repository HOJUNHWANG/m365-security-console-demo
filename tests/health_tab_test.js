const fs = require('fs'), vm = require('vm'), http = require('http');

const html = fs.readFileSync('app/static/index.html', 'utf8');
const js = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]).pop();

const noop = () => {};
const el = () => ({
  set innerHTML(v) {}, get innerHTML() { return ''; }, querySelectorAll: () => [],
  addEventListener: noop, appendChild: noop, setAttribute: noop, getAttribute: () => null,
  removeAttribute: noop, classList: { add: noop, remove: noop, toggle: noop, contains: () => false },
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
const render = (payload) => {
  vm.runInContext('globalThis.__p = ' + JSON.stringify(payload), ctx);
  return vm.runInContext('tabHealth(globalThis.__p)', ctx);
};

let fails = [];
const check = (name, cond) => { console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${name}`); if (!cond) fails.push(name); };

check('no _dataHealth -> friendly message', /reload the page/.test(render({})));
check('empty _dataHealth renders', render({ _dataHealth: {} }).includes('Sign-in Window Coverage'));
check('null reason does not print "null"',
  !render({ _dataHealth: { sources: [{ key: 'x', state: 'down', reason: null, bytes: 10 }] } })
    .includes('>null<'));
check('missing counters render as em dash',
  render({ _dataHealth: { graph: {}, collection: {}, signinWindow: {} } }).includes('—'));

const xss = render({ _dataHealth: { sources: [
  { key: 'a', state: 'down', reason: '<img src=x onerror=alert(1)>', bytes: 5 }] } });
check('reason is HTML-escaped', !xss.includes('<img') && xss.includes('&lt;img'));

const ep = render({ _dataHealth: { graph: { endpoints: [
  { endpoint: '/auditLogs/signIns', n: 4, errors: 1, errRate: 25, avgSec: 62.8, maxSec: 63 }] } } });
check('endpoint row renders', ep.includes('/auditLogs/signIns') && ep.includes('62.8s'));
check('endpoint shows its own failure rate', ep.includes('1 (25%)'));

const oneBad = render({ _dataHealth: { graph: {
  requests: 417, throttled: 3,
  worstEndpoint: { endpoint: '/auditLogs/signIns', n: 3, errors: 3, errRate: 100 },
  endpoints: [
    { endpoint: '/drives/{drive}/items/{token}/permissions', n: 112, errors: 0, errRate: 0, avgSec: 1.9, maxSec: 3.1 },
    { endpoint: '/auditLogs/signIns', n: 3, errors: 3, errRate: 100, avgSec: 68, maxSec: 68 }] } } });
check('★ a 100%-failing endpoint is called out explicitly',
  oneBad.includes('3 of 3 attempts (100%)'));
check('★ the callout names the endpoint', oneBad.includes('/auditLogs/signIns'));
check('low-rate endpoints get no callout',
  !render({ _dataHealth: { graph: {
    worstEndpoint: { endpoint: '/x', n: 100, errors: 1, errRate: 1 }, endpoints: [] } } })
    .includes('Judge an endpoint by'));

const backingOff = render({ _dataHealth: { signinWindow: {
  complete: false, percent: 34, heldDays: 2.39, targetDays: 7, records: 1240,
  fruitlessAttempts: 3, nextAttemptInMin: 80,
  pageSize: 250, pageDelaySec: 15, maxPagesPerCycle: 6, refreshMin: 20, coldRefreshMin: 60,
  staleMaxMin: 180, mode: 'backfill' } } });
check('★ backing off says so, with the wait and the reason',
  /backing off/i.test(backingOff) && backingOff.includes('80 min')
  && backingOff.includes('3'));
check('backing off explains it resumes on its own', /resumes on its own/i.test(backingOff));
const notBackingOff = render({ _dataHealth: { signinWindow: {
  complete: false, percent: 34, heldDays: 2.39, targetDays: 7, records: 1240,
  fruitlessAttempts: 0, nextAttemptInMin: null, mode: 'backfill' } } });
check('not backing off keeps the ordinary backfill note',
  /one 429/.test(notBackingOff) && !/backing off/i.test(notBackingOff));

const partial = render({ _dataHealth: { signinWindow: {
  complete: false, percent: 18, heldDays: 1.28, targetDays: 7, records: 747,
  pageSize: 250, pageDelaySec: 15, maxPagesPerCycle: 6, refreshMin: 20, coldRefreshMin: 60,
  staleMaxMin: 180, mode: 'backfill' } } });
check('incomplete coverage says sources are held back',
  /deliberately held back/.test(partial) && partial.includes('1.28'));
const full = render({ _dataHealth: { signinWindow: {
  complete: true, percent: 100, heldDays: 7, targetDays: 7, records: 2460,
  pageSize: 250, pageDelaySec: 15, maxPagesPerCycle: 6, refreshMin: 20, coldRefreshMin: 60,
  staleMaxMin: 180, mode: 'delta' } } });
check('complete coverage says sources are served', /being served/.test(full));

http.get('http://127.0.0.1:8000/api/health', (res) => {
  let body = '';
  res.on('data', d => body += d);
  res.on('end', () => {
    let out = '';
    try {
      out = render({ _dataHealth: JSON.parse(body) });
      check('live payload renders', out.length > 2000);
      check('live payload has all six panels',
        ['Sign-in Window Coverage', 'Source Status', 'Graph Outcomes', 'Endpoints',
         'Recent Graph Errors', 'Collection History'].every(t => out.includes(t)));
      check('no literal undefined in the output', !out.includes('undefined'));
      console.log(`  (live render: ${(out.length / 1024).toFixed(1)} KB)`);
    } catch (e) {
      check('live payload renders', false);
      console.log('    ' + e.message);
    }
    console.log();
    if (fails.length) { console.log(`${fails.length} check(s) FAILED: ${fails.join(', ')}`); process.exit(1); }
    console.log('all checks passed');
  });
}).on('error', () => {
  console.log('  skip live payload check (server not reachable on :8000)');
  console.log();
  if (fails.length) { console.log(`${fails.length} check(s) FAILED: ${fails.join(', ')}`); process.exit(1); }
  console.log('all checks passed');
});
