const fs = require('fs'), vm = require('vm');

const html = fs.readFileSync('app/static/index.html', 'utf8');
const js = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]).pop();
const baseSnap = JSON.parse(fs.readFileSync('app/static/demo-summary.json', 'utf8'));

let fail = 0;
const T = (name, ok, extra) => {
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${name}${extra ? '  ' + extra : ''}`);
  if (!ok) fail++;
};

const noop = () => {};
function makeEl() {
  return { _html: '', set innerHTML(v) { this._html = v; }, get innerHTML() { return this._html; },
    querySelectorAll: () => [], addEventListener: noop, appendChild: noop, setAttribute: noop,
    getAttribute: () => null, removeAttribute: noop,
    classList: { add: noop, remove: noop, toggle: noop, contains: () => false },
    style: { setProperty: noop }, textContent: '', value: '', scrollTop: 0, dataset: {},
    querySelector: () => makeEl(), focus: noop, closest: () => null, disabled: false, title: '' };
}
function boot(snap) {
  const doc = makeEl(), main = makeEl(), nav = makeEl();
  doc.documentElement = makeEl(); doc.body = makeEl(); doc.hidden = false;
  doc.getElementById = id => (id === 'main' ? main : id === 'nav' ? nav : makeEl());
  doc.querySelector = () => makeEl(); doc.querySelectorAll = () => []; doc.createElement = () => makeEl();
  const sb = {
    window: { addEventListener: noop, matchMedia: () => ({ matches: false, addEventListener: noop }) },
    document: doc, location: { hash: '', href: '', search: '' },
    localStorage: { getItem: () => null, setItem: noop },
    navigator: { language: 'en-US' }, URLSearchParams, Math,
    crypto: require('crypto').webcrypto,
    setTimeout: noop, setInterval: noop, clearInterval: noop, history: { replaceState: noop },
    fetch: () => Promise.resolve({ json: () => Promise.resolve(snap), ok: true }),
    console: { log: noop, warn: noop, error: noop },
  };
  sb.globalThis = sb;
  const ctx = vm.createContext(sb);
  vm.runInContext(js, ctx, { filename: 'app.js' });
  const g = e => vm.runInContext(e, ctx);
  g('DATA = ' + JSON.stringify(snap));
  return g;
}

const row = (user, app) => ({ user, device: 'dev-' + user, platform: '15', app,
  reasons: ['rootedDevice'], lastSync: '2026-10-08T10:00:00Z' });
function snapWith(flagged) {
  const s = JSON.parse(JSON.stringify(baseSnap));
  s._history = s._history || [];
  s.mamRegistrations = Object.assign({}, s.mamRegistrations || {}, { available: true,
    registrationCount: 3, registeredUsers: 3, targetedUsers: 3, notRegistered: 0, notRegisteredUsers: [],
    notRegisteredTruncated: 0, flagged, flaggedCount: flagged.length, staleRegistrations: 0, staleDays: 14,
    byPlatform: {}, groups: [], multiDevice: [], multiDeviceCount: 0, replacedCount: 0, findings: [] });
  return s;
}
const flaggedTable = out => (out.match(/<table(?:(?!<\/table>).)*<th>Flagged<\/th>(?:(?!<\/table>).)*<\/table>/s) || [''])[0];

console.log('\n=== ① 옛 스냅샷 — app 이 객체 ===');
let g = boot(snapWith([
  row('ios', { '@odata.type': '#microsoft.graph.iosMobileAppIdentifier', bundleId: 'com.microsoft.Office.Outlook' }),
  row('and', { '@odata.type': '#microsoft.graph.androidMobileAppIdentifier', packageId: 'com.microsoft.teams' }),
  row('win', { '@odata.type': '#microsoft.graph.windowsAppIdentifier', windowsAppId: 'com.microsoft.edge' }),
  row('bare', { '@odata.type': '#microsoft.graph.iosMobileAppIdentifier' }),
]));
g("LANG='en'");
let out = g('mamPanel(DATA.mamRegistrations)');
let tbl = flaggedTable(out);
T('측정이 돌았다 — 플래그 표가 렌더됨 (4행)', (tbl.match(/rootedDevice/g) || []).length === 4, `${tbl.length} chars`);
T('★ "[object Object]" 없음', !/\[object Object\]/.test(out));
T('iOS → bundleId', tbl.includes('>com.microsoft.Office.Outlook<'));
T('Android → packageId', tbl.includes('>com.microsoft.teams<'));
T('Windows → windowsAppId', tbl.includes('>com.microsoft.edge<'));
T('id 없는 객체 → 짧은 타입명', tbl.includes('>iosMobileAppIdentifier<'));

console.log('\n=== ② 새 스냅샷 — app 이 문자열 / 없음 ===');
g = boot(snapWith([row('new', 'com.microsoft.Office.Word'), row('none', null)]));
g("LANG='en'");
out = g('mamPanel(DATA.mamRegistrations)');
tbl = flaggedTable(out);
T('문자열은 그대로', tbl.includes('>com.microsoft.Office.Word<'));
T('null → 빈 칸 ("null" 아님)', !/>null</.test(tbl) && (tbl.match(/rootedDevice/g) || []).length === 2);

console.log('\n=== ② 한국어 화면도 같은 값 ===');
g = boot(snapWith([row('ios', { bundleId: 'com.microsoft.Office.Outlook' })]));
g("LANG='ko'");
out = g('mamPanel(DATA.mamRegistrations)');
T('KO — "[object Object]" 없음 · id 보임', !/\[object Object\]/.test(out) && out.includes('>com.microsoft.Office.Outlook<'));

console.log('\n=== ③ 음성 대조 — 옛 렌더 규칙이면 잡힌다 ===');
const oldRule = g("esc({bundleId:'com.microsoft.Office.Outlook'}||'')");
T('옛 규칙 esc(f.app) 는 [object Object] 를 냈다', /\[object Object\]/.test(oldRule), oldRule);

console.log(fail ? `\n${fail} FAILED` : '\nALL OK');
process.exit(fail ? 1 : 0);
