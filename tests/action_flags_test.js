const fs = require('fs'), vm = require('vm');

const html = fs.readFileSync('app/static/index.html', 'utf8');
const js = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]).pop();

let fail = 0;
const T = (name, ok, extra) => {
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${name}${extra ? '  ' + extra : ''}`);
  if (!ok) fail++;
};

const noop = () => {};
function makeEl() {
  return {
    _html: '', attrs: {},
    set innerHTML(v) { this._html = v; }, get innerHTML() { return this._html; },
    querySelectorAll: () => [], addEventListener: noop, appendChild: noop,
    setAttribute(k, v) { this.attrs[k] = v; }, getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; },
    removeAttribute(k) { delete this.attrs[k]; },
    classList: { add: noop, remove: noop, toggle: noop, contains: () => false },
    style: { setProperty: noop }, textContent: '', value: '', scrollTop: 0, dataset: {},
    querySelector: () => makeEl(), focus: noop, closest: () => null, disabled: false, title: '',
  };
}
const main = makeEl(), doc = makeEl();
doc.documentElement = makeEl(); doc.body = makeEl(); doc.hidden = false;
const els = { main };
doc.getElementById = id => els[id] || (els[id] = makeEl());
doc.querySelector = () => null; doc.querySelectorAll = () => []; doc.createElement = () => makeEl();
const store = {};
const sb = {
  window: { addEventListener: noop, matchMedia: () => ({ matches: false, addEventListener: noop }) },
  document: doc, location: { hash: '', href: '', search: '' },
  localStorage: { getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); } },
  navigator: { language: 'en-US' }, URLSearchParams, Math, crypto: require('crypto').webcrypto,
  setTimeout: noop, setInterval: noop, clearInterval: noop, history: { replaceState: noop },
  fetch: () => new Promise(noop), console: { log: noop, warn: noop, error: noop },
};
sb.globalThis = sb;
const ctx = vm.createContext(sb);
vm.runInContext(js, ctx, { filename: 'app.js' });
const g = e => vm.runInContext(e, ctx);

console.log('\n=== ① 모든 할 일 항목의 카드 제목이 실제 카드다 ===');
const s = js.indexOf('function buildActions(D){'), e = js.indexOf('/* Per-tab attention counts');
const body = js.slice(s, e);
const pushes = [...body.matchAll(/a\.push\(\[([\s\S]*?)\]\);/g)].map(m => m[1]);
const titles = new Set([...html.matchAll(/panel\(\s*'([^']+)'/g)].map(m => m[1]));
const tagged = pushes.map(p => (p.match(/,\s*'([a-z.]+)'\s*,\s*'([^']+)'\s*$/) || [])[2]);
const untagged = pushes.filter((p, i) => !tagged[i] && !/running OLD code/.test(p));
T(`★ 항목 ${pushes.length}개 중 카드 없는 것 = 오래된 코드 경고 1개뿐`, untagged.length === 0,
  untagged.map(x => x.slice(0, 60)).join(' | '));
const missing = [...new Set(tagged.filter(x => x && !titles.has(x)))];
T('★ 카드 제목이 전부 panel(\'…\') 로 존재 (이름 바뀌면 여기서 걸림)', missing.length === 0, missing.join(', '));

console.log('\n=== ② 칠하는 기준 ===');
const D = {
  _collectedAt: '2026-11-09T19:00:00Z',
  riskySignins: { available: true, riskSignalHigh: 3, failed: 183, failRate: 7.6, windowDays: 7, caFailedCount: 25 },
  securityIncidents: { available: true, activeCount: 0, incidents: [] },
  sharepointSharing: { available: true, anonymousLinksEnabled: true },
  accountSummary: { available: true, disabled: 26, guestsPending: 0 },
};
g('DATA = ' + JSON.stringify(D));
const f = g('flagMap(DATA)');
T('높음 → High-signal Sign-in Events 빨강', f['High-signal Sign-in Events']?.sev === 'high');
T('주의 → Conditional Access Failures 노랑', f['Conditional Access Failures']?.sev === 'med');
T('★ 낮음(실패 로그인 7.6%) · 정보는 안 칠함', !f['Top Failed Sign-in Users'] && !f['Account Summary']);
T('활성 인시던트 0 이면 표시 없음', !f['Security Incidents']);
const D2 = Object.assign({}, D, { exchangeEop: undefined, senderVolume: { available: true, warnPct: 80, counts: { blocked: 1, high: 1, warn: 0 } } });
const f2 = g(`flagMap(${JSON.stringify(D2)})`);
T('같은 카드에 높음+주의 → 빨강 · 문장 2개', f2['Daily Sending Limit']?.sev === 'high' && f2['Daily Sending Limit'].items.length === 2);
T('데이터 오기 전에는 아무것도 안 칠함', Object.keys(g('flagMap({})')).length === 0);

console.log('\n=== ③ 링크 = 카드를 가진 하위 탭 ===');
T('★ CA 실패 → ca.eval', g("actDest('ca','Conditional Access Failures')") === 'ca.eval');
T('레거시 인증 → ca.exposure', g("actDest('ca','Legacy Authentication')") === 'ca.exposure');
T('하위 탭이 안 가진 카드 → 원래 탭', g("actDest('signins','High-signal Sign-in Events')") === 'signins');
T('카드 없음 → 원래 탭', g("actDest('health')") === 'health');

console.log('\n=== ④ 실제 렌더 ===');
g("LANG='en'");
g("active='ca.eval'"); ctx.renderMain();
const out = main.innerHTML;
const card = (out.match(/<div class="panel[^"]*" data-pt="Conditional Access Failures">[\s\S]*?<div class="panel-b">([\s\S]{0,400})/) || []);
T('★ CA 실패 카드에 flag-med 클래스', /class="panel[^"]*flag-med[^"]*" data-pt="Conditional Access Failures"/.test(out));
T('  ↳ 제목 아래 할 일 문장', /flag-why/.test(card[1] || '') && /Conditional Access failure/.test(card[1] || ''));
T('  ↳ 다른 카드는 안 칠함', !/flag-[a-z]+" data-pt="Report-only Impact"/.test(out));
g("setUi('v2')"); g("_collapsed = new Set(['Conditional Access Failures','Device CA Blocks — who cannot work right now'])");
g("active='ca.eval'"); ctx.renderMain();
T('대조: 표시 없는 접힌 카드는 접힌 채', /class="panel collapsed" data-pt="Device CA Blocks — who cannot work right now"/.test(main.innerHTML));
T('★ 표시된 카드는 접혀 있어도 열린 채로', /class="panel flag-med" data-pt="Conditional Access Failures"/.test(main.innerHTML));
T('렌더 뒤 _flags 는 비워짐 (다른 렌더에 안 샘)', Object.keys(g('_flags')).length === 0);
g("LANG='ko'"); g("active='signins'"); ctx.renderMain();
T('한국어: "할 일" 라벨', /flag-why[\s\S]{0,300}할 일/.test(main.innerHTML));

console.log(`\n${fail ? fail + ' FAILED' : 'all passed'}`);
process.exit(fail ? 1 : 0);
