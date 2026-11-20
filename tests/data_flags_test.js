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

console.log('\n=== ① 지도 = 실제 카드 · 실제 소스 ===');
const titles = new Set([...html.matchAll(/panel\(\s*'([^']+)'/g)].map(m => m[1]));
const map = g('SOURCE_PANELS');
const missing = Object.values(map).flat().filter(x => !titles.has(x));
T("★ 지도의 카드 제목이 전부 panel('…') 로 존재", missing.length === 0, missing.join(', '));
const reg = fs.readFileSync('app/registry.py', 'utf8');
const regKeys = [...reg.slice(reg.indexOf('SOURCES = {'), reg.indexOf('}', reg.indexOf('SOURCES = {'))).matchAll(/^\s+"([A-Za-z]+)":/gm)].map(m => m[1]);
const mk = Object.keys(map);
T('★ 지도 키 = registry 소스 키', regKeys.length > 20 && regKeys.every(k => mk.includes(k)) && mk.every(k => regKeys.includes(k)),
  `registry만: ${regKeys.filter(k => !mk.includes(k))} · 지도만: ${mk.filter(k => !regKeys.includes(k))}`);

console.log('\n=== ② 판정 ===');
const D = {
  _collectedAt: '2026-11-12T13:00:00Z',
  riskySignins: { available: true, caFailedCount: 25, windowDays: 7, carried: { ageMin: 47, reason: 'HTTP 429' } },
  dlpSimulation: { available: false, reason: 'Purview timeout' },
  sharingLinks: { available: true },
};
const f = g(`dataFlagMap(${JSON.stringify(D)})`);
T('carried → stale · 분 · 이유', f['Conditional Access Failures']?.kind === 'stale' && f['Conditional Access Failures'].ageMin === 47 && /429/.test(f['Conditional Access Failures'].reason));
T('available false → nodata · 이유', f['DLP Simulation']?.kind === 'nodata' && /timeout/.test(f['DLP Simulation'].reason));
T('정상 소스는 표시 없음', !f['Anonymous Sharing Links']);
T('데이터 없으면 아무것도 안 칠함', Object.keys(g('dataFlagMap(null)')).length === 0);

console.log('\n=== ③ 렌더 ===');
g("LANG='en'");
g('DATA = ' + JSON.stringify(D));
g("active='ca.eval'"); ctx.renderMain();
let out = main.innerHTML;
const cls = t0 => (out.match(new RegExp('class="(panel[^"]*)" data-pt="' + t0.replace(/[()]/g, '\\$&') + '"')) || [])[1] || '';
T('★ CA 실패 카드: 할 일 노랑 + 데이터 표시 같이', /flag-med/.test(cls('Conditional Access Failures')) && /data-stale/.test(cls('Conditional Access Failures')), cls('Conditional Access Failures'));
T('  ↳ "Not refreshed" 줄 · 47 min', /data-why[\s\S]{0,200}Not refreshed[\s\S]{0,200}47 min/.test(out));
T('★ 할 일 없는 카드는 data-stale 만', cls('Device CA Blocks — who cannot work right now') === 'panel data-stale', cls('Device CA Blocks — who cannot work right now'));
T('_dataFlags 는 렌더 뒤 비워짐', Object.keys(g('_dataFlags')).length === 0);
g("setUi('v2')"); g("_collapsed = new Set(['Device CA Blocks — who cannot work right now'])");
g("active='ca.eval'"); ctx.renderMain();
out = main.innerHTML;
T('★ 표시된 카드는 접혀 있어도 열린 채로', cls('Device CA Blocks — who cannot work right now') === 'panel data-stale', cls('Device CA Blocks — who cannot work right now'));
const html2 = g(`panel('DLP Simulation','Collection needed', notice({available:false, reason:'x'}))`);
T('★ 지도 없이도 notice() 만 있으면 nodata', /class="panel[^"]*data-nodata/.test(html2) && /Data not loaded/.test(html2));
const html3 = g(`panel('Anonymous Sharing Links','', '<div class="notice">⚠ ordinary warning</div>')`);
T('일반 경고(notice) 는 표시 안 함', !/data-(nodata|stale)/.test(html3));
g("LANG='ko'");
const html4 = g(`panel('DLP Simulation','', notice({available:false, reason:'x'}))`);
T('한국어 문구', /데이터를 못 불러옴/.test(html4));
T('★ 색 = --data(보라) · 점선 · 노랑/빨강 변수 안 씀',
  /\.panel\.data-nodata[^{]*\{\s*border:1px dashed var\(--data\)/.test(html) && !/data-nodata[^{]*\{[^}]*var\(--(warn|bad)\)/.test(html));
T('네 테마 모두 --data 정의', (html.match(/--data:#[0-9a-f]{6}/g) || []).length === 4);

console.log('\n=== ④ 왼쪽 메뉴 · 오류 줄 ===');
const tabsMap = g('SOURCE_TABS');
const parents = g('TABS').filter(x => x.id).map(x => x.id);
T('★ SOURCE_TABS 키 = SOURCE_PANELS 키', Object.keys(tabsMap).sort().join() === Object.keys(map).sort().join());
T('★ SOURCE_TABS 값이 전부 실제 메뉴 id', Object.values(tabsMap).flat().every(x => parents.includes(x)),
  Object.values(tabsMap).flat().filter(x => !parents.includes(x)).join());
const dtab = g(`dataTabs(${JSON.stringify(D)})`);
T('carried 소스 → ca · signins 에 표시', (dtab.ca || []).includes('riskySignins') && (dtab.signins || []).includes('riskySignins'));
T('down 소스 → dlp 에 표시', (dtab.dlp || []).includes('dlpSimulation'));
g('DATA = ' + JSON.stringify(D)); ctx.renderNav();
const navHtml = doc.getElementById('nav').innerHTML;
T('★ 메뉴에 보라 배지(nb-data)', /nav-badge nb-data/.test(navHtml));
g("LANG='en'");
const longErr = "HTTPStatusError: Server error '504 Gateway Timeout' for url 'https://x/sites?search=%2A'\nFor more information check: https://developer.mozilla.org/x";
g('_dataFlags = ' + JSON.stringify({'Anonymous Sharing Links': {kind:'stale', ageMin:65.9, reason: longErr}}));
const h5 = g(`panel('Anonymous Sharing Links','', '<p>x</p>')`); g('_dataFlags = {}');
T('★ 오류는 다음 줄(data-err) · 꼬리 제거', /<span class="data-err">HTTPStatusError[^<]*504[^<]*<\/span>/.test(h5) && !/For more information/.test(h5), h5.slice(0, 300));
T('분은 반올림(65.9 → 66)', /66 min ago/.test(h5));

console.log(`\n${fail ? fail + ' FAILED' : 'all passed'}`);
process.exit(fail ? 1 : 0);
