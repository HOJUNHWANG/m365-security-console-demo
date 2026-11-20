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
  const doc = makeEl();
  doc.documentElement = makeEl(); doc.body = makeEl(); doc.hidden = false;
  doc.getElementById = () => makeEl();
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

const L = (d, hh, mm) => new Date(2026, 9, d, hh, mm, 0);
function render(nowLocal, collectedLocal, o = {}) {
  const snap = JSON.parse(JSON.stringify(baseSnap));
  snap._history = snap._history || [];
  const ageHours = Math.round((nowLocal - collectedLocal) / 360000) / 10;
  snap.exchangeEop = Object.assign({}, snap.exchangeEop || {}, {
    available: true, collectedAt: collectedLocal.toISOString(), ageHours, stale: ageHours > 20,
    collectTimes: ['10:00', '13:00', '16:00'], collectRunLimitMin: 30,
  }, o);
  const g = boot(snap);
  g(`LANG = ${JSON.stringify(o.lang || 'en')}`);
  g(`(() => { const R = Date, N = ${nowLocal.getTime()};
      globalThis.Date = class extends R { constructor(...a) { a.length ? super(...a) : super(N); }
                                          static now() { return N; } }; })()`);
  return g('tabMailSec(DATA)');
}
const head = h => h.slice(0, 1500);
const PROG = /collection in progress/, MISS = /did not finish/, STALE = /Snapshot is [\d.]+h old/;

console.log('\n[1] ① 16:05 · 스냅샷 13:07 — 16:00 회차가 도는 중 (실제 10-14 화면)');
let h = head(render(L(14, 16, 5), L(14, 13, 7)));
T("'수집 중' 이라고 말한다", PROG.test(h), h.match(/Collected:[^<]*/)?.[0]);
T('끝나지 않음 경고는 아니다', !MISS.test(h));
T('다음 예정(내일 10:00)도 여전히 보인다', /next ≈/.test(h));

console.log('\n[2] ② 16:45 · 스냅샷 13:07 — 실행 한도 30분이 지났는데 안 왔다');
h = head(render(L(14, 16, 45), L(14, 13, 7)));
T("'끝나지 않음' 경고", MISS.test(h), h.match(/did not finish[^<]*/)?.[0]);
T('  ↳ 경고 상자(notice)로 보인다', /class="notice"[^>]*>⚠ The /.test(h));
T("  ↳ '수집 중' 이라고 하지 않는다", !PROG.test(h));
T('  ↳ 로그 위치를 알려 준다', /exo_collect\.log/.test(h));

console.log('\n[3] ③ 정상 — 스냅샷이 최근 예약 시각 뒤');
h = head(render(L(14, 16, 10), L(14, 16, 7)));
T('16:10 · 스냅샷 16:07 → 아무 경고 없음', !PROG.test(h) && !MISS.test(h) && !STALE.test(h));
h = head(render(L(15, 9, 0), L(14, 16, 7)));
T('다음 날 09:00 · 스냅샷 전날 16:07 → 밤사이는 정상', !PROG.test(h) && !MISS.test(h) && !STALE.test(h));
h = head(render(L(15, 10, 5), L(14, 16, 7)));
T("다음 날 10:05 · 스냅샷 전날 16:07 → 첫 회차 '수집 중'", PROG.test(h) && !MISS.test(h));
h = head(render(L(14, 13, 20), L(14, 13, 7)));
T('13:20 · 스냅샷 13:07 → 정상 (13:00 회차가 이미 들어옴)', !PROG.test(h) && !MISS.test(h));

console.log('\n[4] ④ 20시간 넘은 스냅샷은 기존 경고 하나만');
h = head(render(L(15, 13, 30), L(14, 13, 7)));
T("'오래됨' 경고", STALE.test(h));
T('  ↳ 끝나지 않음 경고를 겹치지 않는다', !MISS.test(h));

console.log('\n[5] ⑤ 한국어 화면');
h = head(render(L(14, 16, 5), L(14, 13, 7), { lang: 'ko' }));
T("'수집 진행 중' 으로 번역된다", /수집 진행 중/.test(h), h.match(/수집:[^<]*/)?.[0]);
T('  ↳ 영어 원문이 남지 않는다', !/Collects at|collection in progress|h ago\)/.test(h));
h = head(render(L(14, 16, 45), L(14, 13, 7), { lang: 'ko' }));
T("'끝나지 않았습니다' 로 번역된다", /수집이 끝나지 않았습니다/.test(h));

console.log(fail ? `\n${fail} FAILURE(S)` : '\nall checks passed');
process.exit(fail ? 1 : 0);
