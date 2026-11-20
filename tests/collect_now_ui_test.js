const fs = require('fs'), vm = require('vm');
const html = fs.readFileSync('app/static/index.html', 'utf8');
const js = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]).pop();

let fail = 0;
const T = (name, ok, extra) => { console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${name}${extra ? '  ' + extra : ''}`); if (!ok) fail++; };
const noop = () => {};
function makeEl() {
  return { _html: '', set innerHTML(v) { this._html = v; }, get innerHTML() { return this._html; },
    querySelectorAll: () => [], addEventListener: noop, appendChild: noop, setAttribute: noop, getAttribute: () => null,
    removeAttribute: noop, classList: { add: noop, remove: noop, toggle: noop, contains: () => false },
    style: { setProperty: noop }, textContent: '', value: '', scrollTop: 0, dataset: {},
    querySelector: () => makeEl(), focus: noop, closest: () => null, disabled: false, title: '' };
}
const jsonRes = (o, status = 200) => ({ ok: status < 400, status, headers: { get: () => 'application/json' }, json: async () => o });
const htmlRes = (status) => ({ ok: false, status, headers: { get: () => 'text/html' }, json: async () => { throw new SyntaxError("Unexpected token '<'"); } });

function boot(script) {
  const els = {}; const doc = makeEl();
  doc.documentElement = makeEl(); doc.body = makeEl(); doc.hidden = false;
  doc.getElementById = id => els[id] || (els[id] = makeEl());
  doc.querySelector = () => makeEl(); doc.querySelectorAll = () => []; doc.createElement = () => makeEl();
  const calls = [], toasts = [];
  const sb = {
    window: { addEventListener: noop, matchMedia: () => ({ matches: false, addEventListener: noop }) },
    document: doc, location: { hash: '', href: '', search: '' },
    localStorage: { getItem: () => null, setItem: noop }, navigator: { language: 'en-US' }, URLSearchParams, Math,
    crypto: require('crypto').webcrypto,
    setTimeout: (fn) => { fn(); return 0; },
    setInterval: noop, clearInterval: noop, history: { replaceState: noop },
    fetch: async (url, opt) => { calls.push([url, opt && opt.method, opt && opt.headers]); return script(url, opt, calls); },
    console: { log: noop, warn: noop, error: noop },
  };
  sb.globalThis = sb;
  const ctx = vm.createContext(sb);
  vm.runInContext(js, ctx, { filename: 'app.js' });
  const g = e => vm.runInContext(e, ctx);
  g("LANG='en'");
  g('DATA = {_collectedAt:"2026-11-20T13:35:34Z"}');
  ctx.__toasts = toasts;
  g('toast = (m) => __toasts.push(m)');
  return { g, calls, toasts, els };
}

(async () => {
  console.log('① ③ 정상 흐름');
  let n = 0;
  let b = boot((url) => {
    if (url === '/api/collect') return jsonRes({ status: 'started', running: true });
    if (url === '/api/collect-status') { n++; if (n === 1) return htmlRes(524); return jsonRes({ running: n < 3 }); }
    if (url.startsWith('/api/summary')) return jsonRes({ _collectedAt: '2026-11-20T13:50:00Z', exchangeEop: {} });
    return jsonRes({});
  });
  await b.g('collectNow()');
  const pc = b.calls.find(c => c[0] === '/api/collect');
  T('★ POST /api/collect + 헤더 X-Dashboard-Collect', pc && pc[1] === 'POST' && pc[2]['X-Dashboard-Collect'] === '1');
  T('★ live=1 은 안 부름', !b.calls.some(c => /live=1/.test(c[0])));
  T('③ 상태 확인 한 번 HTML(524)이어도 계속 기다림', n >= 3);
  T('③ 끝나면 /api/summary 다시 읽음 → 새 수집', b.calls.some(c => c[0] === '/api/summary') && b.g('DATA._collectedAt') === '2026-11-20T13:50:00Z');
  T('버튼 다시 켜짐', b.els.refresh && b.els.refresh.disabled === false && /Collect now/.test(b.els.refresh.textContent));
  T('오류 토스트 없음', !b.toasts.some(m => /failed/i.test(m)), JSON.stringify(b.toasts));

  console.log('② 시작 요청이 터널 오류 페이지(HTML)');
  b = boot((url) => url === '/api/collect' ? htmlRes(524) : jsonRes({}));
  for (let i = 0; i < 20; i++) await new Promise(r => setImmediate(r));
  b.els.main.innerHTML = 'PAGE';
  await b.g('collectNow()');
  T('★ 화면은 그대로(백엔드 실패로 덮지 않음)', b.els.main.innerHTML === 'PAGE', b.els.main.innerHTML.slice(0, 80));
  T('  ↳ 토스트로 HTTP 524 · non-JSON 알림', b.toasts.some(m => /524/.test(m) && /non-JSON/.test(m)), JSON.stringify(b.toasts));

  console.log('이미 수집 중');
  n = 0;
  b = boot((url) => {
    if (url === '/api/collect') return jsonRes({ status: 'running', running: true, trigger: 'loop' });
    if (url === '/api/collect-status') { n++; return jsonRes({ running: n < 2 }); }
    if (url.startsWith('/api/summary')) return jsonRes({ _collectedAt: '2026-11-20T13:35:34Z', exchangeEop: {} });
    return jsonRes({});
  });
  await b.g('collectNow()');
  T('running 이면 그 수집이 끝나길 기다렸다가 다시 읽음', n >= 2 && b.calls.some(c => c[0] === '/api/summary'));
  T('  ↳ 데이터가 그대로면 데이터 상태 확인 토스트', b.toasts.some(m => /did not change/.test(m)), JSON.stringify(b.toasts));

  T('HTML 버튼 · 명령 팔레트가 collectNow 를 부름', /onclick="collectNow\(\)"/.test(html) && /run:\(\) => collectNow\(\)/.test(html) && !/onclick="load\(true\)"/.test(html));
  console.log(fail ? `\n${fail} FAILED` : '\nall passed');
  process.exit(fail ? 1 : 0);
})();
