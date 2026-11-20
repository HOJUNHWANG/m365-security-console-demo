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

const fails = [];
const check = (name, cond, out) => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${name}`);
  if (!cond) { fails.push(name); if (out) console.log('        ' + out.slice(0, 500)); }
};
const badge = (click, lang) => {
  vm.runInContext(`LANG='${lang || 'en'}'`, ctx);
  vm.runInContext('globalThis.__th = ' + JSON.stringify({ available: true, riskyClicks: [Object.assign(
    { time: '2026-11-17T00:55:51Z', user: 'u@x', url: 'https://www.example.com/ship?tx=1', msgId: 'm' }, click)] }), ctx);
  const out = vm.runInContext('renderHunting(globalThis.__th)', ctx);
  const i = out.indexOf('www.example.com');
  return (out.slice(i).match(/<span class="badge [^"]*"[^>]*>[^<]*<\/span>/) || [''])[0];
};

let b = badge({ action: 'UrlErrorPage', through: 0, threats: '' });
check('★ 오류 페이지 + 위협 없음 → 회색 풀어 쓴 문구', /b-zero/.test(b) && />Destination error page · no threat found</.test(b), b);
check('  ↳ 원래 동작 이름은 툴팁에', /title="UrlErrorPage — /.test(b), b);
b = badge({ action: 'UrlErrorPage', through: 0, threats: 'Phish' });
check('★ 위협 유형 있으면 그 말 안 함 · 유형 표시', !/no threat found/.test(b) && /UrlErrorPage · Phish/.test(b) && /b-info/.test(b), b);
b = badge({ action: 'UrlErrorPage', through: 0 });
check('옛 스냅숏(threats 칸 없음) → 예전 표시', />UrlErrorPage</.test(b) && /b-info/.test(b), b);
b = badge({ action: 'ClickBlocked', through: 0, threats: 'Phish' });
check('차단 = 노랑 그대로', /b-med/.test(b) && /ClickBlocked/.test(b), b);
b = badge({ action: 'ClickAllowed', through: 1, threats: 'Phish' });
check('경고 무시 = 빨강 그대로', /b-high/.test(b) && /through/.test(b), b);
b = badge({ action: 'UrlErrorPage', through: 0, threats: '' }, 'ko');
check('한국어', />목적지 오류 페이지 · 위협 탐지 없음</.test(b), b);

console.log(fails.length ? `\n${fails.length} FAILED: ${fails}` : '\nall passed');
process.exit(fails.length ? 1 : 0);
