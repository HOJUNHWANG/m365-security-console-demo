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
  if (!cond) { fails.push(name); if (out) console.log('        ' + out.slice(0, 600)); }
};
const tab = (mfa, lang) => {
  vm.runInContext(`LANG='${lang || 'en'}'`, ctx);
  vm.runInContext('globalThis.__D = ' + JSON.stringify({ mfaStatus: mfa }), ctx);
  return vm.runInContext('tabMfa(globalThis.__D)', ctx);
};
const base = { available: true, scope: 'members', total: 83, mfaRegistered: 80, percent: 96.4, notRegistered: ['a@x', 'b@x', 'c@x'],
  guestsTotal: 8, guestsNotRegistered: 7, guestsNotRegisteredByHome: { 'hd.com': 7 }, guestsNotRegisteredUntrusted: 0, mfaTrustedHomes: ['hd.com'] };

let o = tab(base);
check('★ 멤버 기준 문구', /80 \/ 83 members registered/.test(o), o);
check('★ 게스트 줄 · 본사 MFA 신뢰 설명', /7 of 8 guests have no MFA registered here/.test(o) && /\(hd\.com 7\)/.test(o)
  && /Guests from hd\.com sign in with their home-tenant MFA/.test(o), o);
check('신뢰 도메인뿐이면 노랑 배지 없음', !/b-med/.test(o), o);
o = tab({ ...base, guestsNotRegistered: 8, guestsNotRegisteredByHome: { 'hd.com': 7, 'vendor.com': 1 }, guestsNotRegisteredUntrusted: 1 });
check('★ 다른 도메인 미등록 → 노랑 배지', /b-med">1 from other domains</.test(o) && /vendor\.com 1/.test(o), o);
o = tab({ available: true, total: 90, mfaRegistered: 80, percent: 88.9, notRegistered: [] });
check('옛 스냅숏(scope 없음)은 예전 문구 · 게스트 줄 없음', /80 \/ 90 registered/.test(o) && !/Guests are not counted/.test(o), o);
o = tab(base, 'ko');
check('한국어', /멤버 83명 중 80명 등록/.test(o) && /게스트 8명 중 7명이 우리 테넌트에 MFA 미등록/.test(o) && /hd\.com 게스트는 본사 MFA 로/.test(o), o);

console.log(fails.length ? `\n${fails.length} FAILED: ${fails}` : '\nall passed');
process.exit(fails.length ? 1 : 0);
