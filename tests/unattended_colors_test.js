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
vm.runInContext("LANG='en'", ctx);

const fails = [];
const check = (name, cond, out) => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${name}`);
  if (!cond) { fails.push(name); if (out) console.log('        ' + out.slice(0, 800)); }
};
const row = (x) => {
  vm.runInContext('globalThis.__u = ' + JSON.stringify({ available: true, exposedCount: 0, reportOnlyExposedCount: 0,
    conditionallyGatedCount: 2, licenceProvenCount: 2, policyCount: 9, candidateCount: 2, roomSkus: [],
    findings: [Object.assign({ name: 'ROOM', evidence: 'licence', skus: ['Teams_Rooms'], policy: 'P', enforced: true, controls: ['block'] }, x)] }), ctx);
  const out = vm.runInContext('unattendedPanel(globalThis.__u, 1)', ctx);
  return (out.match(/<td[^>]*>[\s\S]*?ROOM[\s\S]*?<\/tr>/) || [out])[0];
};

let r = row({ reach: 'legacyOnly', reachWhy: 'legacy only' });
check('★ 근거 라이선스 = 회색', /b-zero"[^>]*>licence</.test(r) && !/b-high/.test(r), r);
check('★ 레거시 전용 줄: 적용됨 · block 회색', /b-zero">Enforced</.test(r) && /b-zero">block</.test(r) && !/b-med/.test(r), r);
r = row({ reach: 'conditionalBlock', reachWhy: 'outside AllTrusted' });
check('★ 조건부 줄: 빨강 · 노랑 없음', !/b-high|b-med/.test(r), r);
r = row({ reach: 'cannotSatisfy', reachWhy: 'MFA' });
check('막는 줄은 적용됨 빨강 · block 노랑 유지', /b-high">Enforced</.test(r) && /b-med">block</.test(r), r);
r = row({ reach: 'cannotSatisfy', reachWhy: 'MFA', enforced: false });
check('막는 줄 report-only = 노랑', /b-med">Report-only</.test(r), r);
r = row({ reach: 'conditionalBlock', reachWhy: 'x', evidence: 'name' });
check('이름만 근거는 파랑(확인 필요) 유지', /b-info"[^>]*>name only</.test(r), r);

console.log(fails.length ? `\n${fails.length} FAILED: ${fails}` : '\nall passed');
process.exit(fails.length ? 1 : 0);
