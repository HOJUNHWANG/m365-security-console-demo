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
const check = (name, cond) => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${name}`);
  if (!cond) fails.push(name);
};
const call = (expr, v) => { vm.runInContext('globalThis.__v = ' + JSON.stringify(v), ctx); return vm.runInContext(expr, ctx); };
const actions = D => call('buildActions(globalThis.__v)', D).map(a => [a[0], a[1]]);

const sim = {
  name: 'Contoso-DLP-Simulation', mode: 'TestWithNotifications', testing: true, enabled: true, notifyingUsers: true,
  distributed: true, distributionStatus: 'Success', simulationStatus: 'Completed', decision: { on: '2026-09-25', ref: '' },
  locations: {}, matchedItemsCount: 3, inMailCount: 3, atRestCount: 0, exchangeDomains: [], exchangeByClass: { external: 0 },
  ruleCount: 1, sensitiveTypes: ['U.S. SSN'], blockingRule: false, topLocations: {}, rules: [],
};
const cop = (o) => Object.assign({
  name: 'Default DLP policy - Protect sensitive M365 Copilot interactions', mode: 'TestWithoutNotifications', testing: true,
  enabled: true, matchedItemsCount: 0, decided: true, reviewDue: false,
  decision: { on: '2026-11-16', mode: 'TestWithoutNotifications', reviewOn: '2026-11-30', ref: '',
              types: ['U.S. SSN', 'Credit Card Number', 'U.S. ITIN', 'U.S. / U.K. Passport Number', "U.S. Driver's License Number"] },
}, o);
const dl = (c) => ({ available: true, collectedAt: '2026-11-17T13:09:54Z', ageHours: 1, stale: false, policyCount: 2,
  findings: [], detailReport: {}, activityExplorer: {}, simulation: sim, copilot: c });

vm.runInContext("LANG='en'", ctx);
console.log('① 결정대로');
let h = call('copilotDlpPanel(globalThis.__v)', dl(cop()));
check('패널 제목 · 초록 모드 배지', h.includes('Copilot Prompt DLP') && /badge b-ok">TestWithoutNotifications/.test(h));
check('탐지 유형 5 · 검토일 · 유형별 적중 안내', h.includes('Credit Card Number') && h.includes('2026-11-30') && h.includes('not collected yet'));
const tab = call('tabDlp({dlpSimulation: globalThis.__v})', dl(cop()));
check('★ DLP 탭 맨 위', tab.indexOf('Copilot Prompt DLP') > -1 && tab.indexOf('Copilot Prompt DLP') < tab.indexOf('DLP Simulation'));
check('메일·파일 카드에는 Copilot 줄 없음', !call('dlpPanel(globalThis.__v)', dl(cop())).includes('Copilot'));
check('개요 할 일 없음', !actions({ dlpSimulation: dl(cop()) }).some(a => /Copilot/.test(a[1])));

console.log('② 모드 변경 · 검토일 · 없음');
const a1 = actions({ dlpSimulation: dl(cop({ mode: 'Enable', testing: false, decided: false })) });
check('★ 모드 변경 → med', a1.some(a => a[0] === 'med' && /Copilot prompt DLP is now Enable/.test(a[1])));
h = call('copilotDlpPanel(globalThis.__v)', dl(cop({ mode: 'Enable', testing: false, decided: false })));
check('차단 모드 → 빨강 배지 · 기록된 결정 표시', /badge b-high">Enable/.test(h) && h.includes('recorded decision is TestWithoutNotifications'));
check('정책 없음 → 패널에 안내', call('copilotDlpPanel(globalThis.__v)', dl(null)).includes('missing from the snapshot'));
check('★ 검토일 → med', actions({ dlpSimulation: dl(cop({ reviewDue: true })) }).some(a => a[0] === 'med' && /review is due/.test(a[1])));
check('정책 없음 → low', actions({ dlpSimulation: dl(null) }).some(a => a[0] === 'low' && /missing from the snapshot/.test(a[1])));

console.log('③ 관리자 MFA');
const cov = (u) => ({ available: true, policies: ['CA02 - Require MFA for admins'], uncovered: u,
  excludedOnPurpose: [{ name: 'BREAK GLASS', upn: 'bg@x.test', roles: ['Global Administrator'] }] });
h = call('adminMfaLine(globalThis.__v)', cov([]));
check('전원 대상 → 초록 · 정책 이름', h.includes('b-ok') && h.includes('CA02 - Require MFA for admins'));
check('비상 계정 → 회색 의도된 제외', /b-zero">excluded on purpose<\/span> <b>BREAK GLASS/.test(h));
const u = [{ name: 'AI2', upn: 'ai2@x.test', roles: ['AI Administrator'] }];
h = call('adminMfaLine(globalThis.__v)', cov(u));
check('★ 밖 → 노랑 배지 + 이름 · 역할', /b-med">outside admin MFA<\/span> <b>AI2<\/b> \(AI Administrator\)/.test(h));
check('★ 개요 med', actions({ adminAccounts: { available: true, adminMfaCoverage: cov(u) } })
  .some(a => a[0] === 'med' && /admin MFA policy does not target \(AI Administrator\)/.test(a[1])));
check('대상이면 개요 없음', !actions({ adminAccounts: { available: true, adminMfaCoverage: cov([]) } })
  .some(a => /admin MFA/.test(a[1])));

console.log('④ 한국어');
vm.runInContext("LANG='ko'", ctx);
h = call('copilotDlpPanel(globalThis.__v)', dl(cop()));
check('Copilot 프롬프트 DLP · 막히는 프롬프트 없음 · 설명', h.includes('Copilot 프롬프트 DLP') && h.includes('막히는 프롬프트 없음') && h.includes('첨부 파일은 검사하지 않으며'));
h = call('adminMfaLine(globalThis.__v)', cov(u));
check('관리자 MFA 밖 · 의도된 제외', h.includes('관리자 MFA 밖') && h.includes('의도된 제외'));

console.log(fails.length ? `\n${fails.length} FAILED: ${fails}` : '\nall passed');
process.exit(fails.length ? 1 : 0);
