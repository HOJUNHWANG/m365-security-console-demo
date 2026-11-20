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

let fails = [];
const check = (name, cond) => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${name}`);
  if (!cond) fails.push(name);
};


const dev = (o) => Object.assign({
  device: 'LAPTOP-DEMO001', user: 'someone@example.test', complianceState: 'compliant',
  entraObjectCount: 1, intuneDeviceId: '0cadc045', intuneObjectTrustType: 'Workplace', intuneTargetState: 'liveReal',
  presentedDeviceId: '0cadc045', presentedManaged: true, presentedSound: true, presentedSource: 'signin',
  presentedTagged: false, signInDeviceId: '0cadc045', signInExistsInEntra: true, signInTrustType: 'Workplace',
  signInTagged: false, reregistered: false, ok: false, problems: ['NOT tagged'], warnings: [],
  accountsSeen: [], extraAccounts: [], retiring: null,
}, o);
const panelOf = di => { vm.runInContext('globalThis.__d = ' + JSON.stringify(di), ctx); return vm.runInContext('deviceIdentityPanel(globalThis.__d)', ctx); };
const actionsOf = D => { vm.runInContext('globalThis.__D = ' + JSON.stringify(D), ctx); return vm.runInContext('buildActions(globalThis.__D)', ctx); };

console.log('① 기한 안');
vm.runInContext("LANG='en'", ctx);
let di = { available: true, windowDays: 7, tag: 'extensionAttribute1=Approved-Device', enrolled: 3, healthy: 1, problem: 0,
  untaggedSignInCount: 0, devices: [
    dev({ device: 'OLD-A', retiring: { until: '2026-12-15', expired: false } }),
    dev({ device: 'OLD-B', ok: true, problems: [], warnings: ['no claim'], retiring: { until: '2026-12-15', expired: false } }),
    dev({ device: 'GOOD', ok: true, problems: [], presentedTagged: true, signInTagged: true })],
  retiringHeld: [['OLD-A', '2026-12-15'], ['OLD-B', '2026-12-15']], retiringOverdue: [], retiringUnmatched: [], retiringErrors: [],
  taggedObjectCount: 1, taggedStubCount: 0, taggedNotEnrolled: [], enrolledNotTagged: [] };
let h = panelOf(di);
check('★ 불일치 표 없음(초록 문장)', /Every enrolled device has one coherent identity/.test(h));
check('★ 경고 표에 OLD-B 없음', !/Warnings — no action needed/.test(h));
check('★ 회색 반납 대기 줄 · 두 기기 · 기한', /badge b-zero">retiring<\/span> <b>OLD-A<\/b> \(until 2026-12-15\) · <b>OLD-B<\/b>/.test(h));
check('★ Coherent KPI 초록(healthy 1 + held 2 = enrolled 3)', /<div class="kpi ok"><div class="kpi-val">1<\/div>\s*<div class="kpi-label">Coherent/.test(h));
let A = actionsOf({ deviceIdentity: di });
check('★ 개요에 기기 ID 할 일 없음', !A.some(x => x[3] === 'Device Identity Coherence'), JSON.stringify(A));

console.log('② 기한 지남 · 오류 · 등록 없음');
di = Object.assign({}, di, { retiringHeld: [], retiringOverdue: [['OLD-A', '2026-12-15']], retiringUnmatched: ['GONE'],
  retiringErrors: ['OLD-C'], problem: 1, untaggedSignInCount: 1,
  devices: [dev({ device: 'OLD-A', retiring: { until: '2026-12-15', expired: true } })] });
h = panelOf(di);
check('★ 지난 기기는 불일치 표에 다시 나옴', /<span class="trunc">OLD-A<\/span>/.test(h));
check('★ 노랑 "past return date" 줄', /badge b-med">past return date/.test(h));
check('등록 없음 = 정보 배지', /badge b-info">no longer enrolled<\/span> GONE/.test(h));
check('형식 오류 = 빨강 배지', /badge b-high">unreadable entry<\/span> <code>OLD-C/.test(h));
A = actionsOf({ deviceIdentity: di });
check('★ 개요 med: 기한 지남 → 객체 정리', A.some(x => x[0] === 'med' && /past their return date \(OLD-A\)/.test(x[1])), JSON.stringify(A));
check('개요 med: 형식 오류', A.some(x => x[0] === 'med' && /unreadable/.test(x[1])));

console.log('③ 한국어');
vm.runInContext("LANG='ko'", ctx);
h = panelOf(Object.assign({}, di, { retiringHeld: [['OLD-Z', '2026-12-15']] }));
check('반납 대기 · 기한 · 기한 지남 문구', /반납 대기/.test(h) && /기한 2026-12-15/.test(h) && /반납 기한 지남/.test(h));
A = actionsOf({ deviceIdentity: di });
check('개요 한국어', A.some(x => /반납 기한이 지난 기기 1대/.test(x[1])));

console.log(fails.length ? `\n${fails.length} FAILED: ${fails.join(' | ')}` : '\nall passed');
process.exit(fails.length ? 1 : 0);
