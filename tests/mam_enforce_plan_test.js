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
const actions = D => { vm.runInContext('globalThis.__D = ' + JSON.stringify(D), ctx); return vm.runInContext('buildActions(globalThis.__D)', ctx).map(a => [a[0], a[1]]); };

const plan = (days) => ({ noticeSent: '2026-11-17', enforceOn: '2026-12-02', policy: 'CA11 - Require app protection for mobile', ref: 'x', daysLeft: days, warnDaysBefore: 7, warning: days <= 7 });
const D = (days, left, policies = 1) => ({
  riskySignins: { available: true, caReportOnlyBlockCount: 12, caReportOnlyUsers: 9, caReportOnlyPolicyCount: policies, windowDays: 7 },
  mamRegistrations: { available: true, enforceHold: null, enforcePlan: days == null ? null : plan(days),
                      deviceIdGaps: { measured: true, missingActivePeople: left } },
});
const mam = a => a.filter(x => /app protection for mobile|Report-only CA pilot/.test(x[1]));

vm.runInContext("LANG='en'", ctx);
console.log('① 날짜 전');
let a = mam(actions(D(15, 40)));
check('★ 공지 직후(15일 남음) → info · 남은 날 · 인원 · 공지일', a.length === 1 && a[0][0] === 'info' && /15d left · notice sent 2026-11-17\) — 40 active people/.test(a[0][1]));
check('일반 report-only high 안 뜸', !a.some(x => /Report-only CA pilot/.test(x[1])));
a = mam(actions(D(7, 12)));
check('★ 7일 전(11-25)부터 → med', a.length === 1 && a[0][0] === 'med' && /7d left/.test(a[0][1]));
a = mam(actions(D(8, 12)));
check('8일 전은 아직 info', a.length === 1 && a[0][0] === 'info');

console.log('② 0명 · 날짜 지남');
a = mam(actions(D(3, 0)));
check('0명 → info 준비 끝', a.length === 1 && a[0][0] === 'info' && /nobody active is left/.test(a[0][1]));
a = mam(actions(D(-1, 5)));
check('★ 날짜 지났는데 report-only → high', a.length === 1 && a[0][0] === 'high' && /has passed/.test(a[0][1]));

console.log('③ ④ 다른 경우');
a = mam(actions(D(15, 40, 2)));
check('report-only 정책 2개면 일반 판정(high)', a.length === 1 && /Report-only CA pilot would BLOCK/.test(a[0][1]));
a = mam(actions(D(null, 40)));
check('예정 · 보류 둘 다 없으면 일반 판정', a.length === 1 && /Report-only CA pilot would BLOCK/.test(a[0][1]));

vm.runInContext("LANG='ko'", ctx);
a = mam(actions(D(15, 40)));
check('한국어', /12-02 enforce \(15일 남음 · 공지 2026-11-17\) — 아직 기기 ID 없이/.test(a[0][1]) || /2026-12-02 enforce \(15일 남음/.test(a[0][1]));
vm.runInContext("LANG='en'", ctx);
const card = (days, left) => { vm.runInContext('globalThis.__m = ' + JSON.stringify({ available: true, targetedUsers: 77, registeredUsers: 67, registrationCount: 222,
  notRegistered: 12, notRegisteredUsers: [], flagged: [], staleRegistrations: 0, staleDays: 14, enforceHold: null, enforcePlan: plan(days),
  deviceIdGaps: { measured: true, missingActivePeople: left, missingPeople: left, activeDays: 14, byApp: {}, missingActiveUsers: [] } }), ctx);
  return vm.runInContext('mamPanel(globalThis.__m)', ctx); };
check('카드 KPI · 배지: 경고 구간 전 = 파랑(info)', /b-info">enforce 2026-12-02/.test(card(15, 40)));
check('카드 배지: 7일 전부터 = 노랑', /b-med">enforce 2026-12-02/.test(card(7, 40)));
const ps = [{ user: 'a@x', status: 'register', platform: 'iOS', outlook: 'noId', teams: 'noId', iosDeviceInTenant: false, lastUsed: '2026-11-16T00:00:00Z' },
            { user: 'b@x', status: 'reopen', platform: 'iOS', outlook: 'noId', teams: null, iosDeviceInTenant: true, lastUsed: '2026-11-16T00:00:00Z' },
            { user: 'c@x', status: 'ready', platform: 'Android', outlook: 'id', teams: 'id', iosDeviceInTenant: false, lastUsed: null }];
const card2 = () => { vm.runInContext('globalThis.__m = ' + JSON.stringify({ available: true, targetedUsers: 3, registeredUsers: 2, registrationCount: 4,
  notRegistered: 1, notRegisteredUsers: ['z@x'], flagged: [], staleRegistrations: 0, staleDays: 14, enforceHold: null,
  enforcePlan: { ...plan(15), missingAtNotice: 40 }, byPlatform: { iPhone: 3 }, peopleStatus: ps, iosDeviceLookup: true,
  deviceIdGaps: { measured: true, missingActivePeople: 2, missingPeople: 2, activeDays: 14, byApp: {}, missingActiveUsers: ['a@x', 'b@x'] } }), ctx);
  return vm.runInContext('mamPanel(globalThis.__m)', ctx); };
let c2 = card2();
check('★ 사람별 표: 상태 배지(기기 등록 필요 · 기기 등록됨 · 앱 열기)', /b-med">Needs device registration</.test(c2) && /b-low">Device registered · open the app</.test(c2));
check('상태별 개수 줄', />Needs device registration 1</.test(c2) && />Ready 1</.test(c2));
check('공지 뒤 진행 40 → 2', /40 at notice → 2 now/.test(c2));
check('기기 종류 표 · 옛 명단 두 개는 안 나옴', !/Device type/.test(c2) && !/No device ID \(would be blocked\)/.test(c2) && !/z@x/.test(c2));
check('도움말: 본사 등록은 두고 Contoso 추가(둘 다 유지)', /keep that registration and add this tenant with \+ in Authenticator/.test(c2));
check('Android 줄의 iPhone 칸은 —', /c@x[\s\S]*?badge b-zero">—</.test(c2));
vm.runInContext("LANG='ko'", ctx);
c2 = card2();
check('한국어: 상태 · 진행', /기기 등록 필요/.test(c2) && /공지 때 40명 → 지금 2명/.test(c2) && /우리 테넌트 iPhone 등록/.test(c2));
check('한국어 도움말: 둘 다 유지', /그 등록은 그대로 두고 Authenticator 에서 '\+' 로 우리 테넌트를 추가/.test(c2));
check('MAM 카드 배지 문구 등록됨', html.includes('I18N.ko["enforce {0} · notice sent {1}"]') && html.includes("tf('enforce {0} · notice sent {1}'"));

console.log(fails.length ? `\n${fails.length} FAILED: ${fails}` : '\nall passed');
process.exit(fails.length ? 1 : 0);
