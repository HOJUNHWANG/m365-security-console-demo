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
function boot(snap, lang) {
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
  g(`LANG=${JSON.stringify(lang || 'en')}`);
  return g;
}

const N = o => Object.assign({ hosts: [], created: '2026-10-02', ageDays: 11, registrar: 'NameSilo, LLC',
  firstSeen: '2026-10-13T21:22:42Z', lastSeen: '2026-10-15T20:25:13Z', inbound: 3, delivered: 3, status: {}, replies: 0,
  repliedBy: [], recipients: ['employee@contoso.com'], recipientCount: 1, senders: [], subjects: ['Project RFQ - a supplier | Q4'],
  blocked: false, looksLike: null, reason: null, checkedAt: null, by: null }, o);
function make(imp) {
  const s = JSON.parse(JSON.stringify(baseSnap));
  s._history = s._history || [];
  s.exchangeEop = Object.assign({}, s.exchangeEop || {}, { available: true, impersonation: Object.assign({
    listsCollected: true, traceCollected: true, windowStart: '2026-07-16', windowEnd: '2026-10-15', windowDays: 92,
    suspects: [], similarPartners: [], protectGaps: [], policies: [], protectDomains: [], protectUsers: [], trustDomains: [],
    trustSenders: [], confirmedReal: [], blockList: [],
    counts: { replied: 0, delivered: 0, quarantined: 0, blocked: 0, similarPartners: 0, confirmedReal: 0, blockList: 0,
              protectDomains: 0, protectUsers: 0, trustDomains: 0 } }, imp) });
  return s;
}
const LOOK = { collected: true, lastRun: { at: '2026-10-15T21:04:46Z' }, candidates: 365, pending: 0, failed: 1, noDate: 40,
               maxAgeDays: 30, lookbackDays: 30 };
const rows = [
  N({ domain: 'lk1zzz.example', level: 'delivered' }),
  N({ domain: 'replied.example', level: 'replied', replies: 2, repliedBy: ['a@contoso.com'], ageDays: 5 }),
  N({ domain: 'gone.example', level: 'blocked', blocked: true, ageDays: 20 }),
  N({ domain: 'okco.example', level: 'confirmed', reason: 'Sales: phoned, real new vendor', ageDays: 25 }),
];
const full = make({ newDomains: rows, newDomainLookup: LOOK,
  blockList: [{ value: 'gone.example', kind: 'domain', action: 'Block', modified: '2026-10-15', expires: null, notes: '', lookalike: false, newDomain: true }],
  counts: { replied: 0, delivered: 0, quarantined: 0, blocked: 0, similarPartners: 0, confirmedReal: 0, blockList: 1, protectDomains: 0,
            protectUsers: 0, trustDomains: 0, newReplied: 1, newDelivered: 1, newQuarantined: 0, newBlocked: 1, newConfirmed: 1 } });

console.log('\n[1] ① 사칭 감시 하위 탭에 패널이 나온다');
T("하위 탭 titles 에 'New Sender Domains'", /titles:\['Impersonation Watch','New Sender Domains','Block & Trust Lists'\]/.test(html));
let g = boot(full);
let out = g('impersonationPanels(DATA.exchangeEop)');
T('패널이 그려진다(data-pt)', /data-pt="New Sender Domains"/.test(out));
const panelHtml = (out.split('data-pt="New Sender Domains"')[1] || '').split('data-pt="Block & Trust Lists"')[0];

console.log('\n[2] ② 행 내용');
T('lk1zzz.example 행 · 등록일 · 등록 대행', /lk1zzz\.example/.test(panelHtml) && /2026-10-02/.test(panelHtml) && /NameSilo/.test(panelHtml));
T('  ↳ 첫 메일 때 나이 11 days · 제목', /11 days/.test(panelHtml) && /Project RFQ - a supplier/.test(panelHtml));
T('  ↳ 회신한 행은 We replied + 2 sent', /We replied/.test(panelHtml) && /2 sent/.test(panelHtml));
T('  ↳ 차단 행은 Blocked · 확인 행은 Confirmed real + 근거', /Blocked/.test(panelHtml) && /Confirmed real/.test(panelHtml) && /phoned, real new vendor/.test(panelHtml));
T('  ↳ 머리 줄: 검토 2 · 차단 1 · 확인 1', /2 to review · 1 blocked · 1 confirmed/.test(out));
T('  ↳ 조회 상태 줄(후보 365 · 비공개 40 · 실패 1)', /365 first-contact domains in the last 30 days/.test(panelHtml) && /40 without a public date · 1 failed/.test(panelHtml));

console.log('\n[3] ③ 조용한 0 금지');
let o3 = boot(make({ newDomains: [], newDomainLookup: { collected: false } }))('impersonationPanels(DATA.exchangeEop)');
T('캐시 없음 → "not been looked up" 경고 · 빈 표 문구도 "조회 전"', /have not been looked up yet/.test(o3) && /Nothing to show until registration dates are looked up/.test(o3));
T('  ↳ "새 도메인 없음" 이라고 말하지 않는다', !/No newly registered domain has written to us first/.test(o3));
o3 = boot(make({ newDomains: [], newDomainLookup: Object.assign({}, LOOK, { pending: 7 }) }))('impersonationPanels(DATA.exchangeEop)');
T('대기 7 → "7 domain(s) have no registration date yet"', /7 domain\(s\) have no registration date yet/.test(o3));
o3 = boot(make({ newDomains: [], newDomainLookup: LOOK }))('impersonationPanels(DATA.exchangeEop)');
T('조회 끝 · 0건 → "No newly registered domain…"', /No newly registered domain has written to us first/.test(o3));

console.log('\n[4] ④ ✓ / ✕ 는 대시보드 PC 에서만');
T('읽기 전용 화면엔 ✓ 없음', !/impRecord\(/.test(panelHtml) && !/impUnrecord\(/.test(panelHtml));
g('EDIT = {canEdit:true}');
const rw = (g('impersonationPanels(DATA.exchangeEop)').split('data-pt="New Sender Domains"')[1] || '').split('data-pt="Block & Trust Lists"')[0];
const recFor = d => rw.includes(`impRecord('${d}')`);
T('대시보드 PC: delivered · replied 행에 ✓', recFor('lk1zzz.example') && recFor('replied.example'));
T('  ↳ 차단 · 확인 행에는 ✓ 없음', !recFor('gone.example') && !recFor('okco.example'));
T('  ↳ 확인 행에는 ✕(해제)', /impUnrecord\('okco\.example'\)/.test(rw));

console.log('\n[5] ⑤ 차단 목록 표시 · 한국어');
T("차단 목록에 'new domain' 배지", /gone\.example[\s\S]{0,400}new domain/.test(out));
const ko = boot(full, 'ko')('impersonationPanels(DATA.exchangeEop)');
T('패널 제목 번역', /새로 등록된 발신 도메인/.test(ko));
T('  ↳ 머리 줄 · 열 · 상태 줄 번역', /검토 2 · 차단 1 · 확인 1/.test(ko) && /첫 메일 때 나이/.test(ko) && /최근 30일 첫 연락 도메인 365개/.test(ko));
T('  ↳ 영어 원문이 남지 않는다', !/Age at first mail|first-contact domains in the last|to review · 1 blocked · 1 confirmed/.test(ko));

console.log(fail ? `\n${fail} FAILURE(S)` : '\nall checks passed');
process.exit(fail ? 1 : 0);
