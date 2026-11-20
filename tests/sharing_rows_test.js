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

function render(sp, lang) {
  g("LANG='" + (lang || 'en') + "'");
  g('DATA = ' + JSON.stringify({ _collectedAt: '2026-11-18T16:27:00Z', sharepointSharing: Object.assign({
    available: true, sharingCapability: 'externalUserAndGuestSharing', sharingCapabilityLabel: 'Anyone with the link (anonymous)',
    sharingCapabilitySeverity: 'bad', anonymousLinksEnabled: true, findings: [], findingCount: 0,
    idleSessionSignOut: { enabled: true, warnAfterMinutes: 25, signOutAfterMinutes: 30 } }, sp) }));
  g("active='sharing.posture'"); ctx.renderMain();
  return main.innerHTML;
}
const row = (out, label) => (out.match(new RegExp('<td[^>]*>' + label + '</td>\\s*<td[^>]*>([\\s\\S]*?)</td>')) || [])[1] || '';

console.log('\n=== ① 도메인 제한 줄 ===');
let out = render({ domainRestrictionMode: 'allowList', allowedDomains: ['hd.com', 'lk1zzz.example'], blockedDomains: Array(14).fill('x.com') });
let r = row(out, 'Domain restriction');
T('★ 허용 목록 모드 → 허용 2개 + 도메인 이름', /2 allowed/.test(r) && /hd\.com · lk1zzz\.example/.test(r), r);
T('★ 남은 옛 차단 목록은 안 보임', !/blocked/.test(r), r);
r = row(render({ domainRestrictionMode: 'blockList', allowedDomains: [], blockedDomains: Array(14).fill('x.com') }), 'Domain restriction');
T('차단 목록 모드 → 차단 14개', /14 blocked/.test(r) && !/allowed/.test(r), r);
r = row(render({ domainRestrictionMode: 'allowList', allowedDomains: ['a.com', 'b.com', 'c.com', 'd.com', 'e.com', 'f.com'], blockedDomains: [] }), 'Domain restriction');
T('6개 이상이면 개수만', /6 allowed/.test(r) && !/a\.com/.test(r), r);
r = row(render({ domainRestrictionMode: 'allowList', allowedDomains: ['hd.com', 'lk1zzz.example'], blockedDomains: [] }, 'ko'), '도메인 제한');
T('한국어: 허용 목록만 · 허용 2개', /허용 목록만/.test(r) && /허용 2개/.test(r), r);

console.log('\n=== ② 관리 외 기기 동기화 줄 ===');
r = row(render({ unmanagedSyncRestricted: false, syncSwitchUsable: false }), 'Sync blocked on unmanaged devices');
T('★ 클라우드 전용 → 해당 없음(b-zero) · 주황 아님', /b-zero">not available</.test(r) && !/b-med/.test(r), r);
T('  ↳ 대신 막는 곳 설명', /Intune \(company PCs\) \+ device CA \(personal PCs\)/.test(r), r);
r = row(render({ unmanagedSyncRestricted: false, syncSwitchUsable: true }), 'Sync blocked on unmanaged devices');
T('사내 AD 있는 테넌트 → 끔은 그대로 주황', /b-med">off</.test(r), r);
r = row(render({ unmanagedSyncRestricted: false, syncSwitchUsable: null }), 'Sync blocked on unmanaged devices');
T('모르면(조회 실패) → 주황 유지', /b-med">off</.test(r), r);
r = row(render({ unmanagedSyncRestricted: true, syncSwitchUsable: false }), 'Sync blocked on unmanaged devices');
T('켜져 있으면 초록', /b-ok">on</.test(r), r);
r = row(render({ unmanagedSyncRestricted: false, syncSwitchUsable: false }, 'ko'), '관리 외 기기에서 동기화 차단');
T('한국어: 해당 없음 · 클라우드 전용', /해당 없음/.test(r) && /클라우드 전용/.test(r), r);

console.log(`\n${fail ? fail + ' FAILED' : 'all passed'}`);
process.exit(fail ? 1 : 0);
