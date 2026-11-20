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
  const doc = makeEl(), main = makeEl(), nav = makeEl();
  doc.documentElement = makeEl(); doc.body = makeEl(); doc.hidden = false;
  doc.getElementById = id => (id === 'main' ? main : id === 'nav' ? nav : makeEl());
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

const dev = (name, encrypted, recoveryKey, os = 'Windows') => ({ id: name.toLowerCase(), name, os,
  osVersion: '10.0', owner: 'Company', compliance: 'compliant', encrypted, recoveryKey,
  lastSync: '2026-10-01T00:00:00Z', user: name.toLowerCase() + '@example.test', model: 'm', edition: 'Home' });
function snapWith(recoveryKeys, devices) {
  const s = JSON.parse(JSON.stringify(baseSnap));
  s._history = s._history || [];
  s.intuneDevices = Object.assign({}, s.intuneDevices || {}, { available: true, total: devices.length,
    compliant: devices.length, noncompliant: 0, encrypted: devices.filter(d => d.encrypted).length,
    byOs: {}, byEdition: {}, compliancePolicies: [], devices, recoveryKeys });
  return s;
}
const rowOf = (out, name) => (out.match(new RegExp(`<tr>(?:(?!</tr>).)*>${name}<(?:(?!</tr>).)*</tr>`, 's')) || [''])[0];

console.log('\n=== ① ② 상태별 배지 · KPI ===');
let g = boot(snapWith({ windows: 3, escrowed: 1, encryptedNoKey: 1 },
  [dev('JOINED', true, true), dev('LOCKOUT', true, false), dev('PLAIN', false, false), dev('IPHONE', true, null, 'iOS')]));
g("LANG='en'");
let out = g('tabDevices(DATA)');
T('표에 Recovery key 열이 있다', /<th>Recovery key<\/th>/.test(out));
T('키 있음 → In Entra (초록)', /badge b-ok">In Entra</.test(rowOf(out, 'JOINED')));
T('★ 암호화 + 키 없음 → Not backed up (빨강)', /badge b-high"[^>]*>Not backed up</.test(rowOf(out, 'LOCKOUT')));
T('⛔ 암호화 안 됨 + 키 없음 → 빨강 아님', /badge b-zero">No key</.test(rowOf(out, 'PLAIN')) && !/b-high/.test(rowOf(out, 'PLAIN')));
T('비 Windows → —', /badge b-zero">—</.test(rowOf(out, 'IPHONE')) && !/In Entra|Not backed up/.test(rowOf(out, 'IPHONE')));
const tile = (out.match(/<a class="kpi[^"]*"(?:(?!<\/a>).)*Encrypted, no recovery key(?:(?!<\/a>).)*<\/a>/s) || [''])[0];
T("★ KPI 타일이 위험 수를 보인다", /kpi-link bad/.test(tile) && /kpi-val">1</.test(tile), tile.slice(0, 80));
T('  ↳ 부제가 전체 대비를 말한다', /1 of 3 Windows devices have a key in Entra/.test(tile));
T('도움말이 붙는다', /Encrypted, no recovery key<\/b> = the disk is encrypted/.test(out));
const rows = [...out.matchAll(/<div class="kpis kpis-fit"[^>]*>([\s\S]*?)<\/div><div class="kpis kpis-fit"[^>]*>([\s\S]*?)<\/div>\s*<\/div><\/div>/g)][0];
T('KPI 가 두 줄로 나뉜다', !!rows);
T('  ↳ 윗줄 = 상태 (등록 · 복구 키 없음)', !!rows && /Enrolled Devices/.test(rows[1]) && /Encrypted, no recovery key/.test(rows[1]) && !/Company-owned/.test(rows[1]));
T('  ↳ 아랫줄 = 구성 (소유 · 에디션)', !!rows && /Company-owned|Windows/.test(rows[2]) && !/Enrolled Devices/.test(rows[2]));

g = boot(snapWith({ windows: 1, escrowed: 1, encryptedNoKey: 0 }, [dev('JOINED', true, true)]));
g("LANG='en'");
out = g('tabDevices(DATA)');
T('위험 0 이면 KPI 는 ok', /<a class="kpi kpi-link ok"(?:(?!<\/a>).)*Encrypted, no recovery key/s.test(out));

console.log('\n=== ③ 조회 실패 ===');
g = boot(snapWith(null, [dev('LOCKOUT', true, null)]));
g("LANG='en'");
out = g('tabDevices(DATA)');
T('★ KPI 타일 없음', !/Encrypted, no recovery key/.test(out));
T('★ 행은 — (Not backed up 아님)', !/Not backed up/.test(out) && /badge b-zero">—</.test(rowOf(out, 'LOCKOUT')));

console.log('\n=== ④ 한국어 ===');
g = boot(snapWith({ windows: 3, escrowed: 1, encryptedNoKey: 1 },
  [dev('JOINED', true, true), dev('LOCKOUT', true, false), dev('PLAIN', false, false)]));
g("LANG='ko'");
out = g('tabDevices(DATA)');
for (const s of ['Recovery key', 'In Entra', 'Not backed up', 'No key', 'Encrypted, no recovery key', 'Windows devices have a key', 'the disk is encrypted'])
  T(`영문 "${s}" 가 새지 않는다`, !out.includes(s));
T('번역이 실제로 들어간다', /백업 안 됨/.test(out) && /Windows 3대 중 1대만 Entra 에 키가 있음/.test(out));

console.log('\n=== ⑤ 손으로 받은 키 — IT 보관 (2026-10-16) ===');
const held = (d, h) => Object.assign(d, { keyHeld: Object.assign({ heldAt: '2026-10-16', where: 'IT folder', by: 'IT' }, h || {}) });
g = boot(snapWith({ windows: 3, escrowed: 1, encryptedNoKey: 1, entraNoKey: 2, heldByIt: 1, manualOrphans: [] },
  [dev('JOINED', true, true), held(dev('HELD', true, false)), dev('LOCKOUT', true, false)]));
g("LANG='en'");
out = g('tabDevices(DATA)');
T('★ 받은 기기 → Held by IT (빨강 아님)', /badge b-info"[^>]*>Held by IT</.test(rowOf(out, 'HELD')) && !/b-high/.test(rowOf(out, 'HELD')));
T('  ↳ 툴팁에 받은 날짜 · 위치 · "수동 기록"', /title="Collected by hand 2026-10-16 · IT folder - manual record/.test(rowOf(out, 'HELD')));
T('  ↳ 안 받은 기기는 여전히 Not backed up', /Not backed up/.test(rowOf(out, 'LOCKOUT')));
T('  ↳ Entra 에 있으면 In Entra 가 먼저', /In Entra/.test(rowOf(out, 'JOINED')) && !/Held by IT/.test(rowOf(out, 'JOINED')));
const tile5 = (out.match(/<a class="kpi[^"]*"(?:(?!<\/a>).)*Encrypted, no recovery key(?:(?!<\/a>).)*<\/a>/s) || [''])[0];
T('★ KPI 부제가 두 출처를 나눠 말한다', /1 in Entra · 1 held by IT \(manual\) · 3 Windows/.test(tile5), tile5.slice(0, 160));
T('IT 보관 도움말', /<b>Held by IT<\/b> = IT collected the key by hand/.test(out));
T('고아 · 오류 없으면 경고 없음', !/no longer match an enrolled device|could not be read/.test(out));

g = boot(snapWith({ windows: 1, escrowed: 0, encryptedNoKey: 1, entraNoKey: 1, heldByIt: 0,
  manualOrphans: [{ name: 'JIYOUN', heldAt: '2026-10-16' }] }, [dev('JIYOUN', true, false)]));
g("LANG='en'");
out = g('tabDevices(DATA)');
T('★ 고아 기록 → 경고(이름 · 날짜)', /1 manual key record\(s\) no longer match an enrolled device[^<]*JIYOUN \(2026-10-16\)/.test(out));
g = boot(snapWith({ windows: 1, escrowed: 0, encryptedNoKey: 1, manualError: true }, [dev('LOCKOUT', true, false)]));
g("LANG='en'");
out = g('tabDevices(DATA)');
T('★ 기록 파일 오류 → "Entra 키만 셉니다" 경고', /could not be read - counting Entra keys only/.test(out));
T('  ↳ 수동 기록이 없으면 부제는 예전 문구', /0 of 1 Windows devices have a key in Entra/.test(out));
g = boot(snapWith({ windows: 3, escrowed: 1, encryptedNoKey: 1, entraNoKey: 2, heldByIt: 1,
  manualOrphans: [{ name: 'OLD', heldAt: '2026-10-16' }] },
  [dev('JOINED', true, true), held(dev('HELD', true, false)), dev('LOCKOUT', true, false)]));
g("LANG='ko'");
out = g('tabDevices(DATA)');
for (const s of ['Held by IT', 'held by IT (manual)', 'Collected by hand', 'no longer match', 'IT collected the key'])
  T(`영문 "${s}" 가 새지 않는다`, !out.includes(s));
T('번역이 실제로 들어간다', /IT 보관/.test(out) && /Entra 1 · IT 보관\(수동\) 1 · Windows 3대/.test(out) && /손으로 받은 키 기록 1건/.test(out));

console.log();
if (fail) { console.log(`${fail} check(s) FAILED`); process.exit(1); }
console.log('all checks passed');
