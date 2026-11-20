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
  g("LANG='en'");
  return g;
}
function drafts(out) {
  return [...out.matchAll(/href="(mailto:[^"]*)"/g)].map(m => {
    const h = m[1].replace(/&amp;/g, '&').replace(/&#39;/g, "'").replace(/&quot;/g, '"');
    const q = new URLSearchParams(h.split('?')[1]);
    return { to: decodeURIComponent(h.slice(7).split('?')[0]), subject: q.get('subject') || '', body: q.get('body') || '' };
  });
}

const snap = JSON.parse(JSON.stringify(baseSnap));
snap._history = snap._history || [];
snap.threatHunting = Object.assign({ available: true }, snap.threatHunting || {}, { available: true });
const row = (cat, sender, subject, recipient) => ({ cat, sender, subject, recipient, threat: 'Phish',
  time: '2026-09-29T15:00:00Z', location: 'Inbox', msgId: 'm-' + cat });
snap.threatHunting.delivered = [
  row('external', 'bad@evil.example', 'Invoice overdue', 'a@example.com'),
  row('allow', 'partner@partner.example', 'Shipping update', 'b@example.com'),
  row('spoof', 'ceo@own-domain.example', 'Urgent wire', 'c@example.com'),
  row('internal', 'colleague@own-domain.example', 'FW: Bank form', 'd@example.com'),
];
const g = boot(snap);
const out = g('renderHunting(DATA.threatHunting)');
const ds = drafts(out).filter(d => /Malicious email received/.test(d.subject));
const by = s => ds.find(d => d.body.includes(`Sender:   ${s}`));
const ext = by('bad@evil.example'), allow = by('partner@partner.example'), spoof = by('ceo@own-domain.example');

console.log('\n=== 초안이 분류마다 하나씩 ===');
T('세 초안이 모두 그려진다', !!ext && !!allow && !!spoof, `${ds.length}개`);

const UNBLOCK = /misjudge a legitimate email[\s\S]*unblock the domain/;
console.log('\n=== ① 오판 · 도메인 해제 요청 ===');
T('★ 외부 발신자 초안에 있다', !!ext && UNBLOCK.test(ext.body));
T('  ↳ 그 도메인 이름을 적는다', !!ext && /unblock the domain "evil\.example"/.test(ext.body));
T('  ↳ 차단 문장과 같이 있다(차단한다고 쓴 경우에만 해제를 말함)', !!ext && /"evil\.example" is being blocked/.test(ext.body));
T('⛔ 허용 목록 초안에는 없다 — 이미 "false positive" 문장이 있음',
  !!allow && !UNBLOCK.test(allow.body) && /false positive/.test(allow.body));
T('⛔ 자사 사칭 초안에는 없다 — 풀 도메인이 우리 도메인',
  !!spoof && !UNBLOCK.test(spoof.body) && !/unblock/i.test(spoof.body));
const internal = by('colleague@own-domain.example');
T('⛔ 사내 전달 초안: 도메인 차단·해제를 말하지 않는다 — 우리 도메인',
  !!internal && !UNBLOCK.test(internal.body) && !/is being blocked/.test(internal.body));
T('  ↳ "사칭" 이라고 하지 않고 사내 발송이라고 쓴다',
  !!internal && !/forged/.test(internal.body) && /sent from inside our organization/.test(internal.body));
T('  ↳ "Thank you." 앞에 온다(맺음말이 마지막)', !!ext && /unblock the domain "evil\.example"\.\r?\n\r?\nThank you\.$/.test(ext.body));

console.log('\n=== ② 09-28 문구 유지 ===');
for (const [n, d] of [['외부', ext], ['허용', allow], ['사칭', spoof]]) {
  const b = d ? d.body : '';
  T(`${n}: 받은편지함에 없으면 이미 지워짐`, /If you cannot find it in your Inbox, it has already been removed/.test(b));
  T(`${n}: 안 눌렀으면 추가 조치 없음`, /no further action is needed/.test(b));
}

console.log();
if (fail) { console.log(`${fail} check(s) FAILED`); process.exit(1); }
console.log('all checks passed');
