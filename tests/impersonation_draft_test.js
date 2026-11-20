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
    return { raw: h, to: decodeURIComponent(h.slice(7).split('?')[0]), subject: q.get('subject') || '', body: q.get('body') || '' };
  });
}

const S = (o) => Object.assign({ hosts: [], why: 'tld', firstSeen: '2026-07-24T19:15:06Z', inbound: 5, delivered: 0, replies: 0,
  repliedBy: [], recipients: [], recipientCount: 0, senders: [], subjects: [], sameLocalParts: [], blocked: false }, o);
const suspects = [
  S({ level: 'replied', domain: 'partn3r.example', looksLike: 'partner.example', why: 'homoglyph', delivered: 4, replies: 2,
      recipients: ['A@contoso.com', 'b@contoso.com'], repliedBy: ['c@contoso.com', 'a@contoso.com'],
      senders: ['jane.doe@partn3r.example'], sameLocalParts: ['jane.doe'], subjects: ['Re: Invoice'] }),
  S({ level: 'blocked', domain: 'partner.co', looksLike: 'partner.example', delivered: 3, replies: 1, blocked: true,
      recipients: ['d@contoso.com'], repliedBy: ['d@contoso.com'] }),
  S({ level: 'delivered', domain: 'vendor-billing.example', looksLike: 'vendor.example', why: 'contains', delivered: 2,
      recipients: ['e@contoso.com'] }),
  S({ level: 'quarantined', domain: 'quiet.example', looksLike: 'quieter.example', recipients: ['f@contoso.com'] }),
  S({ level: 'blocked', domain: 'nobody.org', looksLike: 'nobody.com', blocked: true, recipients: ['g@contoso.com'] }),
];
const snap = JSON.parse(JSON.stringify(baseSnap));
snap._history = snap._history || [];
snap.exchangeEop = Object.assign({}, snap.exchangeEop || {}, { available: true, impersonation: {
  listsCollected: true, traceCollected: true, windowStart: '2026-07-16', windowEnd: '2026-10-14', windowDays: 91,
  suspects, similarPartners: [], protectGaps: [], policies: [], protectDomains: [], protectUsers: [], trustDomains: [], trustSenders: [], blockList: [],
  confirmedReal: [
    { domain: 'friend.ca', looksLike: 'friend.com', why: 'tld', reason: 'phone check', checkedAt: '2026-10-15', by: 'IT', lastSeen: '2026-10-20T10:00:00Z', inbound: 3, replies: 0,
      newSenders: ['new.person@friend.ca'], newHosts: [], newSinceCheck: true },
    { domain: 'other.ca', looksLike: 'other.com', why: 'tld', reason: 'subject check', checkedAt: '2026-10-15', by: 'IT', lastSeen: '2026-10-21T10:00:00Z', inbound: 3, replies: 0,
      newSenders: [], newHosts: [], newSinceCheck: false },
  ],
  counts: { replied: 1, delivered: 1, quarantined: 1, blocked: 2, similarPartners: 0, confirmedReal: 2, blockList: 0, protectDomains: 0, protectUsers: 0, trustDomains: 0 } } });

const g = boot(snap);
const out = g('impersonationPanels(DATA.exchangeEop)');
const ds = drafts(out).filter(d => /Please double-check emails from/.test(d.subject));
const by = dom => ds.find(d => d.subject.endsWith(dom));
const rep = by('partn3r.example'), del = by('vendor-billing.example');

console.log('\n=== ② ✉ 가 필요한 곳에만 · 차단된 도메인은 표에 없다 ===');
T('초안 2개(회신함 · 도착)', ds.length === 2, `${ds.length}개`);
T('⛔ 격리만 된 도메인에는 없다', !by('quiet.example'));
T('★ 이미 차단된 도메인은 표에 행이 없다(받은 사람이 있어도)', !/>partner\.co</.test(out) && !/>nobody\.org</.test(out) && !by('partner.co'));
T('  ↳ 대신 몇 개가 빠졌고 어디 있는지 알려 준다', /2 already-blocked look-alike domain\(s\) are not listed here/.test(out));
T('  ↳ KPI 에는 남는다', /Already blocked/.test(out));
T('  ↳ 차단 안 된 의심은 그대로', />partn3r\.example</.test(out) && />vendor-billing\.example</.test(out) && />quiet\.example</.test(out));
T('"Blocked" 단계 배지는 더 이상 나오지 않는다', !/class="badge b-ok nw">Blocked</.test(out));

console.log('\n=== ① 사실 문장 ===');
const REPLIED = /replies were sent from our side/, SAME = /same name as a contact at/;
T('"차단됨" 문장은 어느 초안에도 없다(차단 도메인은 초안이 없음)', ds.every(d => !/This domain is now blocked/.test(d.body)));
T('★ "회신했음" 은 발신 기록이 있을 때만', REPLIED.test(rep.body) && !REPLIED.test(del.body));
T('★ "같은 이름" 은 그 이름을 진짜 쪽에서 봤을 때만', SAME.test(rep.body) && !SAME.test(del.body));
for (const [n, d] of [['회신함', rep], ['도착', del]]) {
  T(`${n}: 기존 연락처로 전화 확인하라`, !!d && /by phone, using a number you already have on file/.test(d.body));
  T(`${n}: ⛔ "이미 회신 · 송금했으면 알려 달라" 줄은 없다(10-14 운영자 요청)`, !!d && !/let me know right away/.test(d.body) && !/made or approved a payment/.test(d.body));
  T(`${n}: 진짜면 알려 달라(기록하겠다)`, !!d && /so I can unblock it and record it/.test(d.body));
  T(`${n}: ★ 차단 예정을 알린다 — 보낸 그 도메인 이름으로`, !!d && new RegExp(`emails from "${n === '회신함' ? 'partn3r' : 'vendor-billing'}\\.example" will be blocked`).test(d.body));
  T(`${n}: 맺음말이 마지막`, !!d && /Thank you\.$/.test(d.body));
}
T('보낸 주소 · 제목은 있을 때만 줄을 만든다', /Sender address:  jane\.doe@partn3r\.example/.test(rep.body) && !/Sender address:/.test(del.body)
  && /Recent subject:  Re: Invoice/.test(rep.body) && !/Recent subject:/.test(del.body));

console.log('\n=== ③ 수신자 ===');
const to = rep ? rep.to.split(';') : [];
T('★ 받은 사람 + 회신한 사람 전부, 중복 없이', to.length === 3 && ['a@contoso.com', 'b@contoso.com', 'c@contoso.com'].every(a => to.includes(a)), rep && rep.to);
T('소문자로 맞춘다(같은 사람이 두 번 들어가지 않게)', !to.some(a => /[A-Z]/.test(a)));

console.log('\n=== ④ Outlook ===');
T('주소 구분은 ; (콤마 아님)', !!rep && !rep.raw.split('?')[0].includes(',') && rep.raw.split('?')[0].includes(';'));
T('빈 매개변수가 없다(빈 cc= 금지)', ds.every(d => !/[?&](cc|bcc)=(&|$)/.test(d.raw)));

console.log('\n=== ⑥ 길이 (메일 프로그램은 2,000자 안팎에서 mailto 를 자름) ===');
T('★ 모든 초안이 1,900자 이하', ds.every(d => d.raw.length <= 1900), ds.map(d => d.raw.length).join(','));
const many = JSON.parse(JSON.stringify(snap));
many.exchangeEop.impersonation.suspects = [S({ level: 'delivered', domain: 'long.example', looksLike: 'longer.example', delivered: 9,
  recipients: Array.from({ length: 34 }, (_, i) => `personXY${i}@contoso.com`), subjects: ['A fairly long subject line about an invoice and a bank change request'] })];
const g2 = boot(many);
const long = drafts(g2('impersonationPanels(DATA.exchangeEop)')).find(d => /long\.example/.test(d.subject));
T('  ↳ 넘치면 제목 예시 줄을 먼저 뺀다', !!long && !/Recent subject:/.test(long.body), long && long.raw.length);
T('  ↳ 그래도 수신자는 전부 남긴다', !!long && long.to.split(';').length === 34);
T('  ↳ 제목 줄을 빼면 한도 안에 들어간다', !!long && long.raw.length <= 1900, long && long.raw.length);

console.log('\n=== ⑤ 확인된 정상 ===');
T('목록이 보인다(사라지지 않는다)', /Confirmed real \(recorded, not raised\)/.test(out) && /friend\.ca/.test(out) && /other\.ca/.test(out));
T('★ 확인 뒤 새 주소는 표시 · 그 주소를 보여 준다', /new sender address/.test(out) && /new\.person@friend\.ca/.test(out));
T('★ 알던 주소의 평소 메일은 표시하지 않고 마지막 날짜만(10-14 운영자: 매주 오는 곳이 늘 "새 메일")',
  /no new address · last mail 2026-10-21/.test(out) && !/new mail · last/.test(out));
T('새 주소가 있으면 펼쳐서 보여 준다',/<details class="del-acc" style="margin-top:8px" open><summary><span class="del-caret">▸<\/span><span class="del-name">Confirmed real/.test(out));

console.log('\n=== ⑦ 고정 참조(.env IMPERSONATION_NOTIFY_CC · 10-14 운영자 요청) ===');
T('설정이 비면 cc= 자체가 없다', ds.every(d => !/[?&]cc=/.test(d.raw)));
const ccSnap = JSON.parse(JSON.stringify(snap));
ccSnap.exchangeEop.impersonation.notifyCc = 'Boss@contoso.com; cfo@contoso.com, a@contoso.com';
const g3 = boot(ccSnap);
const ccDs = drafts(g3('impersonationPanels(DATA.exchangeEop)')).filter(d => /Please double-check emails from/.test(d.subject));
const ccOf = d => decodeURIComponent((d.raw.match(/[?&]cc=([^&]*)/) || [])[1] || '').split(';').filter(Boolean);
const rep3 = ccDs.find(d => d.subject.endsWith('partn3r.example'));
T('★ 모든 초안에 참조가 붙는다', ccDs.length === 2 &&ccDs.every(d => ccOf(d).includes('boss@contoso.com') && ccOf(d).includes('cfo@contoso.com')),
  ccDs.map(d => ccOf(d).join(',')).join(' | '));
T('  ↳ 받는 사람에 이미 있는 사람은 참조에서 뺀다', !!rep3 && !ccOf(rep3).includes('a@contoso.com') && rep3.to.split(';').includes('a@contoso.com'));
T('  ↳ ; 로 구분 · 소문자', !!rep3 && /cc=boss@contoso\.com;cfo@contoso\.com/.test(rep3.raw));

console.log('\n=== ⑧ 정상 기록 버튼 (대시보드 PC 에서만) ===');
const outRO = g('impersonationPanels(DATA.exchangeEop)');
T('읽기 전용이면 ✓ 가 없다', !/impRecord\(/.test(outRO));
T('  ↳ 대신 어디서 되는지 알려 준다', /appears only when this dashboard is opened on the dashboard PC itself/.test(outRO));
T('  ↳ 확인된 정상에 해제 ✕ 도 없다', !/impUnrecord\(/.test(outRO));
g('EDIT = {canEdit:true}');
const outRW = g('impersonationPanels(DATA.exchangeEop)');
const recFor = d => new RegExp(`impRecord\\('${d.replace(/\./g, '\\.')}'\\)`).test(outRW);
T('★ 편집 가능하면 차단 안 된 의심에 ✓', recFor('partn3r.example') && recFor('vendor-billing.example') && recFor('quiet.example'));
T('⛔ 차단된 도메인에는 ✓ 없음', !recFor('partner.co') && !recFor('nobody.org'));
T('확인된 정상에 해제 ✕', /impUnrecord\('friend\.ca'\)/.test(outRW) && /impUnrecord\('other\.ca'\)/.test(outRW));
T('안내 문구는 사라진다', !/appears only when this dashboard is opened on the dashboard PC itself/.test(outRW));

console.log('\n=== ⑨ ✉ 칸이 줄바꿈되지 않는다 (10-14 화면: 숫자가 아이콘 아래로 내려감) ===');
T('✉ · ✓ 를 nowrap 으로 감싼다', /<td><span class="nw"><a class="rowlink" href="mailto:/.test(outRW));

console.log('\n=== ⑩ 의심이 전부 차단된 경우 ===');
const allBlk = JSON.parse(JSON.stringify(snap));
allBlk.exchangeEop.impersonation.suspects = suspects.filter(s => s.level === 'blocked');
const outB = boot(allBlk)('impersonationPanels(DATA.exchangeEop)');
T('★ "아무도 안 보냈다" 가 아니라 "전부 차단됐다" 고 말한다',
  /Every look-alike that wrote to us in this window is already blocked/.test(outB) && !/No look-alike of a partner has written to us/.test(outB));
T('  ↳ 표는 없다', !/>Sender domain</.test(outB) && />Sender domain</.test(out));
const noneSnap = JSON.parse(JSON.stringify(snap));
noneSnap.exchangeEop.impersonation.suspects = [];
const outN = boot(noneSnap)('impersonationPanels(DATA.exchangeEop)');
console.log('\n=== ⑪ 하위 도메인에서 온 메일 (10-14 lk1zz.example: 표는 lk1zz.example · 초안 보낸 주소는 lk2zzzzzzz.example) ===');
const subSnap = JSON.parse(JSON.stringify(snap));
subSnap.exchangeEop.impersonation.suspects = [
  S({ level: 'delivered', domain: 'bgr.example', looksLike: 'gr.example', why: 'edit1', delivered: 2, hosts: ['cpsg.bgr.example'],
      senders: ['c.person@cpsg.bgr.example'], recipients: ['h@contoso.com'] }),
  S({ level: 'delivered', domain: 'multi.example', looksLike: 'mult.example', why: 'edit1', delivered: 2, hosts: ['a.multi.example', 'multi.example'],
      senders: ['x@a.multi.example', 'y@multi.example'], recipients: ['i@contoso.com'] }),
];
const outS = boot(subSnap)('impersonationPanels(DATA.exchangeEop)');
const dS = drafts(outS).filter(d => /Please double-check emails from/.test(d.subject));
const one = dS.find(d => /bgr\.example/.test(d.subject)), multi = dS.find(d => /multi\.example/.test(d.subject));
T('★ 보낸 곳이 하나면 제목 · 첫 문장이 받은편지함에 보이는 그 이름(하위 도메인)',
  !!one && one.subject.endsWith('emails from cpsg.bgr.example') && /messages from "cpsg\.bgr\.example"/.test(one.body), one && one.subject);
T('  ↳ 보낸 주소 줄과 어긋나지 않는다', !!one && /Sender address:  c\.person@cpsg\.bgr\.example/.test(one.body));
T('보낸 곳이 여럿이면 공통 이름(등록 도메인)', !!multi && multi.subject.endsWith('emails from multi.example') && /messages from "multi\.example"/.test(multi.body));
T('표에도 도메인 아래 실제 보낸 곳을 보여 준다', /bgr\.example<\/span><div class="muted mono"[^>]*>cpsg\.bgr\.example<\/div>/.test(outS));
T('  ↳ 도메인 자체만 보낸 곳이면 덧붙이지 않는다', />partn3r\.example<\/span><\/td>/.test(out));
T('의심이 아예 없으면 원래 문구 · 차단 안내 없음',/No look-alike of a partner has written to us/.test(outN) && !/already-blocked look-alike/.test(outN));

console.log('\n⑥ 부재중 자동 회신');
const arSnap = JSON.parse(JSON.stringify(snap));
arSnap.exchangeEop.impersonation.suspects = [
  S({ level: 'delivered', domain: 'auto.example', looksLike: 'auto.com', delivered: 2, replies: 0, autoReplies: 2, recipients: ['e@contoso.com'] }),
  S({ level: 'replied', domain: 'mixed.example', looksLike: 'mixed.com', delivered: 2, replies: 1, autoReplies: 3,
      recipients: ['e@contoso.com'], repliedBy: ['e@contoso.com'] }),
];
const outA = boot(arSnap)('impersonationPanels(DATA.exchangeEop)');
const rowOf = d => (outA.match(new RegExp('<tr[^>]*>(?:(?!</tr>)[\\s\\S])*' + d.replace('.', '\\.') + '[\\s\\S]*?</tr>')) || [''])[0];
const ra = rowOf('auto.example'), rm = rowOf('mixed.example');
T('★ 자동 회신만 → 우리 회신 0 + 회색 "2 auto-reply" · 빨강 "sent" 없음', /badge b-zero"[^>]*>2 auto-reply</.test(ra) && !/\d sent</.test(ra));
T('진짜 회신 + 자동 → "1 sent" 빨강 + "3 auto-reply" 회색', /b-high"[^>]*>1 sent</.test(rm) && /b-zero"[^>]*>3 auto-reply</.test(rm));
const coll = fs.existsSync('scripts/exo_collector.ps1') ? fs.readFileSync('scripts/exo_collector.ps1', 'utf8') : '';
const m = coll.match(/\[string\]\$r\.Subject -match '([^']+)'\) \{ \$v\.auto\+\+; continue \}/);
const re = m && new RegExp(m[1].replace(/\\\\/g, '\\'), 'i');
T('수집기에 자동 회신 판정이 있다(n · 보낸 사람 · 시각 앞에서 continue)', !coll || !!re);
if (re) {
  for (const sj of ['Automatic reply: Your Atradius News', 'AUTOMATIC REPLY: x', 'Auto-Reply: x', 'Autoreply: x', 'Out of Office: x', '자동 회신: 견적', '부재중: x'])
    T(`  ↳ 자동 회신으로 봄: ${sj}`, re.test(sj));
  for (const sj of ['RE: Automatic reply settings question', 'Re: HD Hyundai Electric America 1382368 Invoice', 'FW: out of office plan'])
    T(`  ↳ 사람 회신은 그대로: ${sj}`, !re.test(sj));
}

console.log();
if (fail) { console.log(`${fail} check(s) FAILED`); process.exit(1); }
console.log('all checks passed');
