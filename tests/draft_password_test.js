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
  const counts = { crypto: 0, mathRandom: 0 };
  const real = require('crypto').webcrypto;
  const doc = makeEl(), main = makeEl(), nav = makeEl();
  doc.documentElement = makeEl(); doc.body = makeEl(); doc.hidden = false;
  doc.getElementById = id => (id === 'main' ? main : id === 'nav' ? nav : makeEl());
  doc.querySelector = () => makeEl(); doc.querySelectorAll = () => []; doc.createElement = () => makeEl();
  const MathProxy = Object.create(Math);
  MathProxy.random = () => { counts.mathRandom++; return 0.5; };
  const sb = {
    window: { addEventListener: noop, matchMedia: () => ({ matches: false, addEventListener: noop }) },
    document: doc, location: { hash: '', href: '', search: '' },
    localStorage: { getItem: () => null, setItem: noop },
    navigator: { language: 'en-US' }, URLSearchParams, Math: MathProxy,
    crypto: { getRandomValues: a => { counts.crypto++; return real.getRandomValues(a); } },
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
  return { g, counts };
}

const clone = o => JSON.parse(JSON.stringify(o));

const snap = clone(baseSnap);
snap._history = snap._history || [];
snap.threatHunting = snap.threatHunting || { available: true };
snap.threatHunting.clickedThreats = [{
  state: 'late', user: 'clicker@example.com', firstClick: '2026-09-10T22:36:48Z',
  lastClick: '2026-09-10T22:39:55Z', clickCount: 2, throughCount: 0, action: 'ClickAllowed',
  url: 'https://example.invalid/x', zapTime: '2026-09-11T11:53:42Z', threat: 'Phish',
  sender: 'bad@example.net', subject: 'Invoice reminder', received: '2026-09-10T22:18:49Z',
  recipients: ['other1@example.com', 'clicker@example.com', 'other2@example.com'],
  others: ['other1@example.com', 'other2@example.com'], msgId: 'testmsg1',
}];

function drafts(out) {
  return [...out.matchAll(/href="(mailto:[^"]*)"/g)].map(m => {
    const h = m[1].replace(/&amp;/g, '&').replace(/&#39;/g, "'").replace(/&quot;/g, '"');
    const q = new URLSearchParams(h.split('?')[1]);
    return { to: decodeURIComponent(h.slice(7).split('?')[0]),
             subject: q.get('subject') || '', body: q.get('body') || '' };
  });
}
const unesc = s => String(s).replace(/&amp;/g,'&').replace(/&lt;/g,'<').replace(/&gt;/g,'>')
                            .replace(/&quot;/g,'"').replace(/&#39;/g,"'");
const panelPw = out => {
  const m = out.match(/title="Reset the account to exactly this[^"]*">([^<]+)</);
  return m ? unesc(m[1]) : undefined;
};

console.log('\n=== 난수원 ===');
const b1 = boot(snap);
const pws = Array.from({ length: 200 }, () => b1.g('genTempPassword()'));
T('⛔ Math.random() 을 쓰지 않는다', b1.counts.mathRandom === 0, `호출 ${b1.counts.mathRandom}회`);
T('★ crypto.getRandomValues 를 쓴다', b1.counts.crypto > 200, `호출 ${b1.counts.crypto}회`);
T('200개가 전부 서로 다르다', new Set(pws).size === 200, `${new Set(pws).size}/200`);
T('길이 16', pws.every(p => p.length === 16));
T('네 가지 문자 종류를 모두 포함', pws.every(p =>
  /[A-Z]/.test(p) && /[a-z]/.test(p) && /[0-9]/.test(p) && /[^A-Za-z0-9]/.test(p)));
T('⚠ 헷갈리는 글자(I l 1 O 0)가 없다 — 사람이 보고 칩니다',
  pws.every(p => !/[Il1O0]/.test(p)));

console.log('\n=== 어느 편지에 들어가는가 ===');
const b2 = boot(snap);
const out2 = b2.g('tabHunting(DATA)');
const pw = panelPw(out2);
T('★ 패널이 임시 비밀번호를 보여준다', !!pw && pw.length === 16, pw ? `${pw.length}자` : '(없음)');
const d2 = drafts(out2);
const toClicker = d2.find(d => /Action required/.test(d.subject));
const toOthers = d2.find(d => /removed from your mailbox/.test(d.subject));
T('★★ 클릭한 사람의 편지에 들어간다', !!toClicker && toClicker.body.includes(pw));
T('  ↳ 화면에 보이는 값과 편지의 값이 같다',
  !!toClicker && toClicker.body.includes(`Temporary password:  ${pw}`));
T('⛔ 클릭하지 않은 수신자의 편지에는 **없다**',
  !!toOthers && !toOthers.body.includes(pw) && !/[Tt]emporary password/.test(toOthers.body));
T('  ↳ 그 편지 수신자는 클릭자를 빼고 2명', !!toOthers && toOthers.to.split(';').length === 2, toOthers && toOthers.to);

console.log('\n=== 문구 ===');
{
  const b = toClicker ? toClicker.body : '';
  T('⛔ "did wrong" 류의 면죄부가 없다', !!b && !/did wrong|not your fault/i.test(b));
  T('★ 대신 통제에 대한 사실 진술이 있다', /Safe Links did not block it/.test(b));
  T('★ 빨리 알리는 편이 낫다는 문장이 있다', /matters far more/.test(b));
  T('⚠ 배너 언급은 조건절이다 (단정 아님)', /if Outlook showed/i.test(b) && !/That message did carry/i.test(b));
}

const blocked = clone(snap);
blocked.threatHunting.clickedThreats[0].state = 'blocked';
blocked.threatHunting.clickedThreats[0].action = 'ClickBlocked';
const b3 = boot(blocked);
const out3 = b3.g('tabHunting(DATA)');
const d3 = drafts(out3).find(d => /blocked/.test(d.subject));
T('⛔ 차단된 클릭의 편지에는 비밀번호가 없다',
  !!d3 && !/[Tt]emporary password/.test(d3.body), d3 ? d3.subject : '(초안 없음)');
T('  ↳ 그 행은 패널에도 비밀번호를 띄우지 않는다', panelPw(out3) === undefined);

console.log('\n=== 재렌더 안정성 ===');
const again = b2.g('tabHunting(DATA)');
T('★★ 같은 페이지에서 다시 그리면 같은 비밀번호', panelPw(again) === pw);
b2.g("LANG='ko'");
const koOut = b2.g('tabHunting(DATA)');
T('  ↳ 언어를 바꿔도 같다 — 이미 연 초안과 어긋나면 안 됩니다', panelPw(koOut) === pw);
const b4 = boot(snap);
T('⚠ 페이지를 새로 띄우면 새 비밀번호 (재사용하지 않는다)',
  panelPw(b4.g('tabHunting(DATA)')) !== pw);

console.log('\n=== 화면↔편지 왕복 40회 ===');
let mismatch = 0, seen = new Set(), sample = '';
for (let i = 0; i < 40; i++) {
  const bb = boot(snap);
  const o = bb.g('tabHunting(DATA)');
  const p = panelPw(o);
  const body = drafts(o).find(d => /Action required/.test(d.subject)).body;
  seen.add(p);
  if (!body.includes(`Temporary password:  ${p}`)) { mismatch++; if (!sample) sample = p; }
}
T('★★ 40회 전부 화면 값 == 편지 값', mismatch === 0, mismatch ? `${mismatch}회 불일치` : '');
T('  ↳ 40회가 전부 서로 다르다', seen.size === 40, `${seen.size}/40`);

console.log();
if (fail) { console.log(`${fail} check(s) FAILED`); process.exit(1); }
console.log('all checks passed');
