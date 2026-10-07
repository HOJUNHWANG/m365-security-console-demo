const fs = require('fs'), vm = require('vm');
const html = fs.readFileSync('app/static/index.html', 'utf8');
const js = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]).pop();
const snap = JSON.parse(fs.readFileSync('app/static/demo-summary.json', 'utf8'));
snap._history = snap._history || [];

let fail = 0;

const UPSTREAM_GAPS = [
  'Conditional Access evaluates the Entra device object',
  'points at an MDM-only stub',
  'instead of the real registration',
  'sources are being served',
  'since worker start',
  'secureScoreActions',
  'in CA-Pilot-Users',
  'med', 'high', 'low', 'informational',
  'complete',
];
const UPSTREAM_LITERALS = [
  'Microsoft-side',
  'Collect window',
  'active now',
];
const INTERPOLATED = /\d/;
const upstream = s => UPSTREAM_GAPS.some(g => String(s).includes(g))
  || UPSTREAM_LITERALS.some(g => String(s).includes(g))
  || INTERPOLATED.test(String(s));

const T = (name, ok, extra) => {
  console.log(`  ${ok ? 'ok  ' : 'FAIL'} ${name}${extra ? '  ' + extra : ''}`);
  if (!ok) fail++;
};

const noop = () => {};
function makeEl() {
  return {
    _html: '', hidden: [],
    set innerHTML(v) { this._html = v; }, get innerHTML() { return this._html; },
    querySelectorAll(sel) {
      if (sel !== '[data-pt]') return [];
      const self = this;
      return [...this._html.matchAll(/data-pt="([^"]*)"/g)].map(m => ({
        getAttribute: () => m[1].replace(/&amp;/g, '&').replace(/&#39;/g, "'").replace(/&quot;/g, '"'),
        style: { set display(v) { self.hidden.push(m[1]); }, get display() { return ''; } },
      }));
    },
    addEventListener: noop, appendChild: noop, setAttribute: noop, getAttribute: () => null,
    removeAttribute: noop, classList: { add: noop, remove: noop, toggle: noop, contains: () => false },
    style: { setProperty: noop }, textContent: '', value: '', scrollTop: 0, dataset: {},
    querySelector: () => makeEl(), focus: noop, closest: () => null, disabled: false, title: '',
  };
}
const main = makeEl(), nav = makeEl(), doc = makeEl();
doc.documentElement = makeEl(); doc.body = makeEl(); doc.hidden = false;
doc.getElementById = id => (id === 'main' ? main : id === 'nav' ? nav : makeEl());
doc.querySelector = () => makeEl(); doc.querySelectorAll = () => []; doc.createElement = () => makeEl();
const sb = {
  window: { addEventListener: noop, matchMedia: () => ({ matches: false, addEventListener: noop }) },
  document: doc, location: { hash: '', href: '', search: '' },
  localStorage: { getItem: () => null, setItem: noop },
  navigator: { language: 'en-US' }, URLSearchParams,
  setTimeout: noop, setInterval: noop, clearInterval: noop, history: { replaceState: noop },
  fetch: () => Promise.resolve({ json: () => Promise.resolve(snap), ok: true }),
  console: { log: noop, warn: noop, error: noop },
  crypto: require('crypto').webcrypto,
};
sb.globalThis = sb;
const ctx = vm.createContext(sb);
vm.runInContext(js, ctx, { filename: 'app.js' });
const g = e => vm.runInContext(e, ctx);
g('DATA = ' + JSON.stringify(snap));

const DICT = g('I18N').ko;
console.log(`  dictionary: ${Object.keys(DICT).length} entries\n`);
T('dictionary is populated', Object.keys(DICT).length > 400, `${Object.keys(DICT).length}`);

const miss = new Set();
sb.__miss = miss;
g('T_MISS = globalThis.__miss');
const ids = [];
for (const p of g('PARENTS')) {
  for (const id of (p.children ? p.children.map(c => c.id) : [p.id])) ids.push(id);
}
let renderFail = [];
for (const lang of ['ko', 'en']) {
  g(`LANG = ${JSON.stringify(lang)}`);
  for (const id of ids) {
    g(`active = ${JSON.stringify(id)}`);
    try { ctx.renderMain(); ctx.renderNav(); }
    catch (e) { renderFail.push(`${lang}/${id}: ${e.message}`); }
  }
  try { ctx.renderHealth(); ctx.renderAge(); } catch (e) { renderFail.push(`${lang}/header: ${e.message}`); }
}
g('T_MISS = null');
T('every tab renders in both languages', renderFail.length === 0, renderFail.slice(0, 3).join(' | '));
const missLive = [...miss].filter(s => !upstream(s));
T('★ no untranslated string reaches t() while rendering', missLive.length === 0,
  missLive.slice(0, 5).map(s => s.slice(0, 60)).join(' | '));

const dictLines = js.match(/^[ \t]*I18N\.ko\[.*$/gm) || [];
const dictBlock = dictLines.length
  ? js.slice(js.indexOf(dictLines[0]), js.lastIndexOf(dictLines[dictLines.length - 1])
      + dictLines[dictLines.length - 1].length)
  : '';
const code = js.replace(dictBlock, '').replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/^\s*\/\/.*$/gm, ' ');
const LIT = "'((?:[^'\\\\]|\\\\.)*)'";
const seen = new Map();
const add = (s, who) => {
  const v = s.replace(/\\'/g, "'").replace(/\\\\/g, '\\');
  if (!seen.has(v)) seen.set(v, new Set());
  seen.get(v).add(who);
};
for (const [pat, who] of [
  [`\\bt\\(\\s*${LIT}`, 't()'], [`\\btf\\(\\s*${LIT}`, 'tf()'],
  [`\\bhelp\\(\\s*${LIT}`, 'help()'], [`\\bpanel\\(\\s*${LIT}`, 'panel()'],
  [`\\bsev\\(\\s*${LIT}`, 'sev()'],
]) for (const m of code.matchAll(new RegExp(pat, 'g'))) add(m[1], who);
for (const m of code.matchAll(new RegExp(`\\bkpi\\([^,]+,\\s*${LIT}\\s*,\\s*${LIT}`, 'g'))) {
  add(m[1], 'kpi()'); add(m[2], 'kpi()');
}
for (const m of code.matchAll(new RegExp(`\\bkpi\\([^,]+,\\s*${LIT}`, 'g'))) add(m[1], 'kpi()');
for (const m of code.matchAll(/\btable\(\s*\[([^\]]*)\]/g))
  for (const lm of m[1].matchAll(new RegExp(LIT, 'g'))) add(lm[1], 'table()');

const HANGUL = /[가-힣]/, LATIN = /[A-Za-z]/;
const keys = Object.keys(DICT);
const staticMissing = [...seen.keys()].filter(s =>
  s && !(s in DICT) && LATIN.test(s) && !HANGUL.test(s) && !upstream(s)
  && !keys.some(k => k.includes(s)));
T('★ every literal reaching a render helper has an entry', staticMissing.length === 0,
  staticMissing.slice(0, 5).map(s => s.slice(0, 60)).join(' | '));

const HTMLTAG = /<\/?(?:b|i|u|em|strong|code|br|span|div|a|p)\b[^>]*>/i;
const escaped = new Set();
for (const m of code.matchAll(new RegExp(`\\besc\\(\\s*t\\(\\s*${LIT}`, 'g'))) escaped.add(m[1]);
for (const m of code.matchAll(new RegExp(`\\bpanel\\(\\s*${LIT}\\s*,\\s*${LIT}`, 'g'))) { escaped.add(m[1]); escaped.add(m[2]); }
for (const m of code.matchAll(new RegExp(`\\bpanel\\(\\s*${LIT}`, 'g'))) escaped.add(m[1]);
for (const m of code.matchAll(new RegExp(`\\bsev\\(\\s*${LIT}`, 'g'))) escaped.add(m[1]);
const unescape = s => s.replace(/\\'/g, "'").replace(/\\\\/g, '\\');
const tagLeak = [];
for (const raw of escaped) {
  const k = unescape(raw);
  if (HTMLTAG.test(k)) tagLeak.push(`키: ${k.slice(0, 50)}`);
  const v = DICT[k];
  if (v && HTMLTAG.test(v)) tagLeak.push(`ko: ${k.slice(0, 40)} -> ${v.match(HTMLTAG)[0]}`);
}
T('★★ 이스케이프되는 자리에 HTML 태그가 없다 — 있으면 글자로 보입니다',
  tagLeak.length === 0, tagLeak.slice(0, 4).join(' | '));
console.log(`  (이스케이프되는 리터럴 ${escaped.size}개 검사)`);

const holeBad = [];
for (const [k, v] of Object.entries(DICT)) {
  const inKey = [...new Set([...k.matchAll(/\{(\d+)\}/g)].map(m => m[1]))].sort();
  const inVal = [...new Set([...v.matchAll(/\{(\d+)\}/g)].map(m => m[1]))].sort();
  if (inKey.join(',') !== inVal.join(',')) holeBad.push(`${k.slice(0, 50)} -> {${inVal}} (expected {${inKey}})`);
}
T('★ every {n} in a key survives into the Korean', holeBad.length === 0, holeBad.slice(0, 4).join(' | '));

const empty = Object.entries(DICT).filter(([, v]) => !String(v).trim()).map(([k]) => k);
T('no entry translates to an empty string', empty.length === 0, empty.slice(0, 3).join(' | '));

g('LANG = "ko"');
g('active = "overview"');
ctx.renderMain();
const koHtml = main.innerHTML;
g('LANG = "en"');
ctx.renderMain();
const enHtml = main.innerHTML;
T('Korean render differs from English', koHtml !== enHtml);
T('Korean render actually contains Hangul', HANGUL.test(koHtml));
T('English render contains no Hangul', !HANGUL.test(enHtml.replace(/[가-힣]*$/, '')) || !HANGUL.test(enHtml));

const pt = h => [...h.matchAll(/data-pt="([^"]*)"/g)].map(m => m[1]).join('|');
g('LANG = "ko"'); ctx.renderMain(); const koPt = pt(main.innerHTML);
g('LANG = "en"'); ctx.renderMain(); const enPt = pt(main.innerHTML);
T('★ data-pt (sub-tab routing) is language-independent', koPt === enPt, `${koPt.slice(0, 40)}…`);

g('setLang("ko")');
T('setLang switches the language', g('LANG') === 'ko');
g('setLang("zz")');
T('setLang ignores an unknown language', g('LANG') === 'ko');

g('LANG = "ko"');
const hard = [];
for (const par of g('PARENTS')) {
  for (const id of (par.children ? par.children.map(c => c.id) : [par.id])) {
    g(`active = ${JSON.stringify(id)}`);
    ctx.renderMain();
    const segs = main.innerHTML
      .replace(/<style[\s\S]*?<\/style>/g, '')
      .replace(/<[^>]*>/g, '\x01')
      .replace(/&amp;/g, '&').replace(/&#39;/g, "'").replace(/&quot;/g, '"')
      .split(/[\x01\n·|]+/);
    for (let s of segs) {
      s = s.trim();
      if (!s || HANGUL.test(s)) continue;
      if ((s.match(/[A-Za-z][a-z]{2,}/g) || []).length < 3) continue;
      if (/[@\\/=]|https?:/.test(s)) continue;
      if (!code.includes(s) || (s in DICT)) continue;
      const literal = [`'${s}'`, `"${s}"`, '`' + s + '`'].some(q => code.includes(q));
      const insideAKey = keys.some(k => k.includes(s));
      if ((literal || !insideAKey) && !hard.includes(s) && !upstream(s)) hard.push(`${id}: ${s.slice(0, 70)}`);
    }
  }
}
T('★ no hardcoded English sentence renders in Korean mode', hard.length === 0,
  hard.slice(0, 4).join(' | '));

console.log(fail ? `\n${fail} FAILURE(S)` : '\nall checks passed');
process.exit(fail ? 1 : 0);
