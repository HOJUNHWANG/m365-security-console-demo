const fs = require('fs'), vm = require('vm');

const html = fs.readFileSync('app/static/index.html', 'utf8');
const scripts = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]);
const js = scripts[scripts.length - 1];
const prePaint = scripts.find(s => s.includes('var UI_MODES') && s.includes('var THEMES'));
const css = (html.match(/<style>([\s\S]*?)<\/style>/) || [])[1] || '';
const baseSnap = JSON.parse(fs.readFileSync('app/static/demo-summary.json', 'utf8'));
baseSnap._history = baseSnap._history || [];

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

console.log('\n=== ① 첫 화면 전 모드 선택 ===');
function prepaint(search, stored) {
  const attrs = {}, store = Object.assign({}, stored || {});
  const sb = {
    location: { search }, URLSearchParams, navigator: { language: 'ko-KR' },
    localStorage: { getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); } },
    window: {}, matchMedia: () => ({ matches: false }),
    document: { documentElement: { setAttribute: (k, v) => { attrs[k] = v; } } },
  };
  vm.runInContext(prePaint, vm.createContext(sb));
  return { attrs, store };
}
T('첫 화면 전 블록을 찾았다', !!prePaint);
T('★ 기본값은 2.0 (10-01 운영자 결정)', prepaint('', {}).attrs['data-ui'] === 'v2');
T('  ↳ 클래식을 고른 브라우저는 클래식 유지', prepaint('', { ui: 'classic' }).attrs['data-ui'] === 'classic');
T('?ui=2 → v2 (그리고 기억한다)', (r => r.attrs['data-ui'] === 'v2' && r.store.ui === 'v2')(prepaint('?ui=2', {})));
T('?ui=1 → classic', prepaint('?ui=1', { ui: 'v2' }).attrs['data-ui'] === 'classic');
T('저장된 v2 를 따른다', prepaint('', { ui: 'v2' }).attrs['data-ui'] === 'v2');
T('모르는 값은 기본값(2.0)', prepaint('?ui=zz', { ui: 'nonsense' }).attrs['data-ui'] === 'v2');
T('접힌 레일도 첫 화면 전에', prepaint('', { 'ui.rail': '1' }).attrs['data-rail'] === '1');

const noop = () => {};
function makeEl() {
  return {
    _html: '', hidden: [], attrs: {},
    set innerHTML(v) { this._html = v; }, get innerHTML() { return this._html; },
    querySelectorAll(sel) {
      if (sel !== '[data-pt]') return [];
      const self = this;
      return [...this._html.matchAll(/data-pt="([^"]*)"/g)].map(m => ({
        getAttribute: () => m[1].replace(/&amp;/g, '&').replace(/&#39;/g, "'").replace(/&quot;/g, '"'),
        style: { set display(v) { self.hidden.push(m[1]); }, get display() { return ''; } },
      }));
    },
    addEventListener: noop, appendChild: noop,
    setAttribute(k, v) { this.attrs[k] = v; }, getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; },
    removeAttribute(k) { delete this.attrs[k]; },
    classList: { add: noop, remove: noop, toggle: noop, contains: () => false },
    style: { setProperty: noop }, textContent: '', value: '', scrollTop: 0, dataset: {},
    querySelector: () => makeEl(), focus: noop, closest: () => null, disabled: false, title: '',
  };
}
const store = {};
const main = makeEl(), nav = makeEl(), doc = makeEl(), segC = makeEl(), segV = makeEl();
doc.documentElement = makeEl(); doc.body = makeEl(); doc.hidden = false;
const els = { main, nav, uiSegC: segC, uiSegV: segV };
doc.getElementById = id => els[id] || (els[id] = makeEl());
doc.querySelector = () => null; doc.querySelectorAll = () => []; doc.createElement = () => makeEl();
const sb = {
  window: { addEventListener: noop, matchMedia: () => ({ matches: false, addEventListener: noop }) },
  document: doc, location: { hash: '', href: '', search: '' },
  localStorage: { getItem: k => (k in store ? store[k] : null), setItem: (k, v) => { store[k] = String(v); } },
  navigator: { language: 'en-US' }, URLSearchParams, Math,
  crypto: require('crypto').webcrypto,
  setTimeout: noop, setInterval: noop, clearInterval: noop, history: { replaceState: noop },
  fetch: () => Promise.resolve({ json: () => Promise.resolve(baseSnap), ok: true }),
  console: { log: noop, warn: noop, error: noop },
};
sb.globalThis = sb;
const ctx = vm.createContext(sb);
vm.runInContext(js, ctx, { filename: 'app.js' });
const g = e => vm.runInContext(e, ctx);
g('DATA = ' + JSON.stringify(baseSnap));

const ids = [];
for (const p of g('PARENTS')) for (const id of (p.children ? p.children.map(c => c.id) : [p.id])) ids.push(id);
const pts = h => [...h.matchAll(/data-pt="([^"]*)"/g)].map(m => m[1]).join('|');
const render = id => { g(`active = ${JSON.stringify(id)}`); ctx.renderNav(); ctx.renderMain(); return main.innerHTML; };

console.log('\n=== ① 토글 ===');
g("LANG='en'");
T('스크립트 단독 실행 시 기본 클래식', g('UI') === 'classic');
let out = render('overview');
T('클래식 화면에는 v2 머리가 없다', !/v2-head/.test(out) && /class="tab-head"/.test(out));
T('클래식에서 1.0/2.0 토글 = 1.0 켜짐', segC.attrs['aria-checked'] === 'true' && segV.attrs['aria-checked'] === 'false');
T('  ↳ 토글이 두 디자인 모두의 헤더에 있다 (v2-only 아님)', /<div class="ui-seg" id="uiSeg"/.test(html));
T('  ↳ 옛 단일 버튼은 없다', !/id="uiBtn"/.test(html));

const classicPts = {};
for (const id of ids) classicPts[id] = pts(render(id));

g("setUi('v2')");
T('setUi(v2) → UI=v2 · 저장 · <html data-ui>', g('UI') === 'v2' && store.ui === 'v2' && doc.documentElement.attrs['data-ui'] === 'v2');
out = render('overview');
T('v2 화면 = 머리 + 본문 + 목차 자리', /class="v2-head/.test(out) && /id="v2Body"/.test(out) && /id="v2Toc"/.test(out));
T('v2 에서 토글 = 2.0 켜짐', segV.attrs['aria-checked'] === 'true' && segC.attrs['aria-checked'] === 'false');
T('v2 사이드바에 상태 바닥글', /id="v2Status"/.test(nav.innerHTML));
g("setUi('bogus')");
T('모르는 모드는 무시', g('UI') === 'v2');

console.log('\n=== ② 두 디자인이 같은 패널을 보인다 ===');
const diff = ids.filter(id => pts(render(id)) !== classicPts[id]);
T(`★ ${ids.length}개 탭 전부 data-pt 순서까지 같다`, diff.length === 0, diff.slice(0, 4).join(', '));

console.log('\n=== ③ 두 언어 ===');
const miss = new Set();
sb.__miss = miss;
g('T_MISS = globalThis.__miss');
const errs = [];
for (const lang of ['ko', 'en']) {
  g(`LANG = ${JSON.stringify(lang)}`);
  for (const id of ids) { try { render(id); } catch (e) { errs.push(`${lang}/${id}: ${e.message}`); } }
  try { g('v2Status(); v2PaletteItems(); renderUiChrome()'); } catch (e) { errs.push(`${lang}/shell: ${e.message}`); }
}
g('T_MISS = null');
T('v2 에서 모든 탭이 두 언어로 그려진다', errs.length === 0, errs.slice(0, 3).join(' | '));
const missLive = [...miss].filter(s => !upstream(s));
T('★ v2 에서 번역 없는 문자열이 t() 에 닿지 않는다', missLive.length === 0, missLive.slice(0, 5).join(' | '));

const dictBlock = js.slice(js.indexOf('i18n:ko:begin'), js.indexOf('i18n:ko:end'));
const code = js.replace(dictBlock, '').replace(/\/\*[\s\S]*?\*\//g, ' ').replace(/^\s*\/\/.*$/gm, ' ');
const DICT = g('I18N').ko, keys = Object.keys(DICT), HANGUL = /[가-힣]/;
g("LANG='ko'");
const hard = [];
for (const id of ids) {
  const segs = (render(id) + nav.innerHTML).replace(/<style[\s\S]*?<\/style>/g, '').replace(/<[^>]*>/g, '\x01')
    .replace(/&amp;/g, '&').replace(/&#39;/g, "'").replace(/&quot;/g, '"').split(/[\x01\n·|]+/);
  for (let s of segs) {
    s = s.trim();
    if (!s || HANGUL.test(s) || (s.match(/[A-Za-z][a-z]{2,}/g) || []).length < 3) continue;
    if (/[@\\/=]|https?:/.test(s) || !code.includes(s) || (s in DICT)) continue;
    const literal = [`'${s}'`, `"${s}"`, '`' + s + '`'].some(q => code.includes(q));
    if ((literal || !keys.some(k => k.includes(s))) && !hard.includes(s) && !upstream(s)) hard.push(`${id}: ${s.slice(0, 60)}`);
  }
}
T('★ v2 한국어 화면에 하드코딩 영어 문장이 없다', hard.length === 0, hard.slice(0, 4).join(' | '));
g("LANG='en'");

console.log('\n=== ④ 하위 탭 · 내비 · 요약 · 접기 · 검색 ===');
const tabBad = [];
for (const p of g('PARENTS').filter(p => p.children)) {
  for (const c of p.children) {
    const h = render(c.id);
    const tabs = [...h.matchAll(/class="v2-tab( active)?"/g)];
    const act = tabs.filter(m => m[1]).length;
    if (tabs.length !== p.children.length || act !== 1 || !new RegExp(`v2-tab active"[^>]*href="#${c.id.replace('.', '\\.')}"`).test(h))
      tabBad.push(`${c.id}: ${tabs.length}/${p.children.length} active=${act}`);
  }
}
T('★ 하위 탭이 있는 탭마다 탭 줄이 있고 지금 탭 하나만 활성', tabBad.length === 0, tabBad.slice(0, 3).join(' | '));
T('하위 탭 없는 탭에는 탭 줄이 없다', !/class="v2-tabs"/.test(render('mfa')));

render('ca.eval');
const navActive = [...nav.innerHTML.matchAll(/class="nav-item active" data-id="([^"]+)"/g)].map(m => m[1]);
T('내비 = 부모만, 하위 탭에 있어도 부모 하나가 활성', navActive.length === 1 && navActive[0] === 'ca', navActive.join(','));
T('내비에 하위 탭 항목이 없다 (페이지 탭으로 옮김)', !/data-id="ca\.eval"/.test(nav.innerHTML));

out = render('overview');
const acts = g('buildActions(DATA)');
const nHigh = acts.filter(a => a[0] === 'high').length, nMed = acts.filter(a => a[0] === 'med').length;
const heroV = (out.match(/class="v2-hero-v [a-z]+">(\d+)</) || [])[1];
T('★ 요약 숫자 = buildActions 의 high+med', +heroV === nHigh + nMed, `hero=${heroV} actions=${nHigh}+${nMed}`);
T('  ↳ 심각도 칩이 같은 수를 말한다', new RegExp(`<i></i>${nHigh} high<`).test(out) && new RegExp(`<i></i>${nMed} medium<`).test(out));
T('  ↳ 조치 행에 data-sev 가 붙어 칩이 거를 수 있다', (out.match(/class="action(?: in-hero)?" data-sev="/g) || []).length === acts.length);
T('  ↳ ★ 목록에서 접히는 행 = 요약의 "가장 급한" 행 수', (out.match(/class="action in-hero"/g) || []).length === Math.min(4, nHigh + nMed),
  `in-hero=${(out.match(/class="action in-hero"/g) || []).length} expected=${Math.min(4, nHigh + nMed)}`);
T('개요 외 탭에는 요약이 없다', !/v2-hero/.test(render('mfa')));
const savedAt = g('DATA._collectedAt');
g('DATA._collectedAt = null');
out = render('overview');
T('★ 데이터 전에는 0 이 아니라 — (초록 0 = 가장 안심되는 오답)', /class="v2-hero-v">—</.test(out) && !/v2-hero-v ok/.test(out));
g(`DATA._collectedAt = ${JSON.stringify(savedAt)}`);

store['ui.collapsed'] = JSON.stringify(['Priority Action Items']);
g('_collapsed = null');
out = render('overview');
T('★ 접어 둔 패널은 다시 그려도 접혀 있다', /class="panel collapsed" data-pt="Priority Action Items"/.test(out));
g("v2SetCollapsed('Priority Action Items', false)");
T('  ↳ 펼치면 저장에서도 빠진다', JSON.parse(store['ui.collapsed']).length === 0 && !/panel collapsed/.test(render('overview')));
g("setUi('classic')");
store['ui.collapsed'] = JSON.stringify(['Priority Action Items']); g('_collapsed = null');
T('  ↳ 클래식은 접기를 적용하지 않는다', !/panel collapsed/.test(render('overview')));
g("setUi('v2')");

const items = g('v2PaletteItems()');
const pageIds = new Set(items.filter(i => i.grp === 'pages').map(i => i.id));
T('★ 검색 팔레트가 모든 탭·하위 탭을 담는다', ids.every(id => pageIds.has(id)), ids.filter(id => !pageIds.has(id)).join(','));
const m1 = g("v2MatchPalette(v2PaletteItems(), 'mfa').map(i=>i.id)");
T('  ↳ "mfa" → MFA 탭', m1.includes('mfa'));
g("LANG='ko'");
const m2 = g("v2MatchPalette(v2PaletteItems(), 'device').map(i=>i.id)");
T('  ↳ 한국어 화면에서도 영어로 찾힌다', m2.includes('devices') || m2.includes('devid'), m2.join(','));
T('  ↳ 클래식 전환 명령이 있다', g("v2PaletteItems().some(i=>i.grp==='cmd' && /클래식/.test(i.label))"));
g("LANG='en'");
T('  ↳ 일치 없음 → 빈 목록', g("v2MatchPalette(v2PaletteItems(), 'zzqqxx').length") === 0);

const fns = ['setUi', 'v2Go', 'v2Nav', 'v2FilterActs', 'v2Jump', 'v2ToggleRail', 'v2OpenPalette', 'v2ClosePalette',
  'v2RenderPalette', 'v2PalKey', 'v2PalSel', 'v2PalRun'];
const missingFn = fns.filter(f => g(`typeof ${f}`) !== 'function');
T('HTML 이 부르는 함수가 전부 있다', missingFn.length === 0, missingFn.join(','));
const inline = [...html.matchAll(/on(?:click|input|keydown|mousemove)="([^"]+)"/g)].map(m => (m[1].match(/(v2\w+|setUi)\(/) || [])[1]).filter(Boolean);
const undef = [...new Set(inline)].filter(f => g(`typeof ${f}`) !== 'function');
T('  ↳ 인라인 핸들러 이름이 전부 정의돼 있다', undef.length === 0, undef.join(','));

console.log('\n=== ⑤ 사이드바 상태 ===');
const fresh = new Date().toISOString();
g(`DATA._collectedAt = ${JSON.stringify(new Date(Date.now() - 200 * 60000).toISOString())}`);
T('★ 200분 전 수집 → 상태 빨강', g('v2Status().cls') === 'bad');
g(`DATA._collectedAt = ${JSON.stringify(fresh)}`);
const h = g('sourceHealth(DATA)');
const expect = h.down.length ? 'bad' : h.carried.length ? 'warn' : '';
T('방금 수집 → 출처 상태만 반영', g('v2Status().cls') === expect, `cls=${g('v2Status().cls')} expect=${expect}`);
g('DATA._collectedAt = null');
T('수집 전 → 불러오는 중', /Loading/.test(g('v2Status().html')));

console.log('\n=== ⑥ v2 색 대비 ===');
function blockExact(sel) {
  const i = css.indexOf(sel + ' {');
  if (i < 0) return '';
  const open = css.indexOf('{', i), close = css.indexOf('}', open);
  return css.slice(open + 1, close);
}
const vars = b => Object.fromEntries([...b.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)].map(m => [m[1], m[2].trim()]));
const dark = vars(blockExact('[data-ui="v2"]'));
const light = Object.assign({}, dark, vars(blockExact('[data-ui="v2"][data-theme="light"]')));
const srgb = c => { c /= 255; return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4); };
const lum = hex => { const n = hex.replace('#', ''); const r = parseInt(n.slice(0, 2), 16), gg = parseInt(n.slice(2, 4), 16), b = parseInt(n.slice(4, 6), 16);
  return 0.2126 * srgb(r) + 0.7152 * srgb(gg) + 0.0722 * srgb(b); };
const ratio = (a, b) => { const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p); return (x + 0.05) / (y + 0.05); };
const PAIRS = [['--text', '--bg'], ['--text', '--panel'], ['--text', '--panel2'], ['--text', '--bg2'],
  ['--muted', '--panel'], ['--muted', '--bg'], ['--muted', '--bg2'], ['--muted', '--panel2'],
  ['--ok', '--panel'], ['--warn', '--panel'], ['--bad', '--panel'], ['--info', '--panel'], ['--accent', '--panel'],
  ['--accent', '--bg2'], ['--text', '--elev']];
for (const [name, p] of [['v2 dark', dark], ['v2 light', light]]) {
  T(`${name}: 토큰을 찾았다`, /^#/.test(p['--text'] || '') && /^#/.test(p['--panel'] || ''));
  const bad = PAIRS.filter(([f, b]) => /^#[0-9a-f]{6}$/i.test(p[f] || '') && /^#[0-9a-f]{6}$/i.test(p[b] || '') && ratio(p[f], p[b]) < 4.5)
    .map(([f, b]) => `${f} on ${b} = ${ratio(p[f], p[b]).toFixed(2)}`);
  T(`★★ ${name}: 본문 대비 4.5:1 이상`, bad.length === 0, bad.join(' | '));
  const oa = ratio(p['--on-accent'], p['--accent']);
  T(`${name}: 버튼 글자(--on-accent on --accent) 4.5:1 이상`, oa >= 4.5, oa.toFixed(2));
}

console.log('\n=== ⑦ 2.0 CSS 가 클래식을 건드리지 않는다 ===');
const v2css = css.slice(css.indexOf('[data-ui="v2"]'));
const flat = v2css.replace(/\/\*[\s\S]*?\*\//g, '').replace(/@keyframes[^{]+\{(?:[^{}]*\{[^}]*\})*[^}]*\}/g, '');
const sels = [];
for (const m of flat.matchAll(/([^{}]+)\{[^{}]*\}/g)) {
  const s = m[1].trim();
  if (!s || s.startsWith('@')) continue;
  sels.push(...s.replace(/^@media[^{]*\{/, '').split(',').map(x => x.trim()).filter(Boolean));
}
const OWN = /^(\[data-ui="v2"\]|\.v2-|\.ui-seg|\.icon-btn|kbd\b)/;
const leak = sels.filter(s => !OWN.test(s));
T(`★ 2.0 블록의 선택자 ${sels.length}개가 전부 2.0 범위`, sels.length > 50 && leak.length === 0, leak.slice(0, 4).join(' | '));
T('.v2-only 는 클래식에서 숨는다', /\.v2-only\s*\{\s*display:none !important;/.test(css));
const selRule = (css.match(/\[data-ui="v2"\] \.theme-sel \{([^}]*)\}/) || [])[1] || '';
T('★ 2.0 드롭다운 배경이 투명이 아니다 (열린 목록이 흰 바탕이 됨)', /background:var\(--panel2\)/.test(selRule) && !/transparent/.test(selRule), selRule.trim());
T('  ↳ option 에 배경·글자색을 직접 준다', /\[data-ui="v2"\] \.theme-sel option \{[^}]*background:var\(--elev\)[^}]*color:var\(--text\)/.test(css));
T('  ↳ color-scheme 이 테마를 따른다', /\[data-ui="v2"\] \{ color-scheme:dark; \}/.test(css) && /\[data-ui="v2"\]\[data-theme="light"\] \{ color-scheme:light; \}/.test(css));

console.log();
if (fail) { console.log(`${fail} check(s) FAILED`); process.exit(1); }
console.log('all checks passed');
