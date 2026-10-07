'use strict';
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..');
const html = fs.readFileSync(path.join(ROOT, 'app/static/index.html'), 'utf8');
const css = (html.match(/<style>([\s\S]*?)<\/style>/) || [])[1] || '';

let fails = 0, ran = 0;
function T(name, ok, detail) {
  ran++;
  if (ok) console.log(`  ok   ${name}`);
  else { console.log(`  FAIL ${name}\n        ${detail}`); fails++; }
}

const themesM = css.length && html.match(/var THEMES\s*=\s*\[([^\]]*)\]/);
const THEMES = themesM ? themesM[1].split(',').map(s => s.trim().replace(/^['"]|['"]$/g, '')).filter(Boolean) : [];
T('THEMES 배열을 찾았다', THEMES.length >= 2, JSON.stringify(THEMES));

const selBlock = (html.match(/<select id="themeSel"[\s\S]*?<\/select>/) || [''])[0];
const OPTIONS = [...selBlock.matchAll(/<option value="([^"]+)"/g)].map(m => m[1]);
T('★ <select> 옵션이 THEMES 와 정확히 같다 (순서까지)',
  JSON.stringify(OPTIONS) === JSON.stringify(THEMES),
  `select=${JSON.stringify(OPTIONS)} THEMES=${JSON.stringify(THEMES)}`);

const CSS_THEMES = [...new Set([...css.matchAll(/\[data-theme="([^"]+)"\]/g)].map(m => m[1]))];
const ghosts = CSS_THEMES.filter(t => !THEMES.includes(t));
T('★★ 죽은 테마의 CSS 가 남아 있지 않다', ghosts.length === 0,
  `THEMES 에 없는 [data-theme]: ${ghosts.join(', ')}`);

const DEFAULT_THEME = THEMES[0];
const missingCss = THEMES.filter(t => t !== DEFAULT_THEME && !CSS_THEMES.includes(t));
T('기본 테마를 뺀 나머지는 CSS 블록을 가진다', missingCss.length === 0, missingCss.join(', '));

const retM = html.match(/var RETIRED\s*=\s*\{([\s\S]*?)\}\s*;/);
const RETIRED = {};
if (retM) for (const m of retM[1].matchAll(/['"]?([\w-]+)['"]?\s*:\s*['"]([\w-]+)['"]/g)) RETIRED[m[1]] = m[2];
const badTarget = Object.entries(RETIRED).filter(([, v]) => !THEMES.includes(v));
T('★ 은퇴 테마가 전부 살아 있는 테마로 간다', badTarget.length === 0,
  badTarget.map(([k, v]) => `${k}->${v}`).join(', '));
const deadKey = Object.keys(RETIRED).filter(k => THEMES.includes(k));
T('은퇴 목록에 살아 있는 테마가 없다 (죽은 항목)', deadKey.length === 0, deadKey.join(', '));

const EVER = ['midnight', 'light', 'bw', 'blackgold', 'whitegold', 'pastel-light', 'pastel-dark',
  'carbon', 'ocean', 'violet'];
const orphan = EVER.filter(t => !THEMES.includes(t) && !RETIRED[t]);
T('★★ 과거에 존재한 모든 이름이 THEMES 이거나 RETIRED 에 있다', orphan.length === 0,
  `갈 곳 없는 이름: ${orphan.join(', ')} — 이 값을 들고 돌아온 브라우저는 스타일 없는 화면을 봅니다`);

const fallbacks = [...html.matchAll(/return\s+'([\w-]+)'\s*;/g)].map(m => m[1])
  .filter(v => EVER.includes(v));
const badFallback = fallbacks.filter(v => !THEMES.includes(v));
T('★ 폴백(prefers-color-scheme · 기본)이 살아 있는 테마다', badFallback.length === 0,
  badFallback.join(', '));

function parseVars(block) {
  const out = {};
  for (const m of block.matchAll(/(--[\w-]+)\s*:\s*([^;]+);/g)) out[m[1]] = m[2].trim();
  return out;
}
function blockOf(sel) {
  const i = css.indexOf(sel);
  if (i < 0) return '';
  const open = css.indexOf('{', i);
  let d = 0;
  for (let j = open; j < css.length; j++) {
    if (css[j] === '{') d++;
    else if (css[j] === '}') { d--; if (!d) return css.slice(open + 1, j); }
  }
  return '';
}
const rootVars = parseVars(blockOf(':root'));
const palettes = { [DEFAULT_THEME]: rootVars };
for (const t of THEMES) {
  if (t === DEFAULT_THEME) continue;
  palettes[t] = { ...rootVars, ...parseVars(blockOf(`[data-theme="${t}"]`)) };
}

function srgb(c) { c /= 255; return c <= 0.03928 ? c / 12.92 : Math.pow((c + 0.055) / 1.055, 2.4); }
function lum(hex) {
  const h = hex.replace('#', '');
  const n = h.length === 3 ? h.split('').map(x => x + x).join('') : h;
  const r = parseInt(n.slice(0, 2), 16), g = parseInt(n.slice(2, 4), 16), b = parseInt(n.slice(4, 6), 16);
  return 0.2126 * srgb(r) + 0.7152 * srgb(g) + 0.0722 * srgb(b);
}
function ratio(a, b) {
  const [x, y] = [lum(a), lum(b)].sort((p, q) => q - p);
  return (x + 0.05) / (y + 0.05);
}
const HEX = /^#[0-9a-fA-F]{3,8}$/;

const TEXT_PAIRS = [
  ['--text', '--bg'], ['--text', '--panel'], ['--text', '--panel2'],
  ['--muted', '--panel'], ['--muted', '--bg'], ['--muted', '--bg2'],
  ['--ok', '--panel'], ['--warn', '--panel'], ['--bad', '--panel'], ['--info', '--panel'],
  ['--accent', '--panel'],
];
for (const t of THEMES) {
  const p = palettes[t];
  const bad = [];
  for (const [fg, bg] of TEXT_PAIRS) {
    if (!HEX.test(p[fg] || '') || !HEX.test(p[bg] || '')) continue;
    const r = ratio(p[fg], p[bg]);
    if (r < 4.5) bad.push(`${fg} on ${bg} = ${r.toFixed(2)}:1`);
  }
  T(`★★ ${t}: 본문 대비가 전부 4.5:1 이상`, bad.length === 0, bad.join(' | '));
}

for (const t of THEMES) {
  const p = palettes[t];
  if (!HEX.test(p['--on-accent'] || '') || !HEX.test(p['--accent'] || '')) continue;
  const r = ratio(p['--on-accent'], p['--accent']);
  const r2 = HEX.test(p['--accent2'] || '') ? ratio(p['--on-accent'], p['--accent2']) : null;
  console.log(`       ↳ ${t}: --on-accent on --accent = ${r.toFixed(2)}:1` +
    (r2 ? ` · on --accent2 = ${r2.toFixed(2)}:1` : '') +
    (r < 4.5 ? '   ⚠ 4.5 미만 (기존)' : ''));
  T(`${t}: --on-accent 가 --accent 위에서 3:1 이상`, r >= 3.0, `${r.toFixed(2)}:1`);
}

const LIGHT = THEMES.filter(t => {
  const p = palettes[t];
  return HEX.test(p['--bg'] || '') && lum(p['--bg']) > 0.5;
});
T('밝은 테마가 하나 이상 있다', LIGHT.length >= 1, THEMES.join(', '));
for (const t of LIGHT) {
  const missing = ['b-high', 'b-med', 'b-low', 'b-ok', 'b-info']
    .filter(c => !new RegExp(`\\[data-theme="${t}"\\][^{]*\\.${c}\\b`).test(css));
  T(`★ ${t}: 배지 5종이 전부 밝은 테마용으로 뒤집혀 있다`, missing.length === 0,
    `안 뒤집힌 것: ${missing.join(', ')} — 어두운 배경용 pale 글자가 흰 패널에 남습니다`);
}

T('★★ refresh 버튼에 하드코딩 색이 돌아오지 않았다',
  !/button\.refresh[^{]*\{[^}]*rgba\(\s*59\s*,\s*158\s*,\s*255/.test(css),
  'Midnight 의 --accent 를 박아 둔 값입니다. 밝은 테마에서 흰 글자가 흰 배경에 놓입니다');
T('★ refresh 호버가 배경을 덮어쓰지 않는다 (그라디언트 유지)',
  !/button\.refresh:hover(?!:not)[^{]*\{[^}]*background/.test(css),
  '`:hover` 가 아래 그라디언트 규칙보다 명시도가 높습니다 — 호버할 때만 테마가 깨집니다');

console.log('');
if (fails) { console.log(`${fails} 건 실패 / ${ran} 개 실행`); process.exit(1); }
console.log(`all checks passed (${ran} 개 실행)`);
