// Render the Conditional Access tab and assert the evaluation table says, at a glance, whether
// anything is wrong.
//
// The table used to be twelve columns of digits with no verdict, so "is there a problem?" required
// reading every row. It now leads with a Status column and a headline. Both are derived, which means
// both can be derived wrongly - and a verdict that is confidently wrong is worse than no verdict.
// So this pins the three cases that matter and the one that is easy to get backwards: a policy that
// never engaged must NOT read as clean.
const fs = require('fs'), vm = require('vm');

const html = fs.readFileSync('app/static/index.html', 'utf8');
const js = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]).pop();

const noop = () => {};
const el = () => ({
  set innerHTML(v) {}, get innerHTML() { return ''; }, querySelectorAll: () => [],
  addEventListener: noop, appendChild: noop, setAttribute: noop, getAttribute: () => null,
  removeAttribute: noop, classList: { add: noop, remove: noop, toggle: noop, contains: () => false },
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
const render = (payload) => {
  vm.runInContext('globalThis.__p = ' + JSON.stringify(payload), ctx);
  return vm.runInContext('tabCA(globalThis.__p)', ctx);
};

let fails = [];
const check = (name, cond, extra) => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${name}${extra ? '  ' + extra : ''}`);
  if (!cond) fails.push(name);
};

const pol = (o) => Object.assign({
  policy: 'P', mode: 'enforced', switched: false, inScope: 100, scopeKind: 'targeted',
  evaluated: 2338, applied: 0, pass: 0, blocked: 0, blockedUsers: 0, stuckUsers: 0, stuckSample: [],
  wouldBlock: 0, interrupted: 0,
  notApplied: 0, usersImpacted: 0, controls: [], noClaim: 0, claimNotCompliant: 0, claimCompliant: 0,
}, o);

const wrap = (rows) => ({
  riskySignins: { available: true, collecting: false, windowDays: 7, caPolicyEval: rows,
                  caReportOnlyPolicyCount: 0, caSwitchedPolicies: [] },
});

// --- the verdicts -----------------------------------------------------------------------------
let h = render(wrap([pol({ policy: 'CA-Blocking', applied: 50, blocked: 3, blockedUsers: 2,
                           stuckUsers: 1, stuckSample: ['a@x.com'], noClaim: 3 })]));
check('a user left with no success leads with the red verdict', h.includes('verdict bad') && h.includes('⛔'));
check('  and names the policy in the headline', h.includes('CA-Blocking'));
check('  and surfaces the remediation split', h.includes('No claim 3'));
// The dashboard is English-only. Korean crept into this panel once already.
check('★ no Korean anywhere in the rendered panel', !/[가-힣]/.test(h),
      (h.match(/[가-힣]+/g) || []).slice(0, 3).join(' '));
check('★ the ↻ marker is labelled, not a bare glyph',
      render(wrap([pol({ switched: true, applied: 5, pass: 5 })])).includes('↻ was report-only'));

// ★ The distinction the raw block count could not make. An MFA policy stopping bad sign-ins that
// all then succeed is the control working - painting that red trains the reader to ignore red.
h = render(wrap([pol({ policy: 'CA-MFA', applied: 2343, pass: 2305, blocked: 38, blockedUsers: 11,
                       stuckUsers: 0 })]));
check('★ blocks where everyone recovered are amber, never red',
      h.includes('verdict warn') && !h.includes('verdict bad'));
check('  and the headline says nobody is locked out', h.includes('Nobody is locked out'));

h = render(wrap([pol({ mode: 'report-only', applied: 50, wouldBlock: 7 })]));
check('report-only impact reads as amber, not red', h.includes('verdict warn') && !h.includes('verdict bad'));

h = render(wrap([pol({ applied: 50, pass: 50 })]));
check('an engaged policy that stopped nobody reads clean', h.includes('verdict ok') && h.includes('✅'));

// --- the one that is easy to get backwards ----------------------------------------------------
h = render(wrap([pol({ applied: 0, pass: 0 })]));
check('★ a policy that never engaged is "No activity", NOT clean',
      h.includes('No activity') && !h.includes('>✅ Clean'));
check('  and the help text says unmeasured is not proven', h.includes('unmeasured, not proven'));

// --- scope must never print a number it does not have -----------------------------------------
h = render(wrap([pol({ inScope: null, scopeKind: 'unknown', applied: 9 })]));
check('★ an unresolved scope prints — and never 0', h.includes('could not be resolved'));

// --- severity must win the headline, and the sort ---------------------------------------------
h = render(wrap([pol({ policy: 'Clean', applied: 9, pass: 9 }),
                 pol({ policy: 'Bad', applied: 9, blocked: 1, blockedUsers: 1, stuckUsers: 1,
                       stuckSample: ['b@x.com'] })]));
check('one locked-out user among clean policies still raises the alarm', h.includes('verdict bad'));
check('  and a recovered block does not mask it',
      render(wrap([pol({ policy: 'Recovered', applied: 9, blocked: 5, blockedUsers: 5 }),
                   pol({ policy: 'Stuck', applied: 9, blocked: 1, blockedUsers: 1, stuckUsers: 1,
                         stuckSample: ['c@x.com'] })])).includes('verdict bad'));

// --- hostile / missing data -------------------------------------------------------------------
for (const [name, rows] of [['empty list', []],
                            ['nulls in every numeric field', [pol({
                              inScope: undefined, applied: undefined, pass: undefined,
                              blocked: undefined, wouldBlock: undefined, controls: undefined })]]]) {
  let ok = true, err = '';
  try { render(wrap(rows)); } catch (e) { ok = false; err = e.message; }
  check(`survives ${name}`, ok, err);
}

console.log(fails.length ? `\n${fails.length} failed` : '\nall checks passed');
process.exit(fails.length ? 1 : 0);
