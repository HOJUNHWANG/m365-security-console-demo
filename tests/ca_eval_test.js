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

let h = render(wrap([pol({ policy: 'CA-Blocking', applied: 50, blocked: 3, blockedUsers: 2,
                           stuckUsers: 1, stuckSample: ['a@x.com'], noClaim: 3 })]));
check('a user left with no success leads with the red verdict', h.includes('verdict bad') && h.includes('⛔'));
check('  and names the policy in the headline', h.includes('CA-Blocking'));
check('  and surfaces the remediation split', h.includes('No claim 3'));
check('★ no Korean anywhere in the rendered panel', !/[가-힣]/.test(h),
      (h.match(/[가-힣]+/g) || []).slice(0, 3).join(' '));
check('★ the ↻ marker is labelled, not a bare glyph',
      render(wrap([pol({ switched: true, applied: 5, pass: 5 })])).includes('↻ was report-only'));

h = render(wrap([pol({ policy: 'CA-MFA', applied: 2343, pass: 2305, blocked: 38, blockedUsers: 11,
                       stuckUsers: 0 })]));
check('★ blocks where everyone recovered are amber, never red',
      h.includes('verdict warn') && !h.includes('verdict bad'));
check('  and the headline says nobody is locked out', h.includes('Nobody is locked out'));

h = render(wrap([pol({ mode: 'report-only', applied: 50, wouldBlock: 7 })]));
check('report-only impact reads as amber, not red', h.includes('verdict warn') && !h.includes('verdict bad'));

h = render(wrap([pol({ applied: 50, pass: 50 })]));
check('an engaged policy that stopped nobody reads clean', h.includes('verdict ok') && h.includes('✅'));

h = render(wrap([pol({ applied: 0, pass: 0 })]));
check('★ a policy that never engaged is "No activity", NOT clean',
      h.includes('No activity') && !h.includes('>✅ Clean'));
check('  and the help text says unmeasured is not proven', h.includes('unmeasured, not proven'));

h = render(wrap([pol({ inScope: null, scopeKind: 'unknown', applied: 9 })]));
check('★ an unresolved scope prints — and never 0', h.includes('could not be resolved'));

h = render(wrap([pol({ policy: 'Clean', applied: 9, pass: 9 }),
                 pol({ policy: 'Bad', applied: 9, blocked: 1, blockedUsers: 1, stuckUsers: 1,
                       stuckSample: ['b@x.com'] })]));
check('one locked-out user among clean policies still raises the alarm', h.includes('verdict bad'));
check('  and a recovered block does not mask it',
      render(wrap([pol({ policy: 'Recovered', applied: 9, blocked: 5, blockedUsers: 5 }),
                   pol({ policy: 'Stuck', applied: 9, blocked: 1, blockedUsers: 1, stuckUsers: 1,
                         stuckSample: ['c@x.com'] })])).includes('verdict bad'));

h = render(wrap([pol({ policy: 'CA-AppProt', applied: 9, noClaim: 5, device: false })]));
check('★ device:false policy shows no "No claim" badge', !h.includes('No claim'));
h = render(wrap([pol({ policy: 'CA-Device', applied: 9, noClaim: 5, device: true })]));
check('device:true policy still shows the "No claim" badge', h.includes('No claim'));
h = render(wrap([pol({ policy: 'CA-Old', applied: 9, noClaim: 5 })]));
check('snapshot without the field (older collector) keeps the badge', h.includes('No claim'));

const roWrap = (rows, extra) => ({
  riskySignins: Object.assign({ available: true, collecting: false, windowDays: 7, caPolicyEval: rows,
    caReportOnlyPolicyCount: rows.filter(r => r.mode === 'report-only').length, caSwitchedPolicies: [],
    caReportOnlyImpact: [], caReportOnlyImpactCount: 0, caReportOnlyBlockCount: 0,
    caReportOnlyInterruptCount: 0, caReportOnlyUsers: 0, caReportOnlyByControl: [],
    caReportOnlyByClaim: { noClaim: 0, claimNotCompliant: 0, claimCompliant: 0 } }, extra || {}),
});
const two = [pol({ policy: 'CA-Mobile-X', mode: 'report-only', applied: 12, wouldBlock: 2, usersImpacted: 1, device: false }),
             pol({ policy: 'CA-Platform-Y', mode: 'report-only', applied: 0, device: false }),
             pol({ policy: 'CA-Enforced-Z', mode: 'enforced', applied: 40, pass: 40 })];
h = render(roWrap(two));
const roPanel = h.slice(h.indexOf('Report-only Impact'));
check('★ each report-only policy gets its own row in the panel',
      roPanel.includes('CA-Mobile-X') && roPanel.includes('CA-Platform-Y'));
check('an enforced policy is not listed as report-only', !roPanel.slice(0, roPanel.indexOf('Conditional Access Failures') >>> 0).includes('CA-Enforced-Z'));
check('two report-only policies → the "pooled" note is shown', roPanel.includes('pool all 2 report-only policies'));
check('one report-only policy → no pooled note',
      !render(roWrap([two[0]])).includes('pool all'));
check('★ the panel always says it counts interactive sign-ins only', roPanel.includes('Interactive sign-ins only.'));
check('⛔ an empty panel no longer says "safe to enforce"', !roPanel.includes('safe to enforce'));
check('★ an empty panel says non-interactive was not checked',
      roPanel.includes('Non-interactive sign-ins are not checked here'));
h = render(roWrap(two, { caReportOnlyByClaim: { noClaim: 3, claimNotCompliant: 0, claimCompliant: 0 } }));
check('the claim split is labelled as device-condition policies only',
      h.includes('(device-condition policies only)'));

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
