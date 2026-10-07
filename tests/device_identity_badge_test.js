const fs = require('fs'), vm = require('vm');
const html = fs.readFileSync('app/static/index.html', 'utf8');
const js = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map(m => m[1]).pop();

const noop = () => {};
const el = () => ({
  set innerHTML(v) {}, get innerHTML() { return ''; },
  querySelectorAll: () => [], addEventListener: noop, appendChild: noop, setAttribute: noop,
  getAttribute: () => null, removeAttribute: noop,
  classList: { add: noop, remove: noop, toggle: noop, contains: () => false },
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

let fails = [];
const check = (name, cond) => {
  console.log(`  ${cond ? 'ok  ' : 'FAIL'} ${name}`);
  if (!cond) fails.push(name);
};

const dev = (o) => Object.assign({
  device: 'LAPTOP-DEMO001', user: 'someone@contoso.com', complianceState: 'compliant',
  entraObjectCount: 1, intuneDeviceId: '00000001-1111-4222-8333-000000000001',
  intuneObjectTrustType: 'Workplace', intuneTargetState: 'liveReal',
  presentedDeviceId: '00000001-1111-4222-8333-000000000001', presentedManaged: true,
  presentedSound: true, presentedSource: 'entraReal', presentedTagged: false,
  signInDeviceId: '0000004a-1111-4222-8333-00000000004a', signInExistsInEntra: false,
  signInTrustType: null, signInTagged: false, reregistered: true,
  ok: false, problems: [], warnings: [], accountsSeen: [], extraAccounts: [],
}, o);

const render = (devices, extra) => {
  const di = Object.assign({
    available: true, windowDays: 7, tag: 'Approved-Device',
    enrolled: devices.length, healthy: 0, problem: devices.length,
    devices,
  }, extra || {});
  vm.runInContext('globalThis.__d = ' + JSON.stringify(di), ctx);
  return vm.runInContext('deviceIdentityPanel(globalThis.__d)', ctx);
};

let h = render([dev({ reregistered: true })]);
check('★ a re-registered device is NOT labelled orphaned', !/badge b-high[^>]*>orphaned/.test(h));
check('★ it is labelled as a stale claim instead', /stale claim/.test(h));
check('★ and it is amber, not red', /badge b-med[^>]*>stale claim/.test(h));
check('the tooltip says the current object is Intune-managed',
      /Intune-managed/.test(h) && /re-registered onto a new object|registers with now/.test(h));

h = render([dev({ reregistered: false })]);
check('★ a genuine orphan (no re-registration) is still red',
      /badge b-high[^>]*>orphaned/.test(h));
check('a genuine orphan is not softened to "stale claim"', !/stale claim/.test(h));

check('★ the two cases render differently',
      render([dev({ reregistered: true })]) !== render([dev({ reregistered: false })]));

h = render([dev({ reregistered: true, problems: ['re-registered onto a new object which is NOT tagged'] })]);
check('the untagged finding still shows on a re-registered device', /NOT tagged/.test(h));

h = render([dev({ signInDeviceId: null, presentedDeviceId: '0cadc045-51d4-4b15' })]);
check('no claim in window still falls back to "registered*"', /registered\*/.test(h));
h = render([dev({ signInExistsInEntra: true, signInTrustType: 'Workplace' })]);
check('a live sign-in object shows its trustType', /badge b-info[^>]*>Workplace/.test(h));
check('a live sign-in object is neither orphaned nor stale',
      !/orphaned/.test(h) && !/stale claim/.test(h));

let threw = '';
try {
  render([dev({ signInDeviceId: null, presentedDeviceId: null, intuneDeviceId: null,
                intuneObjectTrustType: null, complianceState: null })]);
} catch (e) { threw = e.message; }
check('a row with every optional field missing does not throw', !threw);

console.log();
if (fails.length) { console.log(`${fails.length} check(s) FAILED: ${fails.join(', ')}`); process.exit(1); }
console.log('all checks passed');
