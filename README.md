# MS365 Security Operations Console — public demo

A single-pane security console for a Microsoft 365 tenant. It pulls the information that is
otherwise scattered across the M365 admin center, Defender, Exchange Online and Entra portals into
one read-only screen: 21 collectors, 15 tabs, derived action items, and a tab that reports on the
health of the collection itself.

**This repository is a sanitised demo.** It contains the application code and a synthetic dataset.
It contains no tenant data, no credentials, and none of the operational runbooks from the private
repository it was derived from. How that is enforced — and machine-checked — is described in
[Sanitisation](#sanitisation) below.

> **Live demo — https://hojunhwang.github.io/ms365-secops-console-demo/**
> Every number, name, device and address on that page is generated. See `demo/`.

---

## What it does

Read-only monitoring, deliberately. There are no Graph write permissions anywhere in the codebase
and no write helpers to add one carelessly. Response actions (disabling an account, revoking
sessions) stay in the portals, because doing them from here would mean holding write scopes on an
app-only credential that runs unattended.

| Area | What the tab answers |
|---|---|
| Overview | What needs attention right now, and is the posture trending up or down |
| Identity & access | Who holds privilege, who has no MFA, which guests are dormant, when app credentials expire |
| Conditional Access | What each policy actually evaluates, and who a not-yet-enforced policy would block |
| Devices | Does each enrolled device have one identity that Conditional Access can see |
| Browser claims | Is a device claim present in browser sign-ins — the precondition for device-based CA |
| Threats & alerts | Incidents, alerts, attack-simulation results |
| Email threats | Delivered-threat hunting, sender patterns, ZAP outcomes, risky link clicks |
| Mail security | Auto-forwarding, risky inbox rules, mailbox delegation, quarantine, transport rules |
| Sharing | Anonymous links that actually exist, not just the tenant setting that permits them |
| Posture | Secure Score and its highest-value improvement actions |
| Audit & activity | Recent directory changes and sign-in failure patterns |
| Data health | Is each source fresh, stale or down; request volume, throttling, window coverage |

### Design decisions worth reading the code for

These are the problems that shaped the app. They are described here as engineering lessons; the
specifics of any one tenant are not part of this repository.

- **A device can have two Entra identities, and Conditional Access only sees one of them.** An
  MDM-only enrolment creates a stub device object with a null `trustType`; the device keeps
  authenticating with its older registration. Intune points at the stub, so tagging "the device" by
  Intune's `azureADDeviceId` tags the object that never signs in — and a device-filter policy then
  blocks a machine that is enrolled, compliant *and* tagged. Neither portal shows the disagreement.
  `app/sources/device_identity.py` reconciles sign-in claim, Intune id and tag as a three-way match.

- **Never branch Conditional Access logic on a sign-in's top-level `conditionalAccessStatus`.** It
  reflects *enforced* policies only, so a sign-in that a report-only policy would have blocked still
  reads as `success`. One walk over `appliedConditionalAccessPolicies[].result` handles both
  lifecycles, which means the cutover from report-only to enforced needs no code change and the
  pilot prediction and the real outcome are the same metric.

- **Report-only counts over-report device policies.** A claimless browser session fails a device
  filter for lack of a claim, not because the device is non-compliant, so the blast radius reads as
  an upper bound rather than a forecast. The UI says so on the card, because a number that is
  presented as a prediction will be acted on as one.

- **A "nothing to do" branch that logs at DEBUG is a silent failure mode.** The collection loop slept
  one interval after finishing and stamped its timestamp at the same instant, so the freshness guard
  was decided by floating-point jitter; a skip logged at DEBUG (which uvicorn does not print) then
  halved the effective cadence. Externally that is indistinguishable from a dead collector. It is now
  compared against half the interval and skips log at INFO.

- **Derived alerts have a cost, and it is worth naming.** Badges and action items are computed from
  the current snapshot and never stored, so remediating something clears its badge by itself. The
  flip side: there is no way to record an accepted risk, and a source that fails to collect makes its
  warnings *disappear* rather than turn red — so the header reports `N/M sources` separately.

- **Session controls are not grant controls.** Reading only `grantControls.builtInControls` makes a
  token-protection or sign-in-frequency policy look like it enforces nothing.

- **A tenant setting is a ceiling, not a state.** Per-site sharing capability is not exposed by
  Microsoft Graph at all, so the sharing card enumerates the anonymous links that exist rather than
  reporting the setting that allows them.

---

## Architecture

```
app/
  main.py            FastAPI app, in-process collection loop, /api/summary and /api/health
  registry.py        the source registry - one line per collector
  pipeline.py        collect -> AI summary -> cache + history, shared by the loop and the endpoint
  graph_client.py    MSAL app-only token, shared concurrency limit, retry/throttle handling
  signin_cache.py    a shared sign-in window several sources read from, paged and budgeted
  cache.py           snapshot + metric history on disk
  ai_overview.py     optional AI summary; sends aggregate metrics only, never PII
  sources/           21 collectors, each returning {available, ...} and nothing else
  static/index.html  the entire UI - vanilla JS, one fetch, no build step
```

A collector is a module with a `fetch()` that returns a dict, registered in `registry.py`. A failure
is contained: the pipeline carries the last good value forward and marks it stale rather than
blanking the tab.

### Authentication

Two app-only credentials on one app registration, and no delegated sign-in anywhere:

| Path | Credential | Why |
|---|---|---|
| Microsoft Graph (21 collectors) | app registration + **client secret**, MSAL client-credentials | all permissions are `*.Read.All` |
| Exchange Online collector | the same app + **certificate** (`Exchange.ManageAsApp`) | EXO app-only does not accept a secret |

The service principal holds **Global Reader**. Access to the page itself is a separate layer — the
private deployment sits behind an identity-aware proxy restricted to one administrator, because the
page shows an organisation's full security posture to anyone who can load it.

---

## Sanitisation

The interesting part of publishing this was proving that nothing came with it.

**Masking a real snapshot was rejected.** A snapshot of this dashboard holds hundreds of unique
UPNs and object ids, plus device names, source IPs and mail subjects, spread over 21 sources and
~800 distinct JSON paths. Masking means finding all of them, and one missed field is a disclosure
you cannot prove you avoided.

**Counts are data too.** "Six global admins, 47 enrolled devices, ten guests" survives value-level
masking untouched, because it is carried by the *length* of a list rather than by anything inside it.
Every list is therefore resized by one shared factor — shared, so that sources describing the same
fleet from different angles stay consistent with each other.

So `demo/generate_demo_snapshot.py` reads a real snapshot for its **shape only** — keys, types, list
lengths — and generates every leaf value. In priority order: an authored pool for paths the UI
branches on; a synthetic identifier for anything matching an identifier shape (`contoso.com`,
`LAPTOP-DEMO###`, RFC 5737 documentation IPs, `2001:db8::`); verbatim passthrough *only* if the exact
string is a literal in this repository's own source, which makes it product vocabulary the UI
compares against (`compliant`, `reportOnlyFailure`) rather than a fact about a tenant; and otherwise
a label derived from the JSON path. Identifier mappings are consistent, so a person referenced by two
sources is the same fake person in both.

`demo/verify_demo.py` then checks the result two ways, and the difference matters:

- **Allowlist** — every string in the committed fixture must be an authored pool value, a synthetic
  identifier, a timestamp, or a source literal. Anything unexplained fails. This needs no access to
  private data, so it runs in CI on every push.
- **Blocklist** — no identifier harvested from the private material (the real snapshot *and* the
  private repository's docs, scripts and `.env`, some 6,700 terms) may appear anywhere in this
  repository. An allowlist can be wrong if it was built from something tainted; this catches that.
  Files present in both trees are excluded from the blocklist, or shared test fixtures would flag
  themselves and bury a real finding.

The blocklist check found one leak the hand-written pass had missed: a partner domain sitting in a
source comment, inside an explanation of why a mail template must not claim a domain was blocked.
That is the entire argument for having it.

`tests/demo_render_test.js` renders all 28 sub-tabs from the fixture in a headless harness and fails
on an empty tab or on `undefined` / `NaN` / `[object Object]` reaching the DOM — because a published
static page has no operator watching a log.

### Not included

The private repository's operational material is absent by decision, not by oversight: the
engineering handoff document, device and Conditional Access runbooks, the cutover and remediation
scripts, and every collected snapshot. Masking would not have helped — a document describing which
weaknesses are not yet fixed is an attacker's roadmap whether or not the names are starred out.

---

## Running it

**The demo, with no credentials and no backend** — open `app/static/index.html` over HTTP:

```bash
python -m http.server 8080 --directory app/static
# then open http://127.0.0.1:8080
```

The page tries `/api/summary` first, and on failure falls back to the bundled
`app/static/demo-summary.json` and shows a `DEMO DATA` chip. Timestamps in the fixture are shifted so
`_collectedAt` becomes "now" — otherwise a published demo would permanently display the
stale-data warning the header exists to raise.

**Against a real tenant** — an app registration with the read-only application permissions listed in
`.env.example`, admin-consented:

```bash
python -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env      # fill in tenant id, client id, client secret
uvicorn app.main:app --reload
```

MSAL caches the app-only token per process, so restart uvicorn after granting a new permission or
you will keep seeing stale `403`s.

**Tests** (no dependencies beyond Node and Python):

```bash
node tests/demo_render_test.js     # renders every tab from the fixture
node tests/nav_test.js             # sub-tab router and panel coverage
python demo/verify_demo.py         # allowlist check on the committed fixture
```

---

## Licence

None granted. This is published for portfolio review, not for reuse.
