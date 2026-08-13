# M365 Security Console — public demo

A single-pane security console for a Microsoft 365 tenant. It pulls the information that is
otherwise scattered across the M365 admin center, Defender, Exchange Online and Entra portals into
one read-only screen: 21 collectors, 15 tabs, derived action items, and a tab that reports on the
health of the collection itself.

**This repository is a sanitised demo.** It contains the application code and a synthetic dataset.
It contains no tenant data, no credentials, and none of the operational runbooks from the private
repository it was derived from. How that is enforced — and machine-checked — is described in
[Sanitisation](#sanitisation) below.

Published as a personal portfolio piece with the approval of the organisation it was built for.
**No licence is granted and reuse is not permitted without separate permission** — see
[Permissions and licence](#permissions-and-licence).

> **Live demo — https://hojunhwang.github.io/m365-security-console-demo/**
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

### Synthetic data has a second failure mode

Sanitised is not the same as coherent. A generator that produces one value at a time cannot see
relationships between fields, so the first fixture was provably free of tenant data *and* full of
statements that contradicted each other: 47 devices above a histogram summing to 33, a 73% sign-in
failure rate beside 130 failures out of 3,371, a `firstBlock` later than its own `lastBlock`, one
Conditional Access policy name appearing three times, and — visible on the rendered page — mail
classified "External" whose sender sat in the tenant's own domain.

`demo/audit_fixture.py` checks the relationships rather than the values: counts against the lists
they count, histograms against their totals, subsets against their supersets, rates against their own
numerator and denominator, uniqueness where a value identifies its row, and `first`/`last` ordering.
It found **64 contradictions in 6 categories** on its first run and now gates CI at zero.

The fixes are rules, not patches: totals are re-derived from the lists beside them by name-matching
rather than a hand-kept list of pairs; histograms are rebuilt by counting rows; scalar lists are
deduplicated in one pass because a list of grant controls is a set; and Conditional Access policies
are authored as whole objects, since name, state and controls are only meaningful together.

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
python demo/verify_demo.py         # no unexplained strings in the fixture
python demo/audit_fixture.py       # the fixture does not contradict itself
```

---

## Permissions and licence

**No licence is granted. All rights reserved.**

This repository is published with the approval of the organisation the system was built for. That
approval is specific: it covers **publishing this sanitised demo, with synthetic data, as a personal
portfolio piece**. It does not extend to anything else.

What that means in practice:

- **You may** read the code and fork the repository on GitHub, to the extent GitHub's Terms of
  Service allow for any public repository.
- **You may not**, without separate written permission: copy this code into another project, reuse
  it in whole or in part, redistribute or republish it, create derivative works, or use it
  commercially or internally at another organisation.

Publishing something openly and licensing it for reuse are two different decisions, and only the
first one has been made here. There is deliberately no `LICENSE` file, because adding one would
grant rights that are not mine to give away.

If you want to use any of this, open an issue and ask — the answer is not automatically no, it just
has to be asked. If you are here to evaluate the work rather than to reuse it, everything you need
is already above.
