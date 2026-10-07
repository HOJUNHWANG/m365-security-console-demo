# The demo dataset

`../app/static/demo-summary.json` is the snapshot the static demo renders. **Every value in it is
generated.** No tenant data, no real person, no real device, no real address.

## Regenerating it

Only possible where a real snapshot exists — it is the shape input, and it is not in this
repository:

```bash
python demo/generate_demo_snapshot.py \
    --snapshot ../ms365-security-dashboard/data/graph_snapshot.json \
    --history  ../ms365-security-dashboard/data/graph_history.json \
    --health   health.json \
    --out      app/static/demo-summary.json \
    --report   /tmp/fallback_report.txt
```

`--health` takes a saved `/api/health` response (`curl -s localhost:8000/api/health > health.json`).
The backend builds that payload per request rather than storing it in the snapshot, so without it the
Data Health tab renders empty.

`--report` lists two things worth reading after every run: the JSON paths that fell through to a
generated label (each one is a place where the demo shows `Policy 3` instead of something that reads
like the real thing — it is safe, just poor), and every string that passed through verbatim as
product vocabulary. **Read the second list.** It is the one place where a real string could survive,
and it is short enough to check by eye — currently 118 entries, all Microsoft platform terms, UI enum
tokens and Graph resource paths.

## Re-syncing after the private app changes

`app/` and `tests/` are copied wholesale from the private repository, so the demo-only edits are
replaced with them. Three steps put the demo back, in this order:

```bash
# 1. scrub tenant literals and operational narrative (private script, not in this repo)
python demo/strip_comments.py            # 2. remove every comment and docstring
python demo/apply_demo_mode.py           # 3. apply what is missing, report what was already there

python demo/strip_comments.py --check    # verify only; CI runs both of these
python demo/apply_demo_mode.py --check
```

**`tests/` is re-synced too, and it carries demo-only edits of its own.** Upstream's tests can
depend on things the older demo copies lack (a `crypto` entry in the vm sandboxes, for instance), so
they are copied with the app. That overwrites things `apply_demo_mode.py` then restores: every test
must read `app/static/demo-summary.json` rather than the private `data/graph_snapshot.json`,
`i18n_test.js` carries the recorded list of upstream i18n gaps, and it locates the Korean dictionary
from the `I18N.ko[...]` lines themselves, because the comment markers it used to rely on are gone.

`strip_comments.py` verifies every file before writing it - the Python AST must be unchanged apart
from removed docstrings, and the JS token stream must be identical, including which tokens follow a
line break - and leaves a file untouched if it cannot prove that. It is idempotent. Its scope is
`app/` and `tests/` (comments and docstrings) and `demo/*.py` (comments only; the docstrings in
`demo/` are this tooling's own documentation).

When an anchor cannot be found `apply_demo_mode.py` names the edit and the anchor rather than
guessing. That is the intended behaviour: an upstream refactor should fail loudly here. Its markers
and replacements contain no comments, so it can run after the stripper and its output still passes
`strip_comments.py --check`.

Order matters for the rest: scrub and strip the copied source **before** regenerating, because the
fixture's verbatim-passthrough rule uses the application's own source as its vocabulary. Do it
second and a tenant string in a comment becomes an allowed value in the fixture.

## Auditing it

```bash
python demo/audit_fixture.py
```

A different question from the verifier's. The verifier asks whether real data survived; this asks
whether the synthetic data contradicts itself — a count that disagrees with the list beside it, a
histogram that does not sum to its total, a rate that is not its own numerator over its own
denominator, a `firstBlock` later than its `lastBlock`, a duplicated identity. **Run it after every
regeneration.** The first run found 64 contradictions, three of which were visible on the rendered
page and none of which were visible in the JSON.

## Verifying it

```bash
# allowlist only - safe to run anywhere, including CI on a public repo
python demo/verify_demo.py

# both checks - run this before publishing anything
python demo/verify_demo.py \
    --snapshot ../ms365-security-dashboard/data/graph_snapshot.json \
    --harvest  ../ms365-security-dashboard
```

The second form harvests identifiers from the private material and asserts that none of them appears
anywhere in this repository — source, comments, docs and fixture alike. Run it after any edit that
touches a comment, not just after regenerating the data: the one leak it has caught so far was a
partner domain in a source comment, put there years after the sanitisation rules were written.

## What the fixture deliberately does not preserve

- **Counts.** List lengths are scaled by a single shared factor, because "six global admins, 47
  devices" is posture, and it survives value-level masking untouched.
- **Absolute time.** Timestamps keep their distance from the collection moment, so trends and
  "last seen" logic still behave, but no real instant is reproduced. The page shifts them again at
  load time so the demo never ages into a stale-data warning.
- **Free text.** Mail subjects, incident titles, policy names and finding text are authored pools.
  Nothing is derived from the original string.

## What it does preserve

The **shape**: every key, every nesting level, every field the UI reads. That is the point — the demo
exercises the same render paths as production, so `tests/demo_render_test.js` is a real test of the UI
and not of a hand-written mock that drifted.
