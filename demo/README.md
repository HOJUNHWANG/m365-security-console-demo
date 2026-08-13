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
and it is short enough to check by eye — currently 99 entries, all Microsoft platform terms, UI enum
tokens and Graph resource paths.

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
