"""Anomalous sign-ins - based on the Entra ID sign-in logs (/auditLogs/signIns).

When the tenant was upgraded to Business Premium (2026-07-23) it gained Entra ID **P1**, so this
card was moved back from the unified-audit-log workaround (asynchronous, beta) to the proper P1
sign-in logs. That buys us three things: a synchronous call (no state file, no polling - it
completes within one collection cycle); rich fields such as a human-readable failure reason
(status.failureReason) and location; and a documented, stable v1.0 endpoint.

Requires AuditLog.Read.All (application permission, admin-consented). Success is determined the
same way the Entra portal does it: status.errorCode == 0 is a success, anything else counts as a
failure or interrupt.

Metrics produced: sign-in success/failure counts and failure rate, top failed users (brute-force
targets), IPs failing against many users (password-spray signal), users signing in from many IPs
(account sharing, travel or compromise), the daily failure trend, and a sample of recent failures.
Note: the details (UPN, IP, location) are for dashboard display only and are never sent to the AI
summary - ai_overview._sanitize egresses aggregate counts only.

By default signIns returns interactive user sign-ins, which is where the signal for brute-force
and spray detection lives (non-interactive token-refresh noise is excluded).

NON-INTERACTIVE BLIND SPOT (added 2026-07-30)
--------------------------------------------
That default is also a hole. An UNATTENDED identity - a Teams Rooms console, a shared-device
account, a workload identity - never signs in interactively, so it NEVER appears in the collection
above. On 2026-07-30 the Security Defaults -> Conditional Access cutover blocked both Teams Rooms
accounts for about two hours and the post-cutover check reported "0 blocks", because it only ever
queried the interactive collection: 89 interactive records with 0 CA failures, while 4,821
non-interactive records carried more than 700.

So a second, separate pass reads the non-interactive collection. It is kept separate on purpose:

  * The interactive metrics must NOT change. A non-interactive CA `failure` is usually BENIGN - the
    client attempts a silent token refresh, CA answers "MFA needed", the client then prompts and
    the user succeeds. Folding those into `failed` / `failRate` would inflate the failure rate
    enormously and destroy the brute-force and spray signals, which rely on interactive volume.
  * What matters here is the opposite question: which accounts are blocked and NEVER succeed.
    A block followed by a success is the system working. A block with no success is an outage - and
    an account that cannot produce an interactive success is, by definition, one that cannot answer
    a prompt.

Cost control. Unfiltered, this tenant produces roughly 5,000 non-interactive records per two hours,
so a 7-day pull is out of the question. Three things keep it cheap:
  1. `conditionalAccessStatus eq 'failure'` is filtered SERVER-side, so only blocks come back.
  2. A short window with a record cap. Results are newest-first, so a cap yields the most RECENT
     slice; the oldest record actually fetched is reported as `coverageFrom` so a shortened window
     is visible rather than silently assumed.
  3. The per-account "did it recover" lookup runs only for accounts that already look stuck, and is
     capped. When nothing is wrong it costs nothing.

The signInEventTypes filter is beta-only - v1.0 rejects it with 400.
"""
import asyncio
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

import httpx

from .. import signin_cache
from ..graph_client import graph_get

WINDOW_DAYS = 7            # aggregation window
MAX_RECORDS = 8000         # pagination cap (anything beyond is reported as truncated)
# Used by the non-interactive pass below. NOT the API maximum (1000) on purpose: signIns rejects a
# request that costs too many resource units regardless of remaining budget - measured 2026-08-05,
# $top=500 and $top=1000 both returned 429 while $top=250 returned 200 in 8.8 s. See
# signin_cache.PAGE_SIZE for the full measurement.
PAGE_SIZE = int(os.environ.get("SIGNIN_PAGE_SIZE", "250"))
MULTI_IP_THRESHOLD = 3     # flag users who signed in successfully from at least this many distinct IPs

# --- non-interactive pass ---------------------------------------------------------------------
_BETA = "https://graph.microsoft.com/beta"
# Every event type EXCEPT interactive. Interactive sign-ins are already covered by the main pass,
# and this predicate is what makes Graph return the non-interactive collection at all.
_NI_PREDICATE = "signInEventTypes/any(t: t ne 'interactiveUser')"
NI_WINDOW_HOURS = 12       # short by design: "is something blocked right now", not a trend
NI_MAX_RECORDS = 2000      # newest-first, so the cap keeps the most recent slice
# Recovery lookups. Almost every account's last INTERACTIVE success predates its last silent-refresh
# block, so nearly all of them need this lookup - a small cap left most verdicts as "unknown", which
# is useless. The lookups are independent, so they run concurrently (bounded) instead of serially:
# ~3s each, so 20 in sequence would add a minute while 20 in parallel batches adds a few seconds.
NI_MAX_PROBE = 25
NI_PROBE_CONCURRENCY = 6
# How long a recovery verdict is reused before re-asking Graph. See _last_success for why these
# probes, not the paged window pull, dominated the request count against the throttled endpoint.
PROBE_TTL_MIN = float(os.environ.get("SIGNIN_PROBE_TTL_MIN", "60"))
# userId -> (asked_at, result). Process-lifetime; pruned in _prune_probe_cache.
_probe_cache: dict[str, tuple[datetime, str | None]] = {}
# "Had a success after the last block" is not the same as "nothing is broken". One app can loop
# indefinitely while everything else works: on 2026-07-30 a user's Outlook Mobile was blocked
# continuously for over an hour while their other clients kept succeeding, so a purely
# success-after-block test would have called that account healthy. An account still accumulating
# blocks at the end of the window is reported separately as `flapping`.
NI_RECENT_MINUTES = 30

# Non-modern (legacy) authentication clients - worth blocking with Conditional Access.
# 'Browser', 'Mobile Apps and Desktop clients' and 'Unknown' are excluded (not legacy, or unclear).
_LEGACY_CLIENTS = {
    "Exchange ActiveSync", "IMAP4", "POP3", "SMTP", "Authenticated SMTP",
    "MAPI Over HTTP", "Offline Address Book", "Outlook Anywhere (RPC over HTTP)",
    "Exchange Web Services", "AutoDiscover", "Exchange Online PowerShell",
    "Reporting Web Services", "Other clients",
}

# --- Conditional Access result buckets -------------------------------------------------------
# Every sign-in carries appliedConditionalAccessPolicies[], one entry per CA policy that was
# evaluated, each with a `result`. The SAME field describes both lifecycle stages - a report-only
# pilot and, later, the enforced rollout - only the values differ. So a single walk over this
# field covers both, and flipping a policy from report-only to enabled needs NO code change here.
# It also means the pilot prediction and the enforced outcome land in the same metric, which is
# what makes them comparable after cutover.
#
# Note: do NOT use the sign-in's top-level conditionalAccessStatus for this - that reflects
# ENFORCED policies only (success | failure | notApplied) and stays "success" for a sign-in that a
# report-only policy would have blocked. Report-only impact is invisible there by design.
_RESULTS_REPORT_ONLY = {
    "reportOnlySuccess", "reportOnlyFailure", "reportOnlyInterrupted", "reportOnlyNotApplied",
}
_RESULTS_ENFORCED = {"success", "failure", "notApplied", "notEnabled"}

# Results where the policy's controls were NOT satisfied, i.e. the sign-in was blocked or
# challenged (enforced), or would have been (report-only). This is the pilot's blast radius.
_RESULTS_IMPACT = {"failure", "reportOnlyFailure", "reportOnlyInterrupted"}

# reportOnlyInterrupted = the user would have been interrupted (e.g. an MFA prompt) rather than
# hard-blocked. Counted as impact, but tracked separately: an interrupt is usually an acceptable
# rollout cost, whereas a failure is a genuine lockout to fix before enforcing.
_RESULT_LABELS = {
    "success": "Satisfied", "failure": "Blocked", "notApplied": "Not applied",
    "notEnabled": "Policy off", "reportOnlySuccess": "Would pass",
    "reportOnlyFailure": "Would be blocked", "reportOnlyInterrupted": "Would be interrupted",
    "reportOnlyNotApplied": "Would not apply",
}

# Common sign-in / CA error codes mapped to readable labels (falls back to Graph's failureReason).
_ERR = {
    50053: "Account locked (too many attempts)",
    50055: "Password expired",
    50057: "Account disabled",
    50074: "MFA required — not completed",
    50076: "MFA required by Conditional Access",
    50079: "MFA registration required",
    50097: "Device authentication required (CA)",
    50126: "Invalid username or password",
    50140: "Interrupted — 'Keep me signed in'",
    50144: "AD password expired",
    53000: "Blocked — device not compliant (CA)",
    53001: "Blocked — device not registered/joined (CA)",
    53002: "Blocked — app not approved (CA)",
    53003: "Blocked by Conditional Access policy",
    53004: "MFA registration required to proceed",
    500121: "MFA authentication failed or timed out",
    530002: "Blocked by risk-based Conditional Access",
    65001: "App consent required / not granted",
    700016: "Application not found in tenant",
    90094: "Admin consent required",
}


def _decode(code, reason: str | None) -> str:
    """Turn an error code into a readable label, falling back to the raw failureReason."""
    label = _ERR.get(code)
    if label:
        return label
    reason = (reason or "").strip()
    return reason or (f"error {code}" if code not in (None, 0) else "")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ---------------- Graph calls ----------------
async def _fetch_signins() -> tuple[list, bool]:
    """Interactive sign-ins for the last WINDOW_DAYS.

    Served from `signin_cache`: three sources needed the same 7-day pull, so it is made once per
    collection cycle and shared. The cached records are FULL sign-in records (no $select), which is
    what this card needs, so nothing changed for it except that it may now be the caller that waits
    instead of the caller that fetches. Do not mutate the returned list - it is shared.
    """
    return await signin_cache.get_interactive()


async def _fetch_noninteractive() -> tuple[list, bool]:
    """Non-interactive sign-ins that Conditional Access BLOCKED, newest first.

    conditionalAccessStatus is filtered server-side, so the response holds only blocks instead of
    the full token-refresh firehose. Ordering is newest-first, so hitting the cap shortens the
    window rather than sampling it arbitrarily - the caller reports the oldest record it saw.
    """
    start = _iso(_now() - timedelta(hours=NI_WINDOW_HOURS))
    params = {
        "$filter": f"createdDateTime ge {start} and {_NI_PREDICATE} "
                   f"and conditionalAccessStatus eq 'failure'",
        "$top": PAGE_SIZE,
    }
    records, truncated = [], False
    data = await graph_get(f"{_BETA}/auditLogs/signIns", params=params)
    while True:
        records.extend(data.get("value", []))
        if len(records) >= NI_MAX_RECORDS:
            truncated = True
            break
        nxt = data.get("@odata.nextLink")
        if not nxt:
            break
        data = await graph_get(nxt)
    return records, truncated


async def _last_success(user_id: str) -> str | None:
    """Newest successful USER sign-in for one account within the window.

    Called ONLY for an account that already looks stuck, so the cost is paid only when there is
    something to investigate.

    Two corrections learned on 2026-08-03, both of which silently produced wrong verdicts:

      * The event-type union must NOT include servicePrincipal / managedIdentity. Those records
        carry no userPrincipalName and leak past `userId eq`, so with $top=1 the newest such record
        in the tenant was returned for EVERY account - which made ten different accounts report the
        same "last success" timestamp and every one of them look recovered.
      * Trust nothing about whose record came back: verify userId on the row before using it. The
        filter itself works, but a belt-and-braces check is one comparison and the cost of getting
        this wrong is a stuck account reported as healthy.

    $top is small rather than 1 so that if a stray row does come back there is still a real one
    behind it.

    Cached, because this is the single biggest consumer of the throttled endpoint. Counting the
    filtered `/auditLogs/signIns` requests one cycle makes: ~3 for the shared window pull, ~1-2 for
    the non-interactive pass, and **up to NI_MAX_PROBE (25) here** - so the per-account probes were
    ~80% of the request count, not the big paged pull everyone suspects. Multiplied by two collector
    processes at three cycles an hour, that is what sustained the 2026-08-05 throttle.

    A TTL is the right tool rather than a smaller cap: "has this account had a success since its last
    block" changes on the timescale of a person noticing and re-authenticating, not of a 20-minute
    collection cycle, and cutting the cap instead would just leave more verdicts as "unknown" - the
    exact uselessness NI_MAX_PROBE was raised to fix.
    """
    hit = _probe_cache.get(user_id)
    if hit and (_now() - hit[0]).total_seconds() / 60 < PROBE_TTL_MIN:
        return hit[1]
    start = _iso(_now() - timedelta(hours=NI_WINDOW_HOURS))
    params = {
        "$filter": f"createdDateTime ge {start} and userId eq '{user_id}' "
                   f"and status/errorCode eq 0 and signInEventTypes/any("
                   f"t: t eq 'interactiveUser' or t eq 'nonInteractiveUser')",
        "$top": 10,
    }
    data = await graph_get(f"{_BETA}/auditLogs/signIns", params=params)
    result = None
    for row in (data.get("value") or []):           # newest first
        if (row.get("userId") or "").lower() == (user_id or "").lower():
            result = row.get("createdDateTime") or None
            break
    # Only a completed lookup is cached. A failure raises out of here and is recorded per-account as
    # `probeError`, so caching it would turn one transient error into an hour of blank verdicts.
    _probe_cache[user_id] = (_now(), result)
    _prune_probe_cache()
    return result


def _prune_probe_cache() -> None:
    """Drop expired entries so the cache cannot grow past the accounts actually being probed."""
    if len(_probe_cache) <= NI_MAX_PROBE * 4:
        return
    now = _now()
    for uid in [u for u, (at, _) in _probe_cache.items()
                if (now - at).total_seconds() / 60 >= PROBE_TTL_MIN]:
        _probe_cache.pop(uid, None)


def _actor(r: dict) -> tuple[str, str]:
    """(display value, kind) for a sign-in record.

    A non-interactive pull also returns servicePrincipal and managedIdentity events, which carry no
    userPrincipalName. Falling back keeps a workload identity identifiable instead of collapsing
    every one of them into "(unresolved)".
    """
    upn = (r.get("userPrincipalName") or "").strip().lower()
    if upn and "@" in upn:
        return upn, "user"
    spn = (r.get("servicePrincipalName") or "").strip()
    if spn:
        return spn, "servicePrincipal"
    disp = (r.get("userDisplayName") or "").strip()
    return (disp or "(unresolved)"), ("servicePrincipal" if r.get("servicePrincipalId") else "user")


async def _noninteractive_pass(interactive: list) -> dict:
    """Classify every account with a non-interactive CA block as recovered or stuck.

    `interactive` is the 7-day interactive set already fetched by the main pass, reused here for
    free. Its role is the discriminator: a human blocked on a silent refresh then completes the
    prompt, which lands in the interactive collection as a success. An account with NO interactive
    success at all cannot answer a prompt - that is precisely the unattended case, and precisely
    what the old verification missed.
    """
    try:
        records, truncated = await _fetch_noninteractive()
    except Exception as e:  # noqa: BLE001 - this pass must never sink the whole card
        return {"available": False,
                "reason": f"non-interactive query failed: {e}",
                "windowHours": NI_WINDOW_HOURS}

    # Newest interactive success per account, from data already in memory.
    last_interactive_ok: dict[str, str] = {}
    for r in interactive:
        if (r.get("status") or {}).get("errorCode") != 0:
            continue
        who, _ = _actor(r)
        ts = r.get("createdDateTime") or ""
        if ts > last_interactive_ok.get(who, ""):
            last_interactive_ok[who] = ts

    recent_cut = _iso(_now() - timedelta(minutes=NI_RECENT_MINUTES))
    agg: dict[str, dict] = {}
    for r in records:
        who, kind = _actor(r)
        e = agg.setdefault(who, {
            "user": who, "kind": kind, "userId": r.get("userId"),
            "blocks": 0, "blocksRecent": 0, "lastBlock": "", "firstBlock": "",
            "apps": Counter(), "recentApps": Counter(),
            "policies": Counter(), "controls": Counter(), "codes": Counter(),
        })
        e["blocks"] += 1
        ts = r.get("createdDateTime") or ""
        if ts > e["lastBlock"]:
            e["lastBlock"] = ts
        if not e["firstBlock"] or ts < e["firstBlock"]:
            e["firstBlock"] = ts
        if ts >= recent_cut:
            e["blocksRecent"] += 1
        if r.get("appDisplayName"):
            e["apps"][r["appDisplayName"]] += 1
            if ts >= recent_cut:
                e["recentApps"][r["appDisplayName"]] += 1
        code = (r.get("status") or {}).get("errorCode")
        if code:
            e["codes"][code] += 1
        for p in (r.get("appliedConditionalAccessPolicies") or []):
            if p.get("result") != "failure" or not p.get("displayName"):
                continue
            e["policies"][p["displayName"]] += 1
            for c in ((p.get("enforcedGrantControls") or [])
                      + (p.get("enforcedSessionControls") or [])):
                if c:
                    e["controls"][c] += 1

    # Suspected stuck: no interactive success after the last block. Probe those (and only those)
    # for a non-interactive success, which is how an appliance recovers.
    # NOTE: the loop variable must not be named `e` alongside `except ... as e` - Python rebinds the
    # name to the exception and then DELETES it when the block ends, silently unbinding the account.
    suspects = [acc for acc in agg.values()
                if last_interactive_ok.get(acc["user"], "") <= acc["lastBlock"]]
    suspects.sort(key=lambda acc: -acc["blocks"])
    to_probe, probed = [], 0
    for acc in suspects:
        if not acc.get("userId"):
            # No object id to query - most often a workload identity or an unresolved actor.
            acc["probeSkipped"] = "no userId on the sign-in record"
            continue
        if probed >= NI_MAX_PROBE:
            acc["probeSkipped"] = f"probe cap {NI_MAX_PROBE} reached"
            continue
        to_probe.append(acc)
        probed += 1

    if to_probe:
        sem = asyncio.Semaphore(NI_PROBE_CONCURRENCY)

        async def probe(acc):
            async with sem:
                try:
                    acc["lastAnySuccess"] = await _last_success(acc["userId"])
                except Exception as exc:  # noqa: BLE001 - keep the reason; a silent skip is unreviewable
                    acc["probeError"] = f"{type(exc).__name__}: {exc}"[:160]

        await asyncio.gather(*(probe(a) for a in to_probe))

    accounts = []
    for acc in agg.values():
        inter_ok = last_interactive_ok.get(acc["user"], "")
        any_ok = acc.get("lastAnySuccess") or ""
        last_ok = max(inter_ok, any_ok)
        probe_ran = "lastAnySuccess" in acc
        recovered = bool(last_ok and last_ok > acc["lastBlock"])
        if not recovered and not probe_ran and (acc.get("probeSkipped") or acc.get("probeError")):
            verdict = "unknown"
        elif not recovered:
            # No success at all after the last block: nothing is completing the challenge.
            verdict = "stuck"
        elif acc["blocksRecent"]:
            # Something succeeded, yet blocks are STILL arriving - typically one client stuck in a
            # retry loop while the account's other clients work. Not an outage, not healthy either.
            verdict = "flapping"
        else:
            verdict = "recovered"
        accounts.append({
            "user": acc["user"], "kind": acc["kind"],
            "blocks": acc["blocks"],
            "firstBlock": acc["firstBlock"], "lastBlock": acc["lastBlock"],
            "lastSuccess": last_ok or None,
            # Surfaced so an "unknown" verdict can be explained instead of just shrugged at.
            "probeNote": acc.get("probeError") or acc.get("probeSkipped"),
            # Whether the account can complete a prompt at all is the whole question, so say which
            # kind of success was seen rather than just "it recovered".
            "interactiveSuccess": bool(inter_ok),
            "verdict": verdict,
            "blocksRecent": acc["blocksRecent"],
            "apps": [a for a, _ in acc["apps"].most_common(4)],
            # Which client is still looping - that is what you actually go and fix.
            "recentApps": [a for a, _ in acc["recentApps"].most_common(3)],
            "policies": [p for p, _ in acc["policies"].most_common(3)],
            "controls": [c for c, _ in acc["controls"].most_common(3)],
            "codes": [c for c, _ in acc["codes"].most_common(3)],
        })
    # Stuck first, then still-flapping, then by block volume: that ordering is the work queue.
    order = {"stuck": 0, "flapping": 1, "unknown": 2, "recovered": 3}
    accounts.sort(key=lambda a: (order.get(a["verdict"], 4), -a["blocks"]))

    stuck = [a for a in accounts if a["verdict"] == "stuck"]
    flapping = [a for a in accounts if a["verdict"] == "flapping"]
    return {
        "available": True,
        "reason": None,
        "windowHours": NI_WINDOW_HOURS,
        "recordCount": len(records),
        "truncated": truncated,
        # If truncated, this is the REAL window covered - do not read windowHours as the coverage.
        "coverageFrom": min((r.get("createdDateTime") or "" for r in records), default=None),
        "blockCount": len(records),
        "accountCount": len(accounts),
        "stuckCount": len(stuck),
        "flappingCount": len(flapping),
        "recentMinutes": NI_RECENT_MINUTES,
        "recoveredCount": sum(1 for a in accounts if a["verdict"] == "recovered"),
        "unknownCount": sum(1 for a in accounts if a["verdict"] == "unknown"),
        "stuckUsers": [a["user"] for a in stuck],
        "flappingUsers": [a["user"] for a in flapping],
        "accounts": accounts[:40],
    }


# ---------------- Aggregation ----------------
def _clean_ip(ip: str) -> str:
    if not ip:
        return ""
    ip = ip.strip()
    if ip.startswith("["):                          # [IPv6]:port
        return ip[1:].split("]")[0]
    if ip.count(":") == 1 and ip.count(".") == 3:    # IPv4:port
        return ip.split(":")[0]
    return ip


def _clean_user(raw: str) -> str:
    """Accept only a UPN (e-mail address) as a valid user.

    A failed sign-in can record a username that does not exist, so anything that is not in UPN
    form (contains @) is treated as unresolved. That keeps noise and phantom users out of the counts.
    """
    u = (raw or "").strip().lower()
    if "@" not in u:
        return ""
    return u


def _location(loc: dict) -> str:
    if not loc:
        return ""
    parts = [loc.get("city"), loc.get("countryOrRegion")]
    return ", ".join(p for p in parts if p)


def _claim_state(d: dict) -> str:
    """How much device evidence did this sign-in actually carry?

    This single distinction dominates the blast radius of a device-based CA policy, and neither
    portal shows it. A sign-in with NO device claim fails a device policy for a reason that has
    nothing to do with the device being non-compliant - the client simply never presented a device
    identity (typical for browsers without the Windows Accounts extension, and for embedded
    IE/legacy-Edge webviews). Counting those together with genuinely non-compliant devices makes a
    pilot look far more dangerous than it is, and points remediation at the wrong problem.

      noClaim           -> fix the client/browser SSO, or the device registration
      claimNotCompliant -> a real compliance gap on a known device
      claimCompliant     -> device is compliant yet still blocked: suspect the policy itself
    """
    if not (d.get("deviceId") or "").strip():
        return "noClaim"
    return "claimCompliant" if d.get("isCompliant") else "claimNotCompliant"


def _device(d: dict) -> str:
    """Summarise deviceDetail for a CA impact row.

    Device state is the usual reason a device-targeted CA policy bites, so the compliance and
    managed flags are what you need to triage a pilot hit (e.g. "would be blocked" on an
    unmanaged device = expected; on a managed compliant one = a policy bug).
    """
    if not d:
        return ""
    bits = [(d.get("operatingSystem") or "").strip() or "unknown OS"]
    if d.get("isManaged"):
        bits.append("compliant" if d.get("isCompliant") else "non-compliant")
    else:
        bits.append("unmanaged")
    return " · ".join(bits)


# --- Per-policy scope and state --------------------------------------------------------------
# Two sentinels instead of a set of UPNs. "all" is a policy that targets every user, so every
# sign-in is in scope and there is nothing to enumerate. "unknown" is a scope this code could not
# resolve - reported as such and never silently treated as either extreme, because guessing wrong
# in the "all" direction inflates a scoped policy and guessing wrong the other way hides one.
SCOPE_ALL = "all"
SCOPE_UNKNOWN = "unknown"


async def _members(path: str) -> set | None:
    """UPNs behind a group or a directory role. None means the lookup FAILED - not "no members".

    Keeping those apart is the whole point. A failure collapsing to an empty set would print
    "In scope 0" beside a policy that demonstrably blocked someone, and a zero that looks like a
    measurement is worse than an admitted gap. Measured on 2026-08-12: `$select=userPrincipalName`
    on these collections answers 400 (they are polymorphic directoryObject collections), which is
    what silently zeroed CA-Require-MFA-Admins - a policy with 309 applied sign-ins.

    404 is the exception: a directory role that was never activated in this tenant has no members,
    and an empty set is the correct reading of it.
    """
    out, url = set(), path
    for _ in range(10):        # page cap: membership here is tens, not thousands
        try:
            r = await graph_get(url)
        except httpx.HTTPStatusError as exc:
            return set() if exc.response.status_code == 404 else None
        except Exception:      # noqa: BLE001 - throttled, timed out, forbidden: not a measurement
            return None
        for m in r.get("value") or []:
            if m.get("userPrincipalName"):
                out.add(m["userPrincipalName"].lower())
        url = r.get("@odata.nextLink")
        if not url:
            break
    return out


async def _policy_scope(cond_users: dict) -> object:
    """Which users a CA policy can actually reach: a set of UPNs, SCOPE_ALL, or SCOPE_UNKNOWN.

    This exists because Entra writes an appliedConditionalAccessPolicies entry (result notApplied)
    for EVERY policy on EVERY sign-in, including users the policy does not target. So the raw
    "evaluated" count is the tenant's whole sign-in volume and reads identically on every row - a
    13-person pilot and an all-users MFA policy both showed 2,338. That number cannot distinguish
    the two, which is exactly the distinction the rollout needs.

    Groups are expanded transitively, so a nested group does not silently shrink the scope.
    """
    inc_u = cond_users.get("includeUsers") or []
    if "All" in inc_u:
        return SCOPE_ALL
    scope, unresolved = set(), False
    for uid in inc_u:
        if uid in ("None", ""):
            continue
        if uid == "GuestsOrExternalUsers":
            unresolved = True       # not cheaply enumerable; do not pretend otherwise
            continue
        u = await _safe_upn(uid)
        if u:
            scope.add(u)
        else:
            unresolved = True
    for gid in cond_users.get("includeGroups") or []:
        m = await _members(f"/groups/{gid}/transitiveMembers")
        unresolved = unresolved or m is None
        scope |= m or set()
    for rid in cond_users.get("includeRoles") or []:
        m = await _members(f"/directoryRoles(roleTemplateId='{rid}')/members")
        unresolved = unresolved or m is None
        scope |= m or set()
    # Any part of the include side unread means the audience is bigger than what was gathered, so
    # the count would be wrong in the direction that hides people. Report it as unknown instead.
    if unresolved:
        return SCOPE_UNKNOWN
    # Exclusions are part of the reachable set: an excluded user is never acted on, so counting
    # them as "in scope" would overstate every policy by the break-glass accounts. An unreadable
    # exclusion only overstates the scope, so it is not fatal - unlike an unreadable inclusion.
    for uid in cond_users.get("excludeUsers") or []:
        u = await _safe_upn(uid)
        if u:
            scope.discard(u)
    for gid in cond_users.get("excludeGroups") or []:
        scope -= (await _members(f"/groups/{gid}/transitiveMembers")) or set()
    return scope


async def _safe_upn(uid: str) -> str:
    try:
        u = await graph_get(f"/users/{uid}", params={"$select": "userPrincipalName"})
    except Exception:  # noqa: BLE001 - deleted principal, or a service principal id
        return ""
    return (u.get("userPrincipalName") or "").lower()


async def _policy_meta() -> dict:
    """name -> {state, scope}. Empty dict if the policy list cannot be read.

    The policy object is the authority on whether a policy is enforced. Deriving that from the log
    results instead - which is what this module used to do - misreports for a full window after any
    cutover: on 2026-08-11 two pilot policies were enforced, yet the logs still held their earlier
    report-only rows, so both kept reporting as report-only and the "Report-only Pilot Impact" panel
    counted three report-only policies when the tenant had one.
    """
    try:
        pols = (await graph_get("/identity/conditionalAccess/policies")).get("value") or []
    except Exception:  # noqa: BLE001 - degrade to log-derived mode rather than lose the table
        return {}
    meta = {}
    for p in pols:
        nm = p.get("displayName")
        if not nm:
            continue
        meta[nm] = {
            "state": p.get("state"),
            "scope": await _policy_scope((p.get("conditions") or {}).get("users") or {}),
        }
    return meta


_STATE_MODE = {
    "enabled": "enforced",
    "enabledForReportingButNotEnforced": "report-only",
    "disabled": "off",
}


def _policy_eval_rows(ca_eval: dict, users: dict, controls: dict, claims: dict,
                      in_scope: dict, meta: dict, block_last: dict, success_last: dict) -> list:
    """Collapse the raw per-policy result counters into one row per CA policy.

    Mode comes from the policy object when it is available and falls back to the observed results
    only when it is not. `switched` marks a policy that changed mode inside the window - a cutover -
    which is why the enforced and would-have columns can both be non-zero on the same row.
    """
    rows = []
    for nm, c in ca_eval.items():
        ro = sum(v for k, v in c.items() if k in _RESULTS_REPORT_ONLY)
        en = sum(v for k, v in c.items() if k in _RESULTS_ENFORCED)
        state = (meta.get(nm) or {}).get("state")
        mode = _STATE_MODE.get(state) or ("report-only" if ro else "enforced" if en else "unknown")
        scope = (meta.get(nm) or {}).get("scope", SCOPE_UNKNOWN)
        evaluated = sum(c.values())
        applied = (c["success"] + c["reportOnlySuccess"] + c["failure"]
                   + c["reportOnlyFailure"] + c["reportOnlyInterrupted"])
        # Blocked users who have no successful sign-in AFTER their last block in this window.
        # This is what separates a control doing its job from a person who cannot get in: an MFA
        # policy blocking 38 sign-ins that all then succeeded is normal, while one user left with no
        # success is the thing to act on. Read it as "not seen to recover", not as proof of lockout -
        # a user who simply has not tried again since looks identical, which is why the UI says so.
        blocked_users = block_last.get(nm) or {}
        stuck = sorted(u for u, t in blocked_users.items() if success_last.get(u, "") <= t)
        rows.append({
            "policy": nm,
            "mode": mode,
            # Both mode families present in the window = the switch happened here. Expected during a
            # cutover, and the only honest explanation for a row with real blocks AND would-blocks.
            "switched": bool(ro and en),
            # Sign-ins by users the policy can actually reach. None = all users (whole tenant),
            # "unknown" = could not resolve; the UI must not print a number it does not have.
            "inScope": (evaluated if scope == SCOPE_ALL
                        else None if scope == SCOPE_UNKNOWN
                        else in_scope.get(nm, 0)),
            "scopeKind": ("all" if scope == SCOPE_ALL
                          else "unknown" if scope == SCOPE_UNKNOWN else "targeted"),
            "evaluated": evaluated,
            "applied": applied,
            "pass": c["success"] + c["reportOnlySuccess"],
            # Split on purpose: `blocked` is what the policy DID, `wouldBlock` is what it WOULD have
            # done while report-only. Summing them - the old behaviour - made an enforced policy that
            # has blocked nobody read as 23 blocks, purely from its own pre-cutover report-only rows.
            "blocked": c["failure"],
            "blockedUsers": len(blocked_users),
            "stuckUsers": len(stuck),
            "stuckSample": stuck[:5],
            "wouldBlock": c["reportOnlyFailure"],
            "interrupted": c["reportOnlyInterrupted"],
            "notApplied": c["notApplied"] + c["reportOnlyNotApplied"] + c["notEnabled"],
            "usersImpacted": len(users.get(nm) or ()),
            "controls": [ctl for ctl, _ in (controls.get(nm) or Counter()).most_common(5)],
            # Of the sign-ins this policy would stop, how many carried no device evidence at all?
            # A high number here means "fix the client", not "the devices are non-compliant".
            "noClaim": (claims.get(nm) or Counter())["noClaim"],
            "claimNotCompliant": (claims.get(nm) or Counter())["claimNotCompliant"],
            "claimCompliant": (claims.get(nm) or Counter())["claimCompliant"],
        })
    # Someone who cannot get in outranks everything, then real blocks, then predictions. Sorting by
    # raw block count alone put an MFA policy doing its job above a device policy locking a user out.
    rows.sort(key=lambda x: (x["stuckUsers"], x["blocked"], x["wouldBlock"] + x["interrupted"],
                             x["evaluated"]), reverse=True)
    return rows


def _aggregate(records: list, truncated: bool, meta: dict | None = None) -> dict:
    meta = meta or {}
    logins = failed = 0
    users, ips = set(), set()
    failed_by_user = Counter()
    failed_by_ip = Counter()
    ip_failed_users = defaultdict(set)   # IP -> {users it failed against}
    user_login_ips = defaultdict(set)    # user -> {IPs they signed in from successfully}
    failed_by_day = Counter()
    recent_failures = []
    # Conditional Access diagnostics and legacy authentication
    ca_status_counts = Counter()
    ca_fail_by_policy = Counter()
    ca_fail_by_control = Counter()
    ca_failures = []
    # Per-policy evaluation across BOTH lifecycles (report-only pilot and enforced rollout)
    ca_eval = defaultdict(Counter)        # policy -> Counter of raw result values
    ca_eval_users = defaultdict(set)      # policy -> users hit by an impact result
    ca_eval_controls = defaultdict(Counter)   # policy -> controls involved in impact results
    ca_eval_claim = defaultdict(Counter)      # policy -> claim state of its impacted sign-ins
    ca_in_scope = Counter()               # policy -> sign-ins by users the policy actually targets
    # A block is not automatically a problem: an MFA policy stopping a bad sign-in is the control
    # working. What distinguishes "working" from "locked out" is whether the same user got in
    # afterwards, so the last block per policy/user is kept next to the last success per user.
    ca_block_last = defaultdict(dict)     # policy -> {user: latest block timestamp}
    last_success_ts = {}                  # user -> latest successful sign-in timestamp
    ro_impact = []                        # report-only: sign-ins that WOULD have been affected
    ro_impact_users = set()
    ro_by_control = Counter()
    ro_by_claim = Counter()
    legacy_by_client = Counter()
    legacy_users = set()

    for r in records:
        upn = _clean_user(r.get("userPrincipalName") or "")
        ip = _clean_ip(r.get("ipAddress") or "")
        ts = r.get("createdDateTime") or ""
        status = r.get("status") or {}
        code = status.get("errorCode")
        # Same rule the Entra portal uses: errorCode == 0 is success, anything else is a failure/interrupt
        is_success = code == 0
        loc = _location(r.get("location") or {})
        ca_status = r.get("conditionalAccessStatus")
        client = r.get("clientAppUsed")
        if upn:
            users.add(upn)
        if ip:
            ips.add(ip)
        if ca_status:
            ca_status_counts[ca_status] += 1
        # Legacy (non-modern) authentication - a candidate for blocking with CA
        if client in _LEGACY_CLIENTS:
            legacy_by_client[client] += 1
            if upn:
                legacy_users.add(upn)

        if is_success:
            logins += 1
            if upn and ts and ts > last_success_ts.get(upn, ""):
                last_success_ts[upn] = ts
            if upn and ip:
                user_login_ips[upn].add(ip)
        else:
            failed += 1
            if upn:
                failed_by_user[upn] += 1
            if ip:
                failed_by_ip[ip] += 1
            if ip and upn:
                ip_failed_users[ip].add(upn)
            if ts:
                failed_by_day[ts[:10]] += 1
            recent_failures.append({
                "time": ts,
                "user": upn or "(unresolved)",   # no UPN means we could not resolve the user
                "ip": ip,
                "code": code,
                "error": _decode(code, status.get("failureReason")),  # decoded reason (falls back to failureReason)
                "location": loc,
            })

        # ---- Conditional Access: one pass over the per-policy evaluations ----
        # Runs for EVERY sign-in, not just enforced failures, so a report-only policy's impact is
        # captured even though the sign-in itself succeeded (errorCode 0, caStatus success).
        applied = r.get("appliedConditionalAccessPolicies") or []
        en_names, en_controls = [], []       # enforced failures on this sign-in
        ro_names, ro_controls = [], []       # report-only impact on this sign-in
        ro_interrupt_only = True             # no hard "would be blocked" seen yet
        claim = _claim_state(r.get("deviceDetail") or {})
        for p in applied:
            res = p.get("result")
            nm = p.get("displayName")
            if not nm or not res:
                continue
            ca_eval[nm][res] += 1
            # Is this sign-in's user someone the policy targets at all? SCOPE_ALL needs no test
            # (handled when the row is built); an unresolved scope stays uncounted rather than
            # guessed.
            sc = (meta.get(nm) or {}).get("scope")
            if isinstance(sc, set) and upn and upn.lower() in sc:
                ca_in_scope[nm] += 1
            if res not in _RESULTS_IMPACT:
                continue
            # Session controls matter as much as grant controls here: token protection and
            # sign-in frequency are enforced as SESSION controls, so a policy built on them
            # would otherwise show an empty control list and look like it had no effect.
            controls = [c for c in ((p.get("enforcedGrantControls") or [])
                                    + (p.get("enforcedSessionControls") or [])) if c]
            if upn:
                ca_eval_users[nm].add(upn)
            ca_eval_claim[nm][claim] += 1
            for ctl in controls:
                ca_eval_controls[nm][ctl] += 1
            if res in _RESULTS_REPORT_ONLY:
                # Only if the policy is STILL report-only. After a cutover its earlier report-only
                # rows stay in the window for another seven days, and they are history, not a
                # forecast: showing them under "what would happen if you enforced this" describes a
                # decision that has already been taken. On 2026-08-12 that was 46 of the rows.
                if _STATE_MODE.get((meta.get(nm) or {}).get("state"), "report-only") != "report-only":
                    continue
                ro_names.append(nm)
                ro_controls.extend(controls)
                if res == "reportOnlyFailure":
                    ro_interrupt_only = False
            else:
                en_names.append(nm)
                en_controls.extend(controls)
                if upn and ts and ts > ca_block_last[nm].get(upn, ""):
                    ca_block_last[nm][upn] = ts
                ca_fail_by_policy[nm] += 1
                for ctl in controls:
                    ca_fail_by_control[ctl] += 1

        # Enforced block - kept on the original contract (Overview action items + Threats panel).
        # Gated on caStatus so the existing count keeps its meaning: sign-ins CA actually stopped.
        if ca_status == "failure":
            ca_failures.append({
                "time": ts, "user": upn or "(unresolved)", "ip": ip, "location": loc,
                "policies": en_names, "controls": sorted(set(en_controls)),
                "code": code, "error": _decode(code, status.get("failureReason")),
            })

        # Report-only impact - what enforcing the pilot policies would have done to this sign-in.
        if ro_names:
            if upn:
                ro_impact_users.add(upn)
            for ctl in set(ro_controls):
                ro_by_control[ctl] += 1
            ro_by_claim[claim] += 1
            ro_impact.append({
                "claim": claim,   # noClaim | claimNotCompliant | claimCompliant - see _claim_state
                "time": ts, "user": upn or "(unresolved)", "ip": ip, "location": loc,
                "policies": sorted(set(ro_names)), "controls": sorted(set(ro_controls)),
                "app": r.get("appDisplayName") or "",
                "client": client or "",
                "device": _device(r.get("deviceDetail") or {}),
                # An interrupt (e.g. MFA prompt) is a rollout cost; a block is a lockout to fix first
                "severity": "interrupt" if ro_interrupt_only else "block",
                "signInSucceeded": is_success,
            })

    total = logins + failed
    # Password-spray signal: one IP failing against several users (users >= 2), ranked by user count first
    spray = sorted(
        ({"ip": ip, "failed": failed_by_ip[ip], "users": len(u)}
         for ip, u in ip_failed_users.items() if len(u) >= 2),
        key=lambda x: (x["users"], x["failed"]), reverse=True,
    )[:10]
    multi_ip = sorted(
        ({"user": u, "ips": len(s), "ipList": sorted(s)} for u, s in user_login_ips.items()
         if len(s) >= MULTI_IP_THRESHOLD),
        key=lambda x: x["ips"], reverse=True,
    )[:10]

    recent_failures.sort(key=lambda x: x["time"], reverse=True)
    ca_failures.sort(key=lambda x: x["time"], reverse=True)
    # Hard blocks before interrupts, newest first - the lockouts are what must be fixed pre-enforce
    ro_impact.sort(key=lambda x: (x["severity"] == "block", x["time"]), reverse=True)
    policy_eval = _policy_eval_rows(ca_eval, ca_eval_users, ca_eval_controls, ca_eval_claim,
                                    ca_in_scope, meta, ca_block_last, last_success_ts)
    ro_blocks = sum(1 for x in ro_impact if x["severity"] == "block")

    return {
        "windowDays": WINDOW_DAYS,
        "windowEnd": _iso(_now()),
        "recordCount": len(records),
        "truncated": truncated,
        "logins": logins,
        "failed": failed,                       # key kept for Overview/action-item compatibility
        "recent": total,                        # Overview compatibility key (successes = recent - failed)
        "failRate": round(failed / total * 100, 1) if total else 0,
        "uniqueUsers": len(users),
        "uniqueIps": len(ips),
        "topFailedUsers": [{"user": u, "count": c} for u, c in failed_by_user.most_common(10)],
        "sprayIps": spray,
        "multiIpUsers": multi_ip,
        "failedByDay": [{"date": d, "count": failed_by_day[d]} for d in sorted(failed_by_day)],
        "recentFailures": recent_failures[:25],
        # --- Conditional Access diagnostics ---
        "caStatusCounts": dict(ca_status_counts),
        "caFailedCount": len(ca_failures),
        "caFailByPolicy": [{"policy": p, "count": c} for p, c in ca_fail_by_policy.most_common(10)],
        "caFailByControl": [{"control": c, "count": n} for c, n in ca_fail_by_control.most_common()],
        "caFailures": ca_failures[:25],
        # --- Per-policy CA evaluation (report-only pilot AND enforced rollout, same metric) ---
        "caPolicyEval": policy_eval,
        "caPolicyEvalCount": len(policy_eval),
        # --- Report-only pilot: blast radius if these policies were enforced today ---
        # Counted from the policies' real state, so a policy enforced yesterday stops being counted
        # today rather than a window later.
        "caReportOnlyPolicyCount": sum(1 for p in policy_eval if p["mode"] == "report-only"),
        # Policies whose mode changed inside the window - a cutover the reader needs to know about
        # when a row shows both real and hypothetical blocks.
        "caSwitchedPolicies": [p["policy"] for p in policy_eval if p["switched"]],
        "caPolicyMetaAvailable": bool(meta),
        "caReportOnlyImpactCount": len(ro_impact),
        "caReportOnlyBlockCount": ro_blocks,
        "caReportOnlyInterruptCount": len(ro_impact) - ro_blocks,
        "caReportOnlyUsers": len(ro_impact_users),
        "caReportOnlyByControl": [{"control": c, "count": n} for c, n in ro_by_control.most_common()],
        # The remediation split: client/registration problem vs a real compliance gap vs policy bug
        "caReportOnlyByClaim": {
            "noClaim": ro_by_claim["noClaim"],
            "claimNotCompliant": ro_by_claim["claimNotCompliant"],
            "claimCompliant": ro_by_claim["claimCompliant"],
        },
        "caReportOnlyImpact": ro_impact[:40],
        # --- Legacy authentication ---
        "legacyAuthCount": sum(legacy_by_client.values()),
        "legacyUsers": len(legacy_users),
        "legacyByClient": [{"client": c, "count": n} for c, n in legacy_by_client.most_common()],
    }


# ---------------- Entry point ----------------
async def fetch() -> dict:
    """Fetch the sign-in logs, aggregate, return. 403s are handled upstream by _safe.

    The non-interactive pass runs after the interactive one because it reuses those records to tell
    a recovered account from a stuck one, and it is deliberately additive: it contributes its own
    key and changes none of the interactive metrics.
    """
    records, truncated = await _fetch_signins()
    # The policy objects decide mode and scope; without them the aggregation still works, it just
    # falls back to inferring mode from the logs (see _policy_eval_rows).
    agg = _aggregate(records, truncated, await _policy_meta())
    agg["nonInteractive"] = await _noninteractive_pass(records)
    # signinData: set when the shared pull fell back to an earlier one (see signin_cache).
    return {"available": True, "pending": False, "note": None,
            "signinData": signin_cache.stale_info(), **agg}
