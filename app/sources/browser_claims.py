"""Browser device-claim coverage - has the Microsoft SSO extension actually reached each user?

Why this card exists
--------------------
Conditional Access can only evaluate a device if the sign-in CARRIES a device claim. Edge sends it
natively; **Chrome does not** unless the "Microsoft Single Sign On" extension is installed. Measured
2026-08-02 over 7 days: Edge 734/792 sign-ins carried a claim (93%), Chrome **0/1,193**. Enforcing the
device-filter CA in that state would lock out every Chrome user on an approved company laptop.

Intune deploys the extension automatically only on Windows **Pro** (via an ADMX-ingested Chrome
policy). ADMX ingestion is rejected on Windows **Home** with `0x86000013`, and 11 of 13 enrolled
devices here are Home - so on those the extension must be installed by hand
(`docs/chrome-sso-extension-guide.md`). This card is how that rollout is tracked.

There is NO API that lists a browser's extensions. Graph cannot see them, and Intune only reports
`detectedApps` (MSI/Win32 installs), which never includes a Chrome extension. So presence is measured
by its only observable EFFECT: does this user's Chrome sign-in carry `deviceDetail.deviceId`?

That inference has one important limit, recorded here so the card is not over-read: a claim only
appears when the request actually traverses `login.microsoftonline.com`. A user who installed the
extension but has not signed out since will keep producing claimless rows from cached session
cookies. So `missing` means "not yet PROVEN installed", not "definitely not installed" - which is
exactly the right bar, because an unproven install is also an unproven CA outcome.

Attribution is per USER, not per device: a claimless sign-in has no device claim, therefore no device
name either, so there is nothing to attribute it to but the account.

Read-only. Requires AuditLog.Read.All + Directory.Read.All (already consented); the Intune edition
lookup and the pilot-group lookup are both optional and degrade to empty.
"""
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from .. import signin_cache
from ..graph_client import graph_get

_BETA = "https://graph.microsoft.com/beta"

WINDOW_DAYS = 7
MAX_SIGNINS = 8000
PAGE_SIZE = 1000

# The group whose members are in scope for the device-filter CA - i.e. who must actually have the
# extension before enforcement. Everyone else is reported for context only.
PILOT_GROUP = os.environ.get("PILOT_GROUP_NAME", "CA-Pilot-Users")

# Chrome Web Store identity of the extension being rolled out (display only).
EXTENSION_NAME = "Microsoft Single Sign On"
EXTENSION_ID = "ppnbnpeolgkicgegkbkbjmhlideopiji"

# Browsers that send the device claim without any add-on. Chromium-based Edge does it through the
# same native-messaging host the Chrome extension talks to, but built in.
NATIVE_BROWSERS = ("edge", "internet explorer", "ie")

# The only browsers the extension can FIX. Deliberately narrow: Safari and mobile browsers also fail
# to send a claim, but no extension exists for them, so counting them as "not yet installed" turns
# every iPhone into a rollout task.
FIXABLE_BROWSERS = ("chrome", "opera")

# Entra platform tokens, as they appear in conditions.platforms.includePlatforms.
_OS_TO_PLATFORM = (
    ("windowsphone", "windowsPhone"),   # must precede the plain "windows" test
    ("windows", "windows"),
    ("ios", "iOS"),
    ("ipados", "iOS"),
    ("macos", "macOS"),
    ("mac os", "macOS"),
    ("os x", "macOS"),
    ("android", "android"),
    ("linux", "linux"),
    ("ubuntu", "linux"),
    ("debian", "linux"),
    ("fedora", "linux"),
)


async def _pages(url, params=None, cap=20000):
    out = []
    data = await graph_get(url, params=params)
    while True:
        out.extend(data.get("value", []))
        nxt = data.get("@odata.nextLink")
        if not nxt or len(out) >= cap:
            break
        data = await graph_get(nxt)
    return out


async def _optional(url, params=None, cap=20000):
    """Auxiliary lookup - the card still works without it, so a failure must not kill the source."""
    try:
        return await _pages(url, params, cap)
    except Exception:  # noqa: BLE001
        return []


def _family(browser: str) -> str:
    """Collapse 'Chrome 150.0.0' to 'Chrome'. The version is noise for this question."""
    b = (browser or "").strip()
    if not b:
        return ""
    low = b.lower()
    for name in ("edge", "chrome", "firefox", "safari", "opera", "internet explorer", "ie"):
        if name in low:
            return {"ie": "Internet Explorer", "internet explorer": "Internet Explorer"}.get(
                name, name.capitalize())
    return b.split()[0]


def _is_native(family: str) -> bool:
    fl = (family or "").lower()
    return any(n in fl for n in NATIVE_BROWSERS)


def _needs_extension(family: str) -> bool:
    """Can this browser be fixed by installing the extension? Drives the rollout verdict."""
    fl = (family or "").lower()
    return bool(fl) and not _is_native(fl) and any(n in fl for n in FIXABLE_BROWSERS)


def _unfixable(family: str) -> bool:
    """Non-Edge browser with no extension available (Safari, Firefox, mobile)."""
    fl = (family or "").lower()
    return bool(fl) and not _is_native(fl) and not _needs_extension(fl)


def _platform_of(os_name: str) -> str | None:
    """Map deviceDetail.operatingSystem ('Windows10', 'Ios 26.5.2', 'MacOs') to an Entra platform."""
    low = (os_name or "").strip().lower()
    if not low:
        return None
    for needle, token in _OS_TO_PLATFORM:
        if low.startswith(needle) or needle in low:
            return token
    return None


async def _device_policy_platforms() -> tuple[set | None, list]:
    """Which platforms do the device-dependent CA policies actually evaluate?

    This exists because of a real mistake: the card first judged EVERY non-Edge browser sign-in and
    reported Safari (42 rows, 0 claims) as something to resolve before enforcement. All three pilot
    device policies are scoped `includePlatforms: ["windows"]`, so iOS/macOS/Android are never
    evaluated by them - measured after the platform condition was in place, 31 non-Windows sign-ins
    produced 36 policy verdicts and every one was `reportOnlyNotApplied`. Judging out-of-scope
    platforms invents work and, worse, hides the in-scope number behind it.

    Returns (platform set or None for "all platforms", [policy names]). On failure returns
    (None, []) - i.e. assume everything is in scope, which over-reports rather than under-reports.
    """
    try:
        pols = (await graph_get("/identity/conditionalAccess/policies")).get("value") or []
    except Exception:  # noqa: BLE001 - Policy.Read.All may not be consented; degrade, do not die
        return None, []

    names, platforms, unbounded = [], set(), False
    for p in pols:
        if p.get("state") == "disabled":
            continue
        cond = p.get("conditions") or {}
        grants = set((p.get("grantControls") or {}).get("builtInControls") or [])
        rule = ((cond.get("devices") or {}).get("deviceFilter") or {}).get("rule") or ""
        # Device-dependent = needs a device claim to be satisfiable at all.
        if not (grants & {"compliantDevice", "domainJoinedDevice"} or "device." in rule):
            continue
        names.append(p.get("displayName"))
        plat = cond.get("platforms") or {}
        inc = [x for x in (plat.get("includePlatforms") or []) if x]
        exc = {x for x in (plat.get("excludePlatforms") or []) if x}
        if not inc or "all" in inc:
            unbounded = True
        else:
            platforms |= {x for x in inc if x not in exc}
    if unbounded or not names:
        return None, names
    return platforms, names


async def fetch() -> dict:
    # Interactive browser sign-ins only. Non-interactive rows (token refreshes, service traffic)
    # never carry a browser and would dilute the ratio - and v1.0 /auditLogs/signIns returns
    # interactive only, which is what signin_cache serves.
    # Shared with risky_signins and device_identity: one pull per collection cycle.
    signins, _ = await signin_cache.get_interactive()

    # Who is in scope for the device-filter CA. Optional: without it every user is "context".
    pilot: dict[str, str] = {}          # userId -> UPN
    groups = await _optional("/groups", {"$filter": f"displayName eq '{PILOT_GROUP}'",
                                         "$select": "id,displayName"})
    if groups:
        members = await _optional(f"/groups/{groups[0]['id']}/members",
                                  {"$select": "id,userPrincipalName", "$top": "999"})
        pilot = {(m.get("id") or "").lower(): m.get("userPrincipalName")
                 for m in members if m.get("id")}
    pilot_ids = set(pilot)

    # Windows edition per user, so a Chrome user whose only device is Pro is not chased by hand -
    # Intune installs the extension there. skuFamily is beta-only.
    editions_by_user: dict[str, set] = defaultdict(set)
    managed = await _optional(f"{_BETA}/deviceManagement/managedDevices",
                              {"$select": "id,deviceName,userPrincipalName,skuFamily,operatingSystem",
                               "$top": "100"})
    for m in managed:
        upn = (m.get("userPrincipalName") or "").lower()
        if upn and m.get("skuFamily"):
            editions_by_user[upn].add(m["skuFamily"])

    scope_platforms, scope_policies = await _device_policy_platforms()

    # ---- per user, per browser family ----
    per_user: dict[str, dict] = {}
    fam_totals: Counter = Counter()
    fam_claims: Counter = Counter()
    out_of_scope: Counter = Counter()      # platform -> sign-ins the device policies never evaluate
    unknown_platform = 0

    for r in signins:
        dd = r.get("deviceDetail") or {}
        fam = _family(dd.get("browser"))
        if not fam:
            continue                      # not a browser sign-in
        # A sign-in on a platform the device policies do not target is not a rollout task. Counting
        # it as one produced a false "Safari must be resolved before enforcement" finding.
        if scope_platforms is not None:
            plat = _platform_of(dd.get("operatingSystem"))
            if plat is None:
                unknown_platform += 1
            elif plat not in scope_platforms:
                out_of_scope[plat] += 1
                continue
        uid = (r.get("userId") or "").lower()
        upn = r.get("userPrincipalName") or "(unknown)"
        has = bool(dd.get("deviceId"))
        ts = r.get("createdDateTime") or ""

        fam_totals[fam] += 1
        if has:
            fam_claims[fam] += 1

        u = per_user.setdefault(uid or upn, {
            "user": upn, "userId": uid or None,
            "browsers": {}, "total": 0, "claim": 0,
        })
        u["total"] += 1
        u["claim"] += 1 if has else 0
        b = u["browsers"].setdefault(fam, {
            "total": 0, "claim": 0, "lastClaim": None, "lastNoClaim": None, "devices": set(),
        })
        b["total"] += 1
        if has:
            b["claim"] += 1
            if ts > (b["lastClaim"] or ""):
                b["lastClaim"] = ts
            if dd.get("displayName"):
                b["devices"].add(dd["displayName"])
        else:
            if ts > (b["lastNoClaim"] or ""):
                b["lastNoClaim"] = ts

    rows = []
    for key, u in per_user.items():
        # Only browsers that need the add-on decide the verdict. Edge-only users are done already.
        needing = {f: b for f, b in u["browsers"].items() if _needs_extension(f)}
        n_total = sum(b["total"] for b in needing.values())
        n_claim = sum(b["claim"] for b in needing.values())
        last_claim = max((b["lastClaim"] or "") for b in needing.values()) if needing else ""
        last_no = max((b["lastNoClaim"] or "") for b in needing.values()) if needing else ""

        if not needing:
            # Edge/IE only, or only browsers no extension exists for - nothing to install either way.
            status = "nativeOnly"
        elif n_claim == 0:
            status = "missing"          # not one claim-bearing sign-in: unproven
        elif n_claim == n_total:
            status = "ok"
        elif last_claim and last_claim > last_no:
            # Claims started and the claimless rows are all OLDER - the classic shape right after an
            # install, since pre-install history stays in the window for 7 days. Treat as done.
            status = "ok"
        else:
            # Claims exist but the MOST RECENT sign-in still had none: a second machine without the
            # extension, or an incognito/other-profile session. Needs a look, not a re-install.
            status = "partial"

        upn = u["user"]
        eds = sorted(editions_by_user.get(upn.lower(), set()))
        rows.append({
            "user": upn,
            "inPilot": (u["userId"] or "") in pilot_ids if pilot_ids else None,
            "status": status,
            "editions": eds,                    # [] = no Intune-enrolled device found for this user
            "autoDeployable": bool(eds) and all(e == "Pro" for e in eds),
            "needTotal": n_total, "needClaim": n_claim,
            "needClaimPct": round(100 * n_claim / n_total) if n_total else None,
            # Non-Edge browsers with no extension available - not a rollout task, a CA-scope task.
            "unfixableTotal": sum(b["total"] for f, b in u["browsers"].items() if _unfixable(f)),
            "unfixableBrowsers": sorted(f for f in u["browsers"] if _unfixable(f)),
            "lastClaim": last_claim or None,
            "lastNoClaim": last_no or None,
            "browsers": [
                {"browser": f, "total": b["total"], "claim": b["claim"],
                 "needsExtension": _needs_extension(f), "unfixable": _unfixable(f),
                 "devices": sorted(b["devices"])[:4],
                 "lastClaim": b["lastClaim"], "lastNoClaim": b["lastNoClaim"]}
                for f, b in sorted(u["browsers"].items(), key=lambda kv: -kv[1]["total"])
            ],
        })

    # A pilot member with NO browser sign-in in the window got no row at all, because rows are built
    # from sign-in data. That hid exactly the people who need chasing: the card is titled "who still
    # has to act" and it was silently omitting them, while the State Unknown KPI counted them without
    # naming anyone. Measured 2026-08-04: 12 pilot members, 9 rows.
    # Dedup on the UPN, not the userId: the row dicts never carried userId (it is only used to decide
    # inPilot), so matching on it silently matched nothing and every pilot member got a second,
    # empty row.
    seen_upns = {(r.get("user") or "").lower() for r in rows}
    for uid, upn in pilot.items():
        if (upn or "").lower() in seen_upns:
            continue
        eds = sorted(editions_by_user.get((upn or "").lower(), set()))
        rows.append({
            "user": upn, "inPilot": True, "status": "noData", "editions": eds,
            "autoDeployable": bool(eds) and all(e == "Pro" for e in eds),
            "needTotal": 0, "needClaim": 0, "needClaimPct": None,
            "unfixableTotal": 0, "unfixableBrowsers": [],
            "lastClaim": None, "lastNoClaim": None, "browsers": [],
        })

    # In-scope users first; unknown state ranks high because it is unfinished work, not good news.
    _rank = {"missing": 0, "partial": 1, "noData": 2, "ok": 3, "nativeOnly": 4}
    rows.sort(key=lambda r: (r["inPilot"] is False, _rank.get(r["status"], 9), -r["needTotal"]))

    # The per-browser array is diagnostic only - no panel renders it - and it was 33 KB of the 35 KB
    # this source contributes, 53 of 62 users being outside the pilot. Keep it where it is useful.
    for r in rows:
        if r["inPilot"] is False:
            r.pop("browsers", None)

    scoped = [r for r in rows if r["inPilot"] is not False]     # pilot members, or all if no group
    missing = [r for r in scoped if r["status"] == "missing"]
    partial = [r for r in scoped if r["status"] == "partial"]
    done = [r for r in scoped if r["status"] == "ok"]
    native = [r for r in scoped if r["status"] == "nativeOnly"]
    # A Pro-only user who is still missing it does NOT need the manual guide - but is not fine
    # either: it means the Intune profile has not landed. Split out rather than hidden.
    missing_auto = [r for r in missing if r["autoDeployable"]]
    missing_manual = [r for r in missing if not r["autoDeployable"]]

    # Pilot members with no browser sign-in at all in the window: invisible to this measurement, so
    # they must not be silently counted as ready.
    unseen = 0
    if pilot_ids:
        seen_ids = {(u.get("userId") or "") for u in per_user.values()}
        unseen = len([1 for pid in pilot_ids if pid not in seen_ids])

    ext_total = sum(v for f, v in fam_totals.items() if _needs_extension(f))
    ext_claim = sum(v for f, v in fam_claims.items() if _needs_extension(f))
    unfix_total = sum(v for f, v in fam_totals.items() if _unfixable(f))
    unfix_claim = sum(v for f, v in fam_claims.items() if _unfixable(f))
    unfix_browsers = sorted(f for f in fam_totals if _unfixable(f))

    findings = []
    if missing_manual:
        findings.append({
            "severity": "high",
            "text": f"{len(missing_manual)} in-scope user(s) have not produced a single claim-bearing "
                    f"non-Edge browser sign-in in {WINDOW_DAYS} days. If the device-filter CA is "
                    f"enforced now, these users are blocked in that browser. Send them "
                    f"docs/chrome-sso-extension-guide.md (install, restart Chrome, then SIGN OUT and "
                    f"back in - the claim is only recorded on a real trip to login.microsoftonline.com).",
        })
    if missing_auto:
        findings.append({
            "severity": "high",
            "text": f"{len(missing_auto)} user(s) whose devices are all Windows Pro still show no "
                    f"device claim. Pro is supposed to get the extension automatically from the "
                    f"Intune Chrome profile, so this points at the PROFILE, not the user - check the "
                    f"profile's assignment and the device's last check-in.",
        })
    if partial:
        findings.append({
            "severity": "med",
            "text": f"{len(partial)} user(s) have SOME claim-bearing sign-ins but their most recent "
                    f"one still had none - usually a second machine without the extension, or an "
                    f"incognito window (extensions are off in incognito by default). Check which "
                    f"device, do not re-install.",
        })
    if unseen:
        findings.append({
            "severity": "med",
            "text": f"{unseen} pilot member(s) had no browser sign-in in the window, so their "
                    f"extension state is UNKNOWN, not ready. Do not treat the rollout as complete "
                    f"until they appear here.",
        })
    if unfix_total and unfix_claim == 0:
        # In scope AND unfixable is the genuinely awkward case: the policy will evaluate these
        # sign-ins and no extension can make them pass. Out-of-scope browsers never reach here.
        findings.append({
            "severity": "med",
            "text": f"{unfix_total} IN-SCOPE sign-in(s) came from {', '.join(unfix_browsers)} - "
                    f"browsers with no SSO extension available, so they can never send a device "
                    f"claim, yet the device policies do evaluate this platform "
                    f"({', '.join(sorted(scope_platforms)) if scope_platforms else 'all platforms'}). "
                    f"Installing something will not fix these: either narrow the policy's platform "
                    f"condition or move the traffic to a managed app.",
        })
    home = sum(1 for m in managed if m.get("skuFamily") == "Home")
    if home:
        findings.append({
            "severity": "low",
            "text": f"{home} enrolled device(s) run Windows Home, where Intune ADMX ingestion is "
                    f"rejected (0x86000013) - the extension cannot be pushed there and manual "
                    f"install stays a permanent step in the device-onboarding SOP.",
        })

    return {
        "available": True,
        # Set when the shared sign-in pull fell back to an earlier one (throttle, network blip). The
        # numbers below are then real but not current, and saying so beats a confident stale figure.
        "signinData": signin_cache.stale_info(),
        "windowDays": WINDOW_DAYS,
        "extensionName": EXTENSION_NAME,
        "extensionId": EXTENSION_ID,
        "pilotGroup": PILOT_GROUP if pilot_ids else None,
        "pilotMemberCount": len(pilot_ids) or None,
        "truncated": len(signins) >= MAX_SIGNINS,
        # Platform scope of the device-dependent CA policies. null = they target every platform.
        "scopePlatforms": sorted(scope_platforms) if scope_platforms is not None else None,
        "scopePolicies": scope_policies,
        "outOfScopeSignins": sum(out_of_scope.values()),
        "outOfScopeByPlatform": dict(out_of_scope),
        "unknownPlatformSignins": unknown_platform,
        # Headline: coverage on browsers that need the add-on.
        "extBrowserSignins": ext_total,
        "extBrowserClaims": ext_claim,
        "extClaimPct": round(100 * ext_claim / ext_total) if ext_total else None,
        "unfixableSignins": unfix_total,
        "unfixableClaims": unfix_claim,
        "unfixableBrowsers": unfix_browsers,
        "byBrowser": [
            {"browser": f, "total": t, "claim": fam_claims.get(f, 0),
             "pct": round(100 * fam_claims.get(f, 0) / t) if t else 0,
             "needsExtension": _needs_extension(f), "unfixable": _unfixable(f)}
            for f, t in fam_totals.most_common()
        ],
        "readyCount": len(done),
        "missingCount": len(missing),
        "missingManualCount": len(missing_manual),
        "missingAutoCount": len(missing_auto),
        "partialCount": len(partial),
        "nativeOnlyCount": len(native),
        "unseenPilotCount": unseen,
        "users": rows,
        "findings": findings,
        "findingCount": len(findings),
        "highFindingCount": sum(1 for f in findings if f["severity"] == "high"),
    }
