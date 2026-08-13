"""Device identity coherence - does each enrolled device have ONE identity that CA can see?

Why this card exists
--------------------
Conditional Access evaluates the Entra device object that the SIGN-IN presents. Intune tracks a
device by its own `azureADDeviceId`. A device-filter tag is applied to whichever object an admin
picked. When those three disagree, device-based CA silently fails: the policy reads an object with
no tag and no compliance state, so a device that is enrolled, compliant AND tagged is still blocked.

Neither the Intune nor the Entra portal shows this disagreement. It was found the hard way on
2026-07-28: 4 of 11 enrolled devices had TWO Entra objects - a real `Workplace` registration that
the device actually authenticates with, and a `trustType`-null stub minted by Intune for an
MDM-only enrolment. Tagging by Intune's `azureADDeviceId` put the tag on the stub every time, so
the effective tag coverage was 6/11 while the portal showed 11/11 tagged.

The check is a three-way match per enrolled device:

    sign-in deviceId  ==  Intune azureADDeviceId  ==  the object carrying the tag

Read-only. `$select` keeps the sign-in pull light - only deviceDetail is needed here, unlike
risky_signins which must fetch the full record for the CA policy evaluations.
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

# Must match the value used by the Conditional Access device filter
# (e.g. rule: device.extensionAttribute1 -ne "Approved-Device").
TAG_ATTRIBUTE = "extensionAttribute1"
TAG_VALUE = os.environ.get("DEVICE_TAG_VALUE", "Approved-Device")


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


async def fetch() -> dict:
    devices = await _pages("/devices", {
        "$select": "id,deviceId,displayName,trustType,profileType,isCompliant,isManaged,"
                   "operatingSystem,registrationDateTime,extensionAttributes",
        "$top": "999"})
    managed = await _pages("/deviceManagement/managedDevices", {
        "$select": "id,azureADDeviceId,deviceName,userPrincipalName,complianceState,"
                   "isEncrypted,azureADRegistered,deviceEnrollmentType"})

    # Shared with risky_signins and browser_claims - one pull per collection cycle (signin_cache).
    # The cached records are full sign-in records rather than the $select this card used to make; it
    # only reads createdDateTime and deviceDetail, so the extra fields are ignored.
    signins, _ = await signin_cache.get_interactive()
    # Soft-deleted objects, so a re-registration can be told apart from a real fault: after a
    # device re-registers, Intune's azureADDeviceId can keep pointing at the OLD (now deleted)
    # object for a while. That is a stale field, not a broken identity - the live object still
    # receives Intune state. Without this the check raises a false alarm on every re-registration.
    try:
        deleted = await _pages("/directory/deletedItems/microsoft.graph.device",
                               {"$top": "999"}, cap=2000)
    except Exception:  # noqa: BLE001 - the check must still work without recycle-bin access
        deleted = []

    by_device_id = {(d.get("deviceId") or "").lower(): d for d in devices}
    deleted_ids = {(d.get("deviceId") or "").lower() for d in deleted}
    by_name = defaultdict(list)
    for d in devices:
        by_name[d.get("displayName")].append(d)
    tagged_ids = {
        (d.get("deviceId") or "").lower() for d in devices
        if ((d.get("extensionAttributes") or {}).get(TAG_ATTRIBUTE)) == TAG_VALUE
    }

    # Which deviceId does each device name actually present at sign-in?
    # Track the newest sign-in per id as well as the count: a device that re-registered recently
    # legitimately shows several deviceIds across the window, and picking by count alone breaks
    # on ties - it can select an id belonging to a since-deleted registration and report a
    # healthy device as orphaned.
    seen = defaultdict(Counter)
    latest = defaultdict(dict)      # name -> {deviceId: newest createdDateTime}
    # Which ACCOUNTS sign in from each device. Two work accounts present at enrolment time is what
    # produced the five stub devices, proved on 2026-08-10 by running the same remediation twice on
    # DEVICE-A four hours apart: with the second account still on the machine Company Portal
    # minted a stub (Add device = 1), with it removed the same procedure bound to the existing
    # object (Add device = 0).
    #
    # This is a DETECTOR, never a clearance. Measured 2026-08-10, the tenant cannot answer "how many
    # work accounts are connected to this device":
    #   - this window is WINDOW_DAYS, and heahr@ last signed in from the two affected machines on
    #     07-28, so it reports nothing for exactly the devices that had the problem
    #   - beta managedDevice.usersLoggedOn returns 1 for all 13 devices - it counts Windows
    #     interactive logons, and nobody logs into Windows as the shared account
    #   - registeredOwners/registeredUsers miss it too: adding a work account without ticking
    #     "allow my organization to manage my device" creates no Entra object at all
    # The authoritative check is the device's own "Access work or school" screen, which is why the
    # setup and remediation procedures make it a step. Absence here means nothing was SEEN.
    accounts = defaultdict(Counter)
    for r in signins:
        dd = r.get("deviceDetail") or {}
        name, did = dd.get("displayName"), (dd.get("deviceId") or "")
        upn = (r.get("userPrincipalName") or "").lower()
        if name and upn:
            accounts[name][upn] += 1
        if name and did:
            did = did.lower()
            seen[name][did] += 1
            ts = r.get("createdDateTime") or ""
            if ts > latest[name].get(did, ""):
                latest[name][did] = ts

    # ---- non-interactive top-up -------------------------------------------------------------
    # The pull above is INTERACTIVE ONLY, and that is a hole in exactly this check. A device claim
    # rides on token refreshes far more often than on interactive logons, so a device whose user has
    # not typed a password this week produces no interactive evidence and lands in "cannot verify"
    # while its claim is being delivered hundreds of times a day.
    #
    # Measured 2026-08-12 on DEVICE-B: 300+ sign-ins carrying claim aaaa1111 (Edge 151, Chrome 151,
    # Rich Client), last one 20:40, while this card reported "no sign-in carried a device claim in
    # 7d". Same blindness inflates "orphaned" after a re-registration: the newest INTERACTIVE
    # sign-in still names the old object even after the new one has taken over.
    #
    # Filling it is cheap because it is asked only for the devices the interactive pass could not
    # resolve - a handful, not the 12,500-record firehose (see risky_signins' cost note).
    unresolved = [m for m in managed
                  if m.get("deviceName") and not seen.get(m["deviceName"])
                  and m.get("userPrincipalName")]
    if unresolved:
        since = (datetime.now(timezone.utc) - timedelta(days=WINDOW_DAYS)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        for m in unresolved[:25]:          # cap: this is a top-up, not a second collection
            upn = m["userPrincipalName"].replace("'", "''")
            try:
                r = await graph_get(f"{_BETA}/auditLogs/signIns", params={
                    "$filter": f"userPrincipalName eq '{upn}' and createdDateTime ge {since} "
                               f"and signInEventTypes/any(t: t ne 'interactiveUser')",
                    "$top": 100})
            except Exception:  # noqa: BLE001 - a failed top-up must not blank the card
                continue
            for x in r.get("value") or []:
                dd = x.get("deviceDetail") or {}
                nm, did = dd.get("displayName"), (dd.get("deviceId") or "").lower()
                if not (nm and did):
                    continue
                seen[nm][did] += 1
                ts = x.get("createdDateTime") or ""
                if ts > latest[nm].get(did, ""):
                    latest[nm][did] = ts

    rows = []
    for m in managed:
        name = m.get("deviceName")
        intune_id = (m.get("azureADDeviceId") or "").lower()
        intune_obj = by_device_id.get(intune_id)
        ids = seen.get(name) or Counter()
        # Prefer an id that still exists in Entra; among candidates rank by newest sign-in then
        # by frequency. This makes the answer stable across a re-registration instead of
        # arbitrarily picking a dead id when counts tie.
        ts_of = latest.get(name) or {}
        live_ids = [i for i in ids if i in by_device_id]
        pool = live_ids or list(ids)
        signin_id = max(pool, key=lambda i: (ts_of.get(i, ""), ids[i])) if pool else None
        signin_obj = by_device_id.get(signin_id) if signin_id else None
        objs = by_name.get(name, [])

        # The object the DEVICE presents, which is what the tag has to sit on. A sign-in claim names
        # it directly; without one, fall back to the newest non-stub object of the same name.
        #
        # The fallback is not a guess. On 2026-08-06 the operator supplied `dsregcmd /status` for all
        # five split devices, and on 5/5 the local `WorkplaceDeviceId` is exactly that object - never
        # the stub Intune points at. Without the fallback a device with no device claim in the window
        # drops out of tagInertCount entirely, which is backwards: DEVICE-C is tagged, is NOT
        # managed, and produced no claim, so the one device that is both blocked and invisible was the
        # one missing from the count (measured 3, actual 4).
        real_objs = [o for o in objs if o.get("trustType") and o.get("registrationDateTime")]
        real_obj = (max(real_objs, key=lambda o: o.get("registrationDateTime") or "")
                    if real_objs else None)
        # A claimed id that no longer resolves must NOT win the selection. After a re-registration the
        # sign-in window necessarily still names the OLD object for up to WINDOW_DAYS, and judging a
        # ghost reports "orphaned / untagged / mismatched" on a device that is actually healthy - the
        # mirror of the stale-Intune-pointer case handled below. Fall through to the live object.
        # Seen on 2026-08-07 with DEVICE-D: re-registered at 20:03 onto bbbb2222 with Intune
        # following it, while the card still judged the deleted cccc3333 and raised three problems.
        signin_dead = bool(signin_id and signin_obj is None)
        use_signin = signin_obj is not None
        presented_obj = signin_obj if use_signin else real_obj
        presented_id = ((real_obj.get("deviceId") or "").lower() if (not use_signin and real_obj)
                        else (signin_id if use_signin else None))
        presented_source = "signin" if use_signin else ("entraReal" if real_obj else None)

        # What does Intune's azureADDeviceId actually point at? This is the crux, and the
        # difference between the two "mismatch" cases is the difference between a real fault and
        # a cosmetic one.
        if intune_obj is not None:
            intune_state = "liveReal" if intune_obj.get("trustType") else "liveStub"
        elif intune_id and intune_id in deleted_ids:
            intune_state = "deleted"
        elif intune_id:
            intune_state = "missing"
        else:
            intune_state = "none"

        # Is the object the device actually authenticates with a sound registration that is
        # receiving Intune state?
        #
        # This requires isManaged is True - not merely "populated". Measured 2026-08-04 across the 8
        # enrolled devices that produced a device claim in the window, the correlation with the actual
        # CA verdict is exact:
        #
        #     isManaged True (6 devices) -> CA-Pilot-DeviceAllowlist = reportOnlyNotApplied  (passes)
        #     isManaged None (2 devices) -> CA-Pilot-DeviceAllowlist = reportOnlyFailure     (blocked)
        #
        # and the two blocked objects BOTH carry the tag, exact value "Approved-Device", no whitespace.
        # So **the device filter does not honour extensionAttribute1 on an object that is not
        # Intune-managed** - tagging such a device changes nothing. The earlier test also accepted
        # `isCompliant is not None`, which let `isCompliant=False` count as healthy: DEVICE-E
        # was reported as a warning ("sound registration") while CA was failing it 19 times.
        signin_sound = bool(signin_obj and signin_obj.get("trustType")
                            and signin_obj.get("isManaged") is True)
        # Same test against the presented object, so the verdict survives a device with no claim.
        presented_sound = bool(presented_obj and presented_obj.get("trustType")
                               and presented_obj.get("isManaged") is True)
        presented_tagged = (presented_id in tagged_ids) if presented_id else None

        problems, warnings = [], []
        if intune_state == "liveStub":
            problems.append("Intune points at a phantom object (no trustType - an MDM-only stub, "
                            "which carries no compliance state and can never satisfy a device policy)")
        elif intune_state in ("deleted", "missing"):
            # A dangling azureADDeviceId is COSMETIC as long as the object the device actually
            # signs in with is a sound registration receiving Intune state: compliance is
            # reaching the right object, so device-based CA reads the right object too. Whether
            # the stale target sits in the recycle bin ("deleted") or is gone entirely
            # ("missing") makes no difference to that - so both are treated the same.
            #
            # Seen on 2026-07-30 with DEVICE-D: enrolment minted an id at 14:56, the real
            # Workplace registration appeared at 15:01, and Intune kept the first id. The live
            # object was compliant, managed and tagged, yet the card called it a problem.
            #
            # It is only a real fault when there is no sound object to fall back on, because then
            # nothing in Entra carries this device's compliance state.
            where = ("a deleted object" if intune_state == "deleted"
                     else "an object that no longer exists in Entra")
            if signin_sound:
                warnings.append(f"Intune's azureADDeviceId still points at {where} - stale field "
                                f"after a re-registration, not a broken identity")
            else:
                problems.append(f"Intune's azureADDeviceId points at {where}, and the object this "
                                f"device signs in with is not a sound registration either - "
                                f"nothing in Entra carries its compliance state")

        if signin_dead:
            # The claimed object is gone. Cosmetic if the device has since re-registered onto a sound
            # object that Intune is writing to - that is a re-registration in flight, and the old
            # sign-ins age out on their own. A real fault only when nothing sound replaced it.
            if presented_sound and intune_state == "liveReal" and presented_id == intune_id:
                warnings.append(
                    f"sign-in history still names a deleted object - normal for up to {WINDOW_DAYS}d "
                    f"after a re-registration; the object it registers with now is Intune-managed "
                    f"and Intune points at it")
            else:
                problems.append("the object it signs in with has been deleted from Entra (orphaned)")
            # A re-registration mints a NEW object and the tag does NOT carry over, so this is the
            # moment the tag goes missing. Measured on DEVICE-D 2026-08-07.
            if presented_obj is not None and not presented_tagged:
                problems.append(
                    f"re-registered onto a new object (`{presented_id}`) which is NOT tagged - the "
                    f"tag does not carry over from the old object. Apply "
                    f"extensionAttribute1 = Approved-Device to it (admin action - the tag is a deliberate grant)")
        elif signin_id and signin_id != intune_id:
            (warnings if signin_sound else problems).append(
                "the object it signs in with is not the one Intune's azureADDeviceId names"
                + (" (but that object is a sound registration carrying Intune state)"
                   if signin_sound else ""))
        if not signin_dead and signin_id and signin_id not in tagged_ids:
            problems.append("the object it signs in with is NOT tagged - device-filter policies will block it")
        elif not signin_dead and signin_id and not signin_sound:
            # Tagged but not Intune-managed. Worth its own line because the fix is completely
            # different from "go and tag it" and the card previously implied the device was fine.
            problems.append(
                "the object it signs in with carries the tag but is NOT Intune-managed "
                "(isManaged is not True), and the device filter does not honour the tag on such an "
                "object - measured, these sign-ins are failed by the policy anyway. Tagging cannot "
                "fix this; the device has to re-register so Intune state attaches to this object")
        if len(objs) > 1:
            # Two live objects for one device is the split-identity shape; two objects where one
            # is only a leftover is not, so only flag it when a live stub is involved.
            (problems if intune_state == "liveStub" else warnings).append(
                f"{len(objs)} Entra objects share this device name")
        if not ids:
            # Normally this is "cannot verify" - but Intune's azureADRegistered is readable right now
            # and, measured 2026-08-04 across all 12 enrolled devices, it separates the two shapes
            # exactly: True -> Intune points at the real Workplace object (7 devices), not-True ->
            # Intune points at a stub (5 devices, i.e. every phantom). Since a stub also means the tag
            # is ignored by the device filter (17.14), a device in that state should not sit in the
            # card as an unverifiable unknown - it is a predicted block.
            #
            # Prefer the DIRECT measurement over that correlation when there is a real object to read:
            # azureADRegistered separating the two shapes across 12 devices is a correlation, and
            # A past incident is a standing reminder of what happens when a correlation over a partial
            # sample gets promoted to a rule. The real object's own isManaged is the thing CA reads.
            if presented_obj is not None and not presented_sound:
                problems.append(
                    f"no sign-in carried a device claim in {WINDOW_DAYS}d, but the Entra object this "
                    f"device registers with (`{presented_id}`) "
                    f"{'carries the tag and ' if presented_tagged else ''}is NOT Intune-managed "
                    f"(isManaged={presented_obj.get('isManaged')!r}); the device filter ignores the tag "
                    f"on such an object, so expect this device to be blocked. Intune reports "
                    f"azureADRegistered={m.get('azureADRegistered')!r}. Re-register to fix")
            elif m.get("azureADRegistered") is not True:
                problems.append(
                    f"no sign-in carried a device claim in {WINDOW_DAYS}d, and Intune reports "
                    f"azureADRegistered={m.get('azureADRegistered')!r}. Every enrolled device measured "
                    f"in that state has its Intune pointer on a stub, and the device filter ignores the "
                    f"tag on such an object - expect this device to be blocked. Re-register to confirm")
            else:
                warnings.append(
                    f"no sign-in carried a device claim in {WINDOW_DAYS}d - cannot verify directly"
                    + (", though the object it registers with is Intune-managed and tagged"
                       if presented_sound and presented_tagged else ""))

        rows.append({
            "device": name,
            "user": m.get("userPrincipalName"),
            "ok": not problems,          # warnings alone do NOT make a device unhealthy
            "problems": problems,
            "warnings": warnings,
            "intuneTargetState": intune_state,   # liveReal | liveStub | deleted | missing | none
            "signInObjectSound": signin_sound,
            "entraObjectCount": len(objs),
            "complianceState": m.get("complianceState"),
            "isEncrypted": bool(m.get("isEncrypted")),
            "enrollmentType": m.get("deviceEnrollmentType"),
            "azureADRegistered": m.get("azureADRegistered"),
            "intuneDeviceId": intune_id or None,
            "intuneObjectTrustType": (intune_obj or {}).get("trustType"),
            "intuneObjectTagged": (intune_id in tagged_ids) if intune_id else None,
            "signInDeviceId": signin_id,
            "signInCount": ids.get(signin_id) if signin_id else 0,
            "signInDistinctIds": len(ids),
            # Accounts observed signing in FROM this device. Only a detector: the window is
            # WINDOW_DAYS, so an account added but not used recently will not appear here. The
            # authoritative check is the device's own "Access work or school" screen, which is why
            # the setup and remediation procedures make it a step rather than trusting this number.
            "accountsSeen": sorted(accounts.get(name, {})),
            "extraAccounts": sorted(
                u for u in accounts.get(name, {})
                if u != (m.get("userPrincipalName") or "").lower()),
            "signInTrustType": (signin_obj or {}).get("trustType"),
            "signInCompliant": (signin_obj or {}).get("isCompliant"),
            "signInManaged": (signin_obj or {}).get("isManaged"),
            "signInTagged": (signin_id in tagged_ids) if signin_id else None,
            "signInExistsInEntra": (signin_id in by_device_id) if signin_id else None,
            # The object the device presents, measured from a sign-in claim when there is one and from
            # the newest non-stub same-name object otherwise. This is what CA reads, so the KPIs use it.
            "presentedDeviceId": presented_id,
            "presentedSource": presented_source,      # signin | entraReal | None
            "presentedTagged": presented_tagged,
            "presentedManaged": (presented_obj or {}).get("isManaged"),
            "presentedSound": presented_sound,
            # The claimed id no longer resolves BUT the device now registers with a sound object that
            # Intune follows: a re-registration whose old sign-ins have not aged out yet, not a fault.
            "reregistered": bool(signin_dead and presented_sound
                                 and intune_state == "liveReal" and presented_id == intune_id),
        })

    rows.sort(key=lambda r: (r["ok"], not r["warnings"], r["device"] or ""))
    problem_rows = [r for r in rows if not r["ok"]]
    warn_rows = [r for r in rows if r["ok"] and r["warnings"]]

    tagged_objs = [d for d in devices
                   if ((d.get("extensionAttributes") or {}).get(TAG_ATTRIBUTE)) == TAG_VALUE]

    # Duplicate Entra objects for the SAME enrolled device - the shape that caused the mis-tagging
    enrolled_names = {m.get("deviceName") for m in managed}
    dupes = [
        {"device": n, "objects": len(v),
         "trustTypes": [o.get("trustType") or "(none)" for o in v]}
        for n, v in by_name.items() if n in enrolled_names and len(v) > 1
    ]

    return {
        "available": True,
        # See browser_claims: flags a fallback to an earlier sign-in pull.
        "signinData": signin_cache.stale_info(),
        "windowDays": WINDOW_DAYS,
        "tag": f"{TAG_ATTRIBUTE}={TAG_VALUE}",
        "enrolled": len(rows),
        "healthy": len(rows) - len(problem_rows),
        "problem": len(problem_rows),
        "warned": len(warn_rows),
        "devices": rows,
        "duplicateObjectDevices": dupes,
        "duplicateObjectCount": len(dupes),
        # Counts that make good action items / trend metrics.
        # phantomLinkCount counts only LIVE stubs - a stale pointer at an object that is gone is a
        # cosmetic field, not a device that CA cannot see.
        "phantomLinkCount": sum(1 for r in rows if r["intuneTargetState"] == "liveStub"),
        # Dangling pointers, whether the target is in the recycle bin or gone entirely.
        "staleIntunePointerCount": sum(
            1 for r in rows if r["intuneTargetState"] in ("deleted", "missing")),
        "signInMismatchCount": sum(
            1 for r in rows if r["signInDeviceId"] and r["signInDeviceId"] != r["intuneDeviceId"]),
        # Only genuine orphans - a device that re-registered onto a sound object Intune follows still
        # has the OLD id in the sign-in window for WINDOW_DAYS, and that is a stale record rather than
        # an orphan. Same treatment phantomLinkCount gives a stale-but-harmless pointer.
        "orphanSignInCount": sum(1 for r in rows
                                 if r["signInExistsInEntra"] is False and not r["reregistered"]),
        "untaggedSignInCount": sum(1 for r in rows if r["signInTagged"] is False),
        # Devices where a SECOND account was SEEN signing in. Deliberately not a KPI tile: a "0"
        # would read as "no device has a second account", which this cannot establish (see the
        # detector note above). The UI renders this only when it is non-empty, so it can raise a
        # hand but never issue a clean bill of health.
        "multiAccountDevices": sorted(
            ({"device": r["device"], "extra": r["extraAccounts"]} for r in rows
             if r["extraAccounts"]), key=lambda d: d["device"]),
        # Tagged, but the tag is inert because the object is not Intune-managed. These devices look
        # approved in the portal and are blocked in practice, which is the worst combination.
        #
        # Keyed on the PRESENTED object, not on the sign-in object: requiring a sign-in claim silently
        # excluded any device that produced none, and a device invisible in the sign-in log is more
        # likely to be broken, not less. That undercounted 4 as 3 (seen in production).
        "tagInertCount": sum(1 for r in rows
                             if r["presentedTagged"] is True and not r["presentedSound"]),
        # How many of those verdicts rest on the fallback rather than a sign-in claim.
        "tagInertFromFallback": sum(
            1 for r in rows if r["presentedTagged"] is True and not r["presentedSound"]
            and r["presentedSource"] == "entraReal"),
        # Tag inventory. The tag is an ADMIN GRANT by decision (a deliberate decision) - it must never appear
        # on anything the admin did not approve. Nothing in this tenant can write extensionAttributes
        # any more (the one app that could was disabled, 17.19), so these numbers should only ever
        # change when the admin changes them. An object tagged while NOT enrolled is the anomaly to
        # watch for: it means a tag was applied outside the process.
        "taggedObjectCount": len(tagged_objs),
        "taggedStubCount": sum(1 for d in tagged_objs if not d.get("trustType")),
        "taggedNotEnrolled": sorted(
            n for n in {d.get("displayName") for d in tagged_objs} if n not in enrolled_names),
        "enrolledNotTagged": sorted(
            n for n in enrolled_names
            if n and n not in {d.get("displayName") for d in tagged_objs}),
        # 257 Entra objects against 12 Intune-managed is the unmanaged-fleet number in one figure,
        # so it is displayed rather than merely collected.
        "totalEntraObjects": len(devices),
    }
