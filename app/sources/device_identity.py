import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from .. import signin_cache
from ..graph_client import graph_get

_BETA = "https://graph.microsoft.com/beta"
WINDOW_DAYS = 7
MAX_SIGNINS = 8000
PAGE_SIZE = 1000

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

    signins, _ = await signin_cache.get_interactive()
    try:
        deleted = await _pages("/directory/deletedItems/microsoft.graph.device",
                               {"$top": "999"}, cap=2000)
    except Exception:
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

    seen = defaultdict(Counter)
    latest = defaultdict(dict)
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

    unresolved = [m for m in managed
                  if m.get("deviceName") and not seen.get(m["deviceName"])
                  and m.get("userPrincipalName")]
    if unresolved:
        since = (datetime.now(timezone.utc) - timedelta(days=WINDOW_DAYS)).strftime(
            "%Y-%m-%dT%H:%M:%SZ")
        for m in unresolved[:25]:
            upn = m["userPrincipalName"].replace("'", "''")
            try:
                r = await graph_get(f"{_BETA}/auditLogs/signIns", params={
                    "$filter": f"userPrincipalName eq '{upn}' and createdDateTime ge {since} "
                               f"and signInEventTypes/any(t: t ne 'interactiveUser')",
                    "$top": 100})
            except Exception:
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
        ts_of = latest.get(name) or {}
        live_ids = [i for i in ids if i in by_device_id]
        pool = live_ids or list(ids)
        signin_id = max(pool, key=lambda i: (ts_of.get(i, ""), ids[i])) if pool else None
        signin_obj = by_device_id.get(signin_id) if signin_id else None
        objs = by_name.get(name, [])

        real_objs = [o for o in objs if o.get("trustType") and o.get("registrationDateTime")]
        real_obj = (max(real_objs, key=lambda o: o.get("registrationDateTime") or "")
                    if real_objs else None)
        signin_dead = bool(signin_id and signin_obj is None)
        use_signin = signin_obj is not None
        presented_obj = signin_obj if use_signin else real_obj
        presented_id = ((real_obj.get("deviceId") or "").lower() if (not use_signin and real_obj)
                        else (signin_id if use_signin else None))
        presented_source = "signin" if use_signin else ("entraReal" if real_obj else None)

        if intune_obj is not None:
            intune_state = "liveReal" if intune_obj.get("trustType") else "liveStub"
        elif intune_id and intune_id in deleted_ids:
            intune_state = "deleted"
        elif intune_id:
            intune_state = "missing"
        else:
            intune_state = "none"

        signin_sound = bool(signin_obj and signin_obj.get("trustType")
                            and signin_obj.get("isManaged") is True)
        presented_sound = bool(presented_obj and presented_obj.get("trustType")
                               and presented_obj.get("isManaged") is True)
        presented_tagged = (presented_id in tagged_ids) if presented_id else None

        problems, warnings = [], []
        if intune_state == "liveStub":
            problems.append("Intune points at a phantom object (no trustType - an MDM-only stub, "
                            "which carries no compliance state and can never satisfy a device policy)")
        elif intune_state in ("deleted", "missing"):
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
            if presented_sound and intune_state == "liveReal" and presented_id == intune_id:
                warnings.append(
                    f"sign-in history still names a deleted object - normal for up to {WINDOW_DAYS}d "
                    f"after a re-registration; the object it registers with now is Intune-managed "
                    f"and Intune points at it")
            else:
                problems.append("the object it signs in with has been deleted from Entra (orphaned)")
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
            problems.append(
                "the object it signs in with carries the tag but is NOT Intune-managed "
                "(isManaged is not True), and the device filter does not honour the tag on such an "
                "object - in practice, these sign-ins are failed by the policy anyway. Tagging cannot "
                "fix this; the device has to re-register so Intune state attaches to this object")
        if len(objs) > 1:
            (problems if intune_state == "liveStub" else warnings).append(
                f"{len(objs)} Entra objects share this device name")
        if not ids:
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
                    f"azureADRegistered={m.get('azureADRegistered')!r}. An enrolled device in that "
                    f"state typically has its Intune pointer on a stub, and the device filter ignores the "
                    f"tag on such an object - expect this device to be blocked. Re-register to confirm")
            else:
                warnings.append(
                    f"no sign-in carried a device claim in {WINDOW_DAYS}d - cannot verify directly"
                    + (", though the object it registers with is Intune-managed and tagged"
                       if presented_sound and presented_tagged else ""))

        presented_compliant = (signin_obj or {}).get("isCompliant") if signin_obj else None
        if (m.get("complianceState") == "compliant" and signin_obj
                and presented_compliant is not True):
            warnings.append(
                f"Intune says compliant but the object CA reads has isCompliant="
                f"{presented_compliant!r}. CA reads the second one, so this device fails "
                f"'require compliant device' (53000 DeviceNotCompliant) while every Intune view "
                f"shows it green. Usual cause: a re-registration with no check-in since - one "
                f"Company Portal sync fixes it. Do NOT re-register again on the strength of this")

        rows.append({
            "device": name,
            "user": m.get("userPrincipalName"),
            "ok": not problems,
            "compliancePublishedToCa": presented_compliant,
            "complianceSplit": (m.get("complianceState") == "compliant"
                                and signin_obj is not None
                                and presented_compliant is not True),
            "problems": problems,
            "warnings": warnings,
            "intuneTargetState": intune_state,
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
            "accountsSeen": sorted(accounts.get(name, {})),
            "extraAccounts": sorted(
                u for u in accounts.get(name, {})
                if u != (m.get("userPrincipalName") or "").lower()),
            "signInTrustType": (signin_obj or {}).get("trustType"),
            "signInCompliant": (signin_obj or {}).get("isCompliant"),
            "signInManaged": (signin_obj or {}).get("isManaged"),
            "signInTagged": (signin_id in tagged_ids) if signin_id else None,
            "signInExistsInEntra": (signin_id in by_device_id) if signin_id else None,
            "presentedDeviceId": presented_id,
            "presentedSource": presented_source,
            "presentedTagged": presented_tagged,
            "presentedManaged": (presented_obj or {}).get("isManaged"),
            "presentedSound": presented_sound,
            "reregistered": bool(signin_dead and presented_sound
                                 and intune_state == "liveReal" and presented_id == intune_id),
        })

    rows.sort(key=lambda r: (r["ok"], not r["warnings"], r["device"] or ""))
    problem_rows = [r for r in rows if not r["ok"]]
    warn_rows = [r for r in rows if r["ok"] and r["warnings"]]

    tagged_objs = [d for d in devices
                   if ((d.get("extensionAttributes") or {}).get(TAG_ATTRIBUTE)) == TAG_VALUE]

    enrolled_names = {m.get("deviceName") for m in managed}
    dupes = [
        {"device": n, "objects": len(v),
         "trustTypes": [o.get("trustType") or "(none)" for o in v]}
        for n, v in by_name.items() if n in enrolled_names and len(v) > 1
    ]

    return {
        "available": True,
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
        "phantomLinkCount": sum(1 for r in rows if r["intuneTargetState"] == "liveStub"),
        "staleIntunePointerCount": sum(
            1 for r in rows if r["intuneTargetState"] in ("deleted", "missing")),
        "signInMismatchCount": sum(
            1 for r in rows if r["signInDeviceId"] and r["signInDeviceId"] != r["intuneDeviceId"]),
        "orphanSignInCount": sum(1 for r in rows
                                 if r["signInExistsInEntra"] is False and not r["reregistered"]),
        "untaggedSignInCount": sum(1 for r in rows if r["signInTagged"] is False),
        "multiAccountDevices": sorted(
            ({"device": r["device"], "extra": r["extraAccounts"]} for r in rows
             if r["extraAccounts"]), key=lambda d: d["device"]),
        "tagInertCount": sum(1 for r in rows
                             if r["presentedTagged"] is True and not r["presentedSound"]),
        "tagInertFromFallback": sum(
            1 for r in rows if r["presentedTagged"] is True and not r["presentedSound"]
            and r["presentedSource"] == "entraReal"),
        "taggedObjectCount": len(tagged_objs),
        "taggedStubCount": sum(1 for d in tagged_objs if not d.get("trustType")),
        "taggedNotEnrolled": sorted(
            n for n in {d.get("displayName") for d in tagged_objs} if n not in enrolled_names),
        "enrolledNotTagged": sorted(
            n for n in enrolled_names
            if n and n not in {d.get("displayName") for d in tagged_objs}),
        "totalEntraObjects": len(devices),
    }
