"""Anonymous ("Anyone with the link") sharing links that actually exist.

Why this card exists
--------------------
`sharepoint_sharing` reports the tenant `sharingCapability`, which is only a **ceiling**. In this
tenant the ceiling is deliberately open (`externalUserAndGuestSharing`) so that two sites can be
shared with a partner who said they cannot authenticate, while the other ~32 sites are set to
`Disabled` per-site. That makes the tenant-level flag a permanent false positive on its own.

**Per-site `sharingCapability` does not exist in Microsoft Graph** - not a permission problem, the
property is simply absent from `/sites`. Only SPO PowerShell exposes it:

    Get-SPOSite -Limit All | ? { $_.SharingCapability -ne 'Disabled' } | ft Url,SharingCapability

So this source does the thing that *is* reachable and matters more: it enumerates the **actual
anonymous links** on the sites that are allowed to have them, and reports what each one grants.
Measured 2026-08-03: 5 anonymous links, **all of them `type=edit` with downloads allowed** - anyone
holding the URL can modify and download those files with no identity, no sign-in record and no CA
evaluation. That is a materially different posture from "view-only links to a partner", and no
portal surfaces it in one place.

Cost, and why the scan is scoped
--------------------------------
A tenant-wide crawl is not viable: walking all 40 sites (drives -> children -> per-item
`/permissions`) exceeded 600 s even at concurrency 8, because a permission call is needed for every
item flagged `shared`. Scoped to the two anonymous-capable sites it is ~15 s at the same
concurrency. Hence `ANON_SITE_PATHS`: the scan targets only sites that *can* hold anonymous links.

The blind spot that leaves - a site becoming anonymous-capable without anyone updating the list - is
covered separately and cheaply by `newSites`: any site created recently inherits the tenant default,
which here means anonymous-capable. That is one extra API call, not a crawl.

Needs `Sites.Read.All` (application). Added 2026-08-03; the app-only token is cached per process, so
the server must be restarted after granting it.
"""
import asyncio
import os
from datetime import datetime, timedelta, timezone

from ..graph_client import graph_get

# Sites permitted to hold anonymous links, as webUrl suffixes. Keep in step with the SPO PowerShell
# output above - Graph cannot derive this. Semicolon-separated override for other tenants.
ANON_SITE_PATHS = [
    p.strip() for p in os.environ.get(
        "ANON_SITE_PATHS",
        "/sites/HEA_HPTFileSharing;/sites/HEAPMNEXTERATEAM",
    ).split(";") if p.strip()
]

NEW_SITE_DAYS = int(os.environ.get("SHARING_NEW_SITE_DAYS", "30"))
MAX_DEPTH = 4
MAX_ITEMS_PER_SITE = 400
CONCURRENCY = 8


def _now():
    return datetime.now(timezone.utc)


def _parse(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


class _Scan:
    """Holds the semaphore and the per-run budget so the walk cannot run away."""

    def __init__(self):
        self.sem = asyncio.Semaphore(CONCURRENCY)
        self.truncated = False

    async def get(self, path, params=None):
        # The semaphore is released before any recursive gather() below, otherwise a deep tree
        # would hold every slot while waiting on its own children and deadlock.
        async with self.sem:
            try:
                return await graph_get(path, params=params)
            except Exception:
                return None

    async def items(self, drive_id, item_id, depth, acc):
        if depth > MAX_DEPTH or len(acc) >= MAX_ITEMS_PER_SITE:
            self.truncated = True
            return
        d = await self.get(f"/drives/{drive_id}/items/{item_id}/children",
                           params={"$select": "id,name,folder,shared,webUrl", "$top": 200})
        if not d:
            return
        subs = []
        for it in d.get("value") or []:
            if len(acc) >= MAX_ITEMS_PER_SITE:
                self.truncated = True
                break
            # 'shared' is only present when the item carries some sharing, so it lets us skip the
            # expensive per-item permission call on everything else.
            if it.get("shared"):
                acc.append((drive_id, it["id"], it.get("name"), it.get("webUrl")))
            if it.get("folder"):
                subs.append(it["id"])
        if subs:
            await asyncio.gather(*(self.items(drive_id, s, depth + 1, acc) for s in subs))


async def fetch() -> dict:
    scan = _Scan()
    sites = (await graph_get("/sites", params={"search": "*", "$top": 200})).get("value") or []
    # contentstorage/* are Loop/Designer containers created by the service, not real sites.
    real = [s for s in sites if "/contentstorage/" not in (s.get("webUrl") or "")]

    cutoff = _now() - timedelta(days=NEW_SITE_DAYS)
    new_sites = []
    for s in real:
        created = _parse(s.get("createdDateTime"))
        if created and created >= cutoff:
            new_sites.append({
                "name": s.get("displayName") or s.get("name"),
                "url": s.get("webUrl"),
                "created": s.get("createdDateTime"),
            })

    targets = [s for s in real
               if any((s.get("webUrl") or "").endswith(p) for p in ANON_SITE_PATHS)]
    missing = [p for p in ANON_SITE_PATHS
               if not any((s.get("webUrl") or "").endswith(p) for s in real)]

    async def per_site(site):
        shared_items = []
        drives = await scan.get(f"/sites/{site['id']}/drives")
        for d in (drives or {}).get("value") or []:
            root = await scan.get(f"/drives/{d['id']}/root", params={"$select": "id"})
            if root and root.get("id"):
                await scan.items(d["id"], root["id"], 0, shared_items)

        async def perms(drive_id, item_id):
            r = await scan.get(f"/drives/{drive_id}/items/{item_id}/permissions")
            return (r or {}).get("value") or []

        results = await asyncio.gather(*(perms(x[0], x[1]) for x in shared_items))
        return site, shared_items, results

    scanned = await asyncio.gather(*(per_site(s) for s in targets))

    links, org_count, user_count = [], 0, 0
    now = _now()
    for site, shared_items, results in scanned:
        for (_, _, name, web_url), plist in zip(shared_items, results):
            for p in plist:
                link = p.get("link") or {}
                scope = link.get("scope")
                if scope == "organization":
                    org_count += 1
                    continue
                if scope == "users":
                    user_count += 1
                    continue
                if scope != "anonymous":
                    continue
                exp = _parse(p.get("expirationDateTime"))
                links.append({
                    "site": site.get("displayName") or site.get("name"),
                    "item": name,
                    "url": web_url,
                    "type": link.get("type"),            # view | edit | embed
                    "editable": link.get("type") == "edit",
                    "preventsDownload": bool(link.get("preventsDownload")),
                    "expires": p.get("expirationDateTime"),
                    "expired": bool(exp and exp < now),
                    "daysLeft": (exp - now).days if exp else None,
                })

    links.sort(key=lambda x: (not x["editable"], x["daysLeft"] if x["daysLeft"] is not None else 9999))
    editable = [x for x in links if x["editable"]]
    expired = [x for x in links if x["expired"]]
    no_expiry = [x for x in links if not x["expires"]]

    findings = []
    if editable:
        findings.append({
            "severity": "high",
            "text": f"{len(editable)} anonymous link(s) grant EDIT, not view - anyone holding the URL "
                    f"can modify and download the file with no identity, so there is no sign-in "
                    f"record and no Conditional Access evaluation. Downgrade to view unless editing "
                    f"by an unauthenticated party is genuinely intended.",
        })
    if no_expiry:
        findings.append({
            "severity": "high",
            "text": f"{len(no_expiry)} anonymous link(s) have no expiry date - they stay live "
                    f"indefinitely. Set AnonymousLinkExpirationInDays tenant-wide.",
        })
    if expired:
        findings.append({
            "severity": "low",
            "text": f"{len(expired)} anonymous link(s) are past their expiry but still present on the "
                    f"item. Expired links do not grant access, but they are clutter that hides the "
                    f"live ones - remove them.",
        })
    if new_sites:
        findings.append({
            "severity": "med",
            "text": f"{len(new_sites)} site(s) created in the last {NEW_SITE_DAYS} days. A new site "
                    f"inherits the tenant sharing default, which here is anonymous-capable - set each "
                    f"one's external sharing level explicitly and add it to ANON_SITE_PATHS if it is "
                    f"meant to allow anonymous links.",
        })
    if missing:
        findings.append({
            "severity": "med",
            "text": f"{len(missing)} configured site path(s) no longer resolve ({', '.join(missing)}) "
                    f"- ANON_SITE_PATHS is stale, so those sites are not being scanned.",
        })
    if scan.truncated:
        findings.append({
            "severity": "med",
            "text": f"The scan hit its bound ({MAX_ITEMS_PER_SITE} shared items or depth {MAX_DEPTH} "
                    f"per site), so the link list is incomplete. Raise the limit or narrow the scope.",
        })

    return {
        "available": True,
        "note": "Per-site sharingCapability is not exposed by Microsoft Graph, so the scan targets a "
                "configured list of anonymous-capable sites. Verify the list with "
                "Get-SPOSite -Limit All | ft Url,SharingCapability",
        "siteCount": len(real),
        "scannedSites": [s.get("displayName") or s.get("name") for s in targets],
        "scannedSiteCount": len(targets),
        "configuredPaths": ANON_SITE_PATHS,
        "unresolvedPaths": missing,
        "newSiteDays": NEW_SITE_DAYS,
        "newSites": new_sites,
        "newSiteCount": len(new_sites),
        "links": links,
        "anonCount": len(links),
        "editableCount": len(editable),
        "expiredCount": len(expired),
        "noExpiryCount": len(no_expiry),
        "orgLinkCount": org_count,
        "userLinkCount": user_count,
        "truncated": scan.truncated,
        "findings": findings,
        "findingCount": len(findings),
        "highFindingCount": sum(1 for f in findings if f["severity"] == "high"),
    }
