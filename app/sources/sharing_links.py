import asyncio
import os
from datetime import datetime, timedelta, timezone

from ..graph_client import graph_get
from ._i18n import finding

ANON_SITE_PATHS = [
    p.strip() for p in os.environ.get(
        "ANON_SITE_PATHS",
        "",
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
    def __init__(self):
        self.sem = asyncio.Semaphore(CONCURRENCY)
        self.truncated = False

    async def get(self, path, params=None):
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
            if it.get("shared"):
                acc.append((drive_id, it["id"], it.get("name"), it.get("webUrl")))
            if it.get("folder"):
                subs.append(it["id"])
        if subs:
            await asyncio.gather(*(self.items(drive_id, s, depth + 1, acc) for s in subs))


async def fetch() -> dict:
    scan = _Scan()
    sites = (await graph_get("/sites", params={"search": "*", "$top": 200})).get("value") or []
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
                    "type": link.get("type"),
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
        findings.append(finding(
            "high",
            en=f"{len(editable)} anonymous link(s) grant EDIT, not view - anyone holding the URL "
               f"can modify and download the file with no identity, so there is no sign-in "
               f"record and no Conditional Access evaluation. Downgrade to view unless editing "
               f"by an unauthenticated party is genuinely intended.",
            ko=f"익명 링크 {len(editable)}건이 보기가 아니라 **편집**을 허용합니다. URL 을 가진 "
               "사람은 누구든 신원 없이 파일을 고치고 내려받을 수 있어서 사인인 기록도 "
               "Conditional Access 평가도 남지 않습니다. 인증 없는 상대의 편집이 정말 의도한 "
               "것이 아니라면 보기로 낮추십시오."))
    if links and not editable:
        findings.append(finding(
            "low",
            en=f"All {len(links)} anonymous link(s) are view-only. If that is intended, this is "
               f"the safer shape and nothing needs doing. If someone reports that 'Can edit' has "
               f"disappeared from the sharing dialog, the cause is the tenant cap, which Graph "
               f"cannot read: Get-SPOTenant | Select FileAnonymousLinkType. View there means no "
               f"anonymous link can grant edit, whatever the site settings say.",
            ko=f"익명 링크 {len(links)}건이 전부 보기 전용입니다. 의도한 것이라면 더 안전한 "
               f"모양이고 할 일은 없습니다. 다만 공유 대화상자에서 'Can edit' 이 사라졌다는 "
               f"연락을 받으면 원인은 테넌트 상한이고, **Graph 로는 읽을 수 없습니다**: "
               f"Get-SPOTenant | Select FileAnonymousLinkType. 거기가 View 면 사이트 설정이 "
               f"무엇이든 익명 링크는 편집을 줄 수 없습니다."))

    if no_expiry:
        findings.append(finding(
            "high",
            en=f"{len(no_expiry)} anonymous link(s) have no expiry date - they stay live "
               f"indefinitely. Set AnonymousLinkExpirationInDays tenant-wide.",
            ko=f"익명 링크 {len(no_expiry)}건에 만료일이 없습니다 - 무기한 살아 있습니다. "
               "테넌트 전역으로 AnonymousLinkExpirationInDays 를 설정하십시오."))
    if expired:
        findings.append(finding(
            "low",
            en=f"{len(expired)} anonymous link(s) are past their expiry but still present on the "
               f"item. Expired links do not grant access, but they are clutter that hides the "
               f"live ones - remove them.",
            ko=f"만료됐는데 항목에 그대로 남아 있는 익명 링크 {len(expired)}건. 만료된 링크는 "
               "접근을 허용하지 않지만, 살아 있는 링크를 가려서 안 보이게 만듭니다 - 지우십시오."))
    if new_sites:
        findings.append(finding(
            "med",
            en=f"{len(new_sites)} site(s) created in the last {NEW_SITE_DAYS} days. A new site "
               f"inherits the tenant sharing default, which may be anonymous-capable - set each "
               f"one's external sharing level explicitly and add it to ANON_SITE_PATHS if it is "
               f"meant to allow anonymous links.",
            ko=f"최근 {NEW_SITE_DAYS}일 안에 만들어진 사이트 {len(new_sites)}곳. 새 사이트는 "
               "테넌트 공유 기본값을 물려받고, 그 기본값은 익명 허용일 수 있습니다 - 각 "
               "사이트의 외부 공유 수준을 명시적으로 정하고, 익명 링크를 허용할 사이트라면 "
               "ANON_SITE_PATHS 에 추가하십시오."))
    if missing:
        findings.append(finding(
            "med",
            en=f"{len(missing)} configured site path(s) no longer resolve ({', '.join(missing)}) "
               f"- ANON_SITE_PATHS is stale, so those sites are not being scanned.",
            ko=f"설정된 사이트 경로 {len(missing)}개가 더 이상 확인되지 않습니다"
               f"({', '.join(missing)}) - ANON_SITE_PATHS 가 낡았고, 그 사이트들은 스캔되지 "
               "않고 있습니다."))
    if scan.truncated:
        findings.append(finding(
            "med",
            en=f"The scan hit its bound ({MAX_ITEMS_PER_SITE} shared items or depth {MAX_DEPTH} "
               f"per site), so the link list is incomplete. Raise the limit or narrow the scope.",
            ko=f"스캔이 한도에 걸렸습니다(사이트당 공유 항목 {MAX_ITEMS_PER_SITE}개 또는 깊이 "
               f"{MAX_DEPTH}). 링크 목록이 완전하지 않으니 한도를 올리거나 범위를 좁히십시오."))

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
