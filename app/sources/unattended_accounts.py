from ..graph_client import graph_get

ROOM_SKU_HINTS = (
    "MEETING_ROOM",
    "TEAMS_ROOMS",
    "MTR_",
    "SURFACEHUB",
    "TEAMS_SHARED_DEVICE",
    "PHONESYSTEM_VIRTUALUSER",
)
NAME_HINTS = ("conference", "conf room", "boardroom", "board room", "huddle", "meeting room",
              "teams room", "surfacehub", "surface hub", "kiosk", "reception", "lobby")

BLOCKING_CONTROLS = {"mfa", "block", "compliantDevice", "domainJoinedDevice",
                     "passwordChange", "approvedApplication", "compliantApplication"}

UNSATISFIABLE_CONTROLS = {"mfa", "compliantDevice", "domainJoinedDevice", "passwordChange",
                          "approvedApplication", "compliantApplication"}

LEGACY_CLIENT_TYPES = {"exchangeActiveSync", "other"}


def _reach(controls: set, legacy_only: bool, conditions: dict) -> tuple[str, str]:
    unsatisfiable = controls & UNSATISFIABLE_CONTROLS
    if unsatisfiable:
        _c = ", ".join(sorted(unsatisfiable))
        return ("cannotSatisfy", f"requires {_c}, which needs a person",
                f"{_c} 를 요구하는데, 그건 사람이 있어야 합니다")
    if legacy_only:
        return ("legacyOnly", "scoped to legacy protocols only; appliances use modern auth",
                "레거시 프로토콜에만 걸려 있고, 장비는 최신 인증을 씁니다")
    if "block" not in controls:
        return ("conditionalBlock", "no blocking grant control", "차단하는 부여 조건이 없습니다")

    loc = conditions.get("locations") or {}
    excl_loc = [x for x in (loc.get("excludeLocations") or []) if x]
    incl_loc = [x for x in (loc.get("includeLocations") or []) if x]
    plat = conditions.get("platforms") or {}
    incl_plat = [x for x in (plat.get("includePlatforms") or []) if x and x != "all"]
    client = set(conditions.get("clientAppTypes") or [])

    narrowing, narrowing_ko = [], []
    if excl_loc:
        _l = ", ".join(excl_loc)
        narrowing.append(f"only outside {_l}")
        narrowing_ko.append(f"{_l} 밖에서만")
    elif incl_loc and "All" not in incl_loc:
        narrowing.append("only from specific locations")
        narrowing_ko.append("특정 위치에서만")
    if incl_plat:
        _p = ", ".join(incl_plat)
        narrowing.append(f"platforms {_p}")
        narrowing_ko.append(f"플랫폼 {_p}")
    if client and client != {"all"}:
        _cl = ", ".join(sorted(client))
        narrowing.append(f"clients {_cl}")
        narrowing_ko.append(f"클라이언트 {_cl}")

    if narrowing:
        return "conditionalBlock", "; ".join(narrowing), "; ".join(narrowing_ko)
    return ("unconditionalBlock", "blocks with no narrowing condition",
            "좁히는 조건 없이 그냥 막습니다")


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


async def _group_members(gid: str) -> set[str]:
    try:
        ms = await _pages(f"/groups/{gid}/transitiveMembers", {"$select": "id", "$top": "999"})
        return {m.get("id") for m in ms if m.get("id")}
    except Exception:
        return set()


async def fetch() -> dict:
    skus = await _pages("/subscribedSkus")
    sku_name = {s.get("skuId"): (s.get("skuPartNumber") or "") for s in skus}
    room_sku_ids = {sid for sid, part in sku_name.items()
                    if any(h.lower() in part.lower() for h in ROOM_SKU_HINTS)}

    users = await _pages("/users", {
        "$select": "id,userPrincipalName,displayName,accountEnabled,userType,assignedLicenses",
        "$top": "999"})

    candidates = []
    for u in users:
        if not u.get("accountEnabled"):
            continue
        lic = {(l or {}).get("skuId") for l in (u.get("assignedLicenses") or [])}
        by_lic = sorted(sku_name.get(s, s) for s in (lic & room_sku_ids))
        blob = f"{u.get('displayName') or ''} {u.get('userPrincipalName') or ''}".lower()
        by_name = [h for h in NAME_HINTS if h in blob]
        if by_lic or by_name:
            candidates.append({
                "id": u["id"],
                "upn": u.get("userPrincipalName"),
                "name": u.get("displayName"),
                "evidence": "licence" if by_lic else "name",
                "skus": by_lic,
                "nameHints": by_name,
            })

    policies = await _pages("/identity/conditionalAccess/policies")
    group_cache: dict[str, set[str]] = {}

    async def members_of(gid):
        if gid not in group_cache:
            group_cache[gid] = await _group_members(gid)
        return group_cache[gid]

    findings, checked_policies = [], []
    for p in policies:
        state = p.get("state")
        if state not in ("enabled", "enabledForReportingButNotEnforced"):
            continue
        controls = set((p.get("grantControls") or {}).get("builtInControls") or [])
        hostile = sorted(controls & BLOCKING_CONTROLS)
        if not hostile:
            continue

        client_types = set((p.get("conditions") or {}).get("clientAppTypes") or [])
        legacy_only = bool(client_types) and client_types <= LEGACY_CLIENT_TYPES
        reach, reach_why, reach_why_ko = _reach(controls, legacy_only, p.get("conditions") or {})
        locks_out = reach in ("cannotSatisfy", "unconditionalBlock")

        uc = (p.get("conditions") or {}).get("users") or {}
        inc_u, exc_u = set(uc.get("includeUsers") or []), set(uc.get("excludeUsers") or [])
        all_users = "All" in inc_u
        inc_gm, exc_gm = set(), set()
        for g in (uc.get("includeGroups") or []):
            inc_gm |= await members_of(g)
        for g in (uc.get("excludeGroups") or []):
            exc_gm |= await members_of(g)

        exposed = []
        for c in candidates:
            in_scope = all_users or c["id"] in inc_u or c["id"] in inc_gm
            excluded = c["id"] in exc_u or c["id"] in exc_gm
            if in_scope and not excluded:
                exposed.append(c)

        checked_policies.append({
            "policy": p.get("displayName"),
            "id": p.get("id"),
            "state": state,
            "enforced": state == "enabled",
            "controls": hostile,
            "allUsers": all_users,
            "legacyOnly": legacy_only,
            "clientAppTypes": sorted(client_types),
            "reach": reach,
            "reachWhy": reach_why,
            "reachWhyKo": reach_why_ko,
            "locksOut": locks_out,
            "exposed": len(exposed) if locks_out else 0,
        })
        for c in exposed:
            findings.append({
                "upn": c["upn"], "name": c["name"], "evidence": c["evidence"],
                "skus": c["skus"], "policy": p.get("displayName"), "policyId": p.get("id"),
                "state": state, "enforced": state == "enabled", "controls": hostile,
                "legacyOnly": legacy_only, "clientAppTypes": sorted(client_types),
                "reach": reach, "reachWhy": reach_why, "reachWhyKo": reach_why_ko,
                "locksOut": locks_out,
            })

    hard = [f for f in findings
            if f["evidence"] == "licence" and f["enforced"] and f["locksOut"]]
    exposed_upns = {f["upn"] for f in hard}
    gated_upns = {f["upn"] for f in findings
                  if f["evidence"] == "licence" and f["enforced"]
                  and f["reach"] == "conditionalBlock"} - exposed_upns
    return {
        "available": True,
        "candidates": candidates,
        "candidateCount": len(candidates),
        "licenceProvenCount": sum(1 for c in candidates if c["evidence"] == "licence"),
        "nameOnlyCount": sum(1 for c in candidates if c["evidence"] == "name"),
        "findings": findings,
        "exposedCount": len(exposed_upns),
        "exposedUsers": sorted(exposed_upns),
        "reportOnlyExposedCount": len({f["upn"] for f in findings
                                       if f["evidence"] == "licence" and not f["enforced"]
                                       and f["locksOut"]}),
        "conditionallyGatedCount": len(gated_upns),
        "conditionallyGatedUsers": sorted(gated_upns),
        "policies": checked_policies,
        "policyCount": len(checked_policies),
        "roomSkus": sorted({sku_name[s] for s in room_sku_ids}),
    }
