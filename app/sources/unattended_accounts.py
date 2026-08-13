"""Unattended accounts vs the MFA policies that would lock them out.

Why this card exists
--------------------
A Teams Rooms console, a shared-device account and a phone-system virtual user all sign in with
NOBODY PRESENT. There is no one to approve an Authenticator push. So a Conditional Access policy
that requires MFA does not "prompt" such an account - it locks it out permanently, and the failure
looks like an ordinary sign-in error rather than a policy mistake.

This is not hypothetical. On 2026-07-30 the Security Defaults -> Conditional Access cutover
enabled `CA-Require-MFA-AllUsers` with `includeUsers: ["All"]`. Both Teams Rooms Pro accounts
started failing with AADSTS50076 seventy-eight seconds later and stayed down for about two hours,
taking conference-room Teams calling with them. Nothing in either portal warns about this, and the
pre-cutover report-only evidence did not show it either - see the sign-in log note below.

Two things make it easy to miss:

  1. The Entra CA blade shows the policy scope as "All users". It does not tell you that some of
     those users are appliances.
  2. The v1.0 `/auditLogs/signIns` collection returns INTERACTIVE sign-ins only. An unattended
     account never appears there, so a verification pass built on that endpoint is structurally
     blind to exactly the accounts most likely to break. Non-interactive sign-ins need
     `beta` + `signInEventTypes/any(t: t ne 'interactiveUser')`.

So the check is done on configuration, not on log evidence: find the unattended identities by
licence, then test them against the user scope of every enabled MFA-requiring policy. That gives
an answer BEFORE a cutover rather than after.

Identification is by licence SKU, which is what actually makes an account a room/appliance
identity. A display-name heuristic is applied as a weaker second net and reported separately, so a
person named "Conference Coordinator" is never silently treated as an appliance.

Read-only.
"""
from ..graph_client import graph_get

# SKU part numbers that mean "this identity belongs to a device, not a person".
ROOM_SKU_HINTS = (
    "MEETING_ROOM",            # Microsoft Teams Rooms Basic / legacy Meeting Room
    "TEAMS_ROOMS",             # Microsoft_Teams_Rooms_Pro / _Basic
    "MTR_",                    # Teams Rooms add-ons
    "SURFACEHUB",              # Surface Hub device accounts
    "TEAMS_SHARED_DEVICE",     # shared-device (frontline) accounts
    "PHONESYSTEM_VIRTUALUSER", # resource accounts for auto attendant / call queue
)
# Weaker signal - reported, but never treated as proof on its own.
NAME_HINTS = ("conference", "conf room", "boardroom", "board room", "huddle", "meeting room",
              "teams room", "surfacehub", "surface hub", "kiosk", "reception", "lobby")

# Grant controls that an unattended account cannot satisfy.
BLOCKING_CONTROLS = {"mfa", "block", "compliantDevice", "domainJoinedDevice",
                     "passwordChange", "approvedApplication", "compliantApplication"}

# Controls an unattended identity can NEVER satisfy, whatever the conditions: there is nobody to
# approve a prompt, and an appliance that is not enrolled cannot become compliant. In scope of one of
# these means locked out, full stop.
UNSATISFIABLE_CONTROLS = {"mfa", "compliantDevice", "domainJoinedDevice", "passwordChange",
                          "approvedApplication", "compliantApplication"}

# Client-app types that only legacy protocols match. A policy scoped to just these cannot affect a
# Teams Rooms console or any other appliance that authenticates with modern auth - a legacy-auth
# block policy is the standard shape here, and counting it as a lockout is a false alarm.
LEGACY_CLIENT_TYPES = {"exchangeActiveSync", "other"}


def _reach(controls: set, legacy_only: bool, conditions: dict) -> tuple[str, str]:
    """How does this policy actually affect an unattended account? -> (verdict, why)

    A plain `block` grant is NOT automatically a lockout - it is a deny rule, and whether it hurts
    depends entirely on what narrows it. The recommended control for a Teams Rooms account is exactly
    that shape: block everything OUTSIDE a trusted location, which permits the room at its desk and
    denies a stolen password from anywhere else. Counting that as "locked out" told the operator their
    own protective policy was an outage (seen 2026-08-03, right after enforcing it).

      cannotSatisfy      - requires something no unattended account can produce -> locked out
      unconditionalBlock - blocks with nothing narrowing it -> locked out
      conditionalBlock   - blocks only outside a location / platform / client set -> intended control
      legacyOnly         - scoped to legacy protocols an appliance never uses -> no effect

    Limitation worth knowing: platform or client narrowing is treated as conditional too, but unlike a
    location exclusion it does not permit normal operation - it only decides whether the appliance is
    in scope at all. A Windows-only block still locks out a Windows appliance. Deciding that needs the
    appliance's platform, which the licence does not tell us, so the reason string is surfaced and the
    judgement is left to the reader.
    """
    unsatisfiable = controls & UNSATISFIABLE_CONTROLS
    if unsatisfiable:
        return "cannotSatisfy", f"requires {', '.join(sorted(unsatisfiable))}, which needs a person"
    if legacy_only:
        return "legacyOnly", "scoped to legacy protocols only; appliances use modern auth"
    if "block" not in controls:
        return "conditionalBlock", "no blocking grant control"

    loc = conditions.get("locations") or {}
    excl_loc = [x for x in (loc.get("excludeLocations") or []) if x]
    incl_loc = [x for x in (loc.get("includeLocations") or []) if x]
    plat = conditions.get("platforms") or {}
    incl_plat = [x for x in (plat.get("includePlatforms") or []) if x and x != "all"]
    client = set(conditions.get("clientAppTypes") or [])

    narrowing = []
    if excl_loc:
        narrowing.append(f"only outside {', '.join(excl_loc)}")
    elif incl_loc and "All" not in incl_loc:
        narrowing.append("only from specific locations")
    if incl_plat:
        narrowing.append(f"platforms {', '.join(incl_plat)}")
    if client and client != {"all"}:
        narrowing.append(f"clients {', '.join(sorted(client))}")

    if narrowing:
        return "conditionalBlock", "; ".join(narrowing)
    return "unconditionalBlock", "blocks with no narrowing condition"


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
    except Exception:  # noqa: BLE001 - a group we cannot read must not sink the whole card
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
            continue                        # a disabled account cannot be locked out
        lic = {(l or {}).get("skuId") for l in (u.get("assignedLicenses") or [])}
        by_lic = sorted(sku_name.get(s, s) for s in (lic & room_sku_ids))
        blob = f"{u.get('displayName') or ''} {u.get('userPrincipalName') or ''}".lower()
        by_name = [h for h in NAME_HINTS if h in blob]
        if by_lic or by_name:
            candidates.append({
                "id": u["id"],
                "upn": u.get("userPrincipalName"),
                "name": u.get("displayName"),
                # licence is proof; a name match alone is only a suggestion
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
            continue                        # e.g. a session-control-only policy cannot lock anyone out

        # A policy scoped only to legacy client types cannot reach a modern-auth appliance. Without
        # this, CA-Block-LegacyAuth reads as "blocks both conference rooms", which is wrong: the
        # rooms authenticate with modern auth and were never touched by it.
        client_types = set((p.get("conditions") or {}).get("clientAppTypes") or [])
        legacy_only = bool(client_types) and client_types <= LEGACY_CLIENT_TYPES
        reach, reach_why = _reach(controls, legacy_only, p.get("conditions") or {})
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
            "locksOut": locks_out,
            "exposed": len(exposed) if locks_out else 0,
        })
        for c in exposed:
            findings.append({
                "upn": c["upn"], "name": c["name"], "evidence": c["evidence"],
                "skus": c["skus"], "policy": p.get("displayName"), "policyId": p.get("id"),
                "state": state, "enforced": state == "enabled", "controls": hostile,
                "legacyOnly": legacy_only, "clientAppTypes": sorted(client_types),
                "reach": reach, "reachWhy": reach_why, "locksOut": locks_out,
            })

    # Only licence-proven appliances inside a policy that can actually reach them count towards the
    # alert. A name-only match is surfaced in the table but must not raise an alarm about a person
    # who happens to be called "Conference ...", and a legacy-only policy cannot touch an appliance
    # that uses modern auth.
    hard = [f for f in findings
            if f["evidence"] == "licence" and f["enforced"] and f["locksOut"]]
    exposed_upns = {f["upn"] for f in hard}
    # Appliances sitting inside a deliberately narrowed block (the recommended shape for a room
    # account) are reported separately: that is the control working, not an outage.
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
        # Headline: licence-proven appliances inside an ENFORCED blocking policy = locked out now.
        "exposedCount": len(exposed_upns),
        "exposedUsers": sorted(exposed_upns),
        "reportOnlyExposedCount": len({f["upn"] for f in findings
                                       if f["evidence"] == "licence" and not f["enforced"]
                                       and f["locksOut"]}),
        # Protected by a conditional block rather than locked out by it.
        "conditionallyGatedCount": len(gated_upns),
        "conditionallyGatedUsers": sorted(gated_upns),
        "policies": checked_policies,
        "policyCount": len(checked_policies),
        "roomSkus": sorted({sku_name[s] for s in room_sku_ids}),
    }
