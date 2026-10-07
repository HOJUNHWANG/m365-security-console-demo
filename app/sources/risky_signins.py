import asyncio
import ipaddress
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

import httpx

from .. import signin_cache
from ..config import settings
from ..graph_client import graph_get

WINDOW_DAYS = 7
MAX_RECORDS = 8000
PAGE_SIZE = int(os.environ.get("SIGNIN_PAGE_SIZE", "250"))
MULTI_IP_THRESHOLD = 3

_BETA = "https://graph.microsoft.com/beta"
_NI_PREDICATE = "signInEventTypes/any(t: t ne 'interactiveUser')"
NI_WINDOW_HOURS = 12
NI_MAX_RECORDS = 2000
NI_MAX_PROBE = 25
NI_PROBE_CONCURRENCY = 6
PROBE_TTL_MIN = float(os.environ.get("SIGNIN_PROBE_TTL_MIN", "60"))
_probe_cache: dict[str, tuple[datetime, str | None]] = {}
NI_RECENT_MINUTES = 30

_LEGACY_CLIENTS = {
    "Exchange ActiveSync", "IMAP4", "POP3", "SMTP", "Authenticated SMTP",
    "MAPI Over HTTP", "Offline Address Book", "Outlook Anywhere (RPC over HTTP)",
    "Exchange Web Services", "AutoDiscover", "Exchange Online PowerShell",
    "Reporting Web Services", "Other clients",
}

_RESULTS_REPORT_ONLY = {
    "reportOnlySuccess", "reportOnlyFailure", "reportOnlyInterrupted", "reportOnlyNotApplied",
}
_RESULTS_ENFORCED = {"success", "failure", "notApplied", "notEnabled"}

_RESULTS_IMPACT = {"failure", "reportOnlyFailure", "reportOnlyInterrupted"}

_RESULT_LABELS = {
    "success": "Satisfied", "failure": "Blocked", "notApplied": "Not applied",
    "notEnabled": "Policy off", "reportOnlySuccess": "Would pass",
    "reportOnlyFailure": "Would be blocked", "reportOnlyInterrupted": "Would be interrupted",
    "reportOnlyNotApplied": "Would not apply",
}

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


_ERR_KO = {
    50053: "계정 잠김 (시도 횟수 초과)",
    50055: "비밀번호 만료",
    50057: "계정 비활성",
    50074: "MFA 필요 — 완료되지 않음",
    50076: "Conditional Access 가 MFA 를 요구",
    50079: "MFA 등록 필요",
    50097: "기기 인증 필요 (CA)",
    50126: "아이디 또는 비밀번호가 틀림",
    50140: "중단됨 — '로그인 상태 유지'",
    50144: "AD 비밀번호 만료",
    53000: "차단 — 기기가 준수하지 않음 (CA)",
    53001: "차단 — 기기가 등록/조인되지 않음 (CA)",
    53002: "차단 — 승인되지 않은 앱 (CA)",
    53003: "Conditional Access 정책으로 차단",
    53004: "진행하려면 MFA 등록 필요",
    65001: "앱 동의 필요 / 동의되지 않음",
    90094: "관리자 동의 필요",
    500121: "MFA 인증 실패 또는 시간 초과",
    530002: "위험 기반 Conditional Access 로 차단",
    700016: "테넌트에 없는 응용 프로그램",
}


def _decode(code, reason: str | None) -> tuple[str, str]:
    label = _ERR.get(code)
    if label:
        return label, _ERR_KO.get(code, label)
    reason = (reason or "").strip()
    out = reason or (f"error {code}" if code not in (None, 0) else "")
    return out, out


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ua_family(browser: str | None, os_: str | None) -> str:
    def fam(v):
        parts = [p for p in (v or "").split() if not p[:1].isdigit()]
        return " ".join(parts).lower()
    return f"{fam(browser)}|{fam(os_)}".strip("|")


def _mins_between(a: str, b: str) -> float | None:
    try:
        ta = datetime.fromisoformat((a or "").replace("Z", "+00:00"))
        tb = datetime.fromisoformat((b or "").replace("Z", "+00:00"))
    except ValueError:
        return None
    return abs((tb - ta).total_seconds()) / 60


def _iso(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


async def _fetch_signins() -> tuple[list, bool]:
    return await signin_cache.get_interactive()


async def _fetch_noninteractive() -> tuple[list, bool]:
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
    for row in (data.get("value") or []):
        if (row.get("userId") or "").lower() == (user_id or "").lower():
            result = row.get("createdDateTime") or None
            break
    _probe_cache[user_id] = (_now(), result)
    _prune_probe_cache()
    return result


def _prune_probe_cache() -> None:
    if len(_probe_cache) <= NI_MAX_PROBE * 4:
        return
    now = _now()
    for uid in [u for u, (at, _) in _probe_cache.items()
                if (now - at).total_seconds() / 60 >= PROBE_TTL_MIN]:
        _probe_cache.pop(uid, None)


def _actor(r: dict) -> tuple[str, str]:
    upn = (r.get("userPrincipalName") or "").strip().lower()
    if upn and "@" in upn:
        return upn, "user"
    spn = (r.get("servicePrincipalName") or "").strip()
    if spn:
        return spn, "servicePrincipal"
    disp = (r.get("userDisplayName") or "").strip()
    return (disp or "(unresolved)"), ("servicePrincipal" if r.get("servicePrincipalId") else "user")


async def _noninteractive_pass(interactive: list) -> dict:
    try:
        records, truncated = await _fetch_noninteractive()
    except Exception as e:
        return {"available": False,
                "reason": f"non-interactive query failed: {e}",
                "windowHours": NI_WINDOW_HOURS}

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

    suspects = [acc for acc in agg.values()
                if last_interactive_ok.get(acc["user"], "") <= acc["lastBlock"]]
    suspects.sort(key=lambda acc: -acc["blocks"])
    to_probe, probed = [], 0
    for acc in suspects:
        if not acc.get("userId"):
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
                except Exception as exc:
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
            verdict = "stuck"
        elif acc["blocksRecent"]:
            verdict = "flapping"
        else:
            verdict = "recovered"
        accounts.append({
            "user": acc["user"], "kind": acc["kind"],
            "blocks": acc["blocks"],
            "firstBlock": acc["firstBlock"], "lastBlock": acc["lastBlock"],
            "lastSuccess": last_ok or None,
            "probeNote": acc.get("probeError") or acc.get("probeSkipped"),
            "interactiveSuccess": bool(inter_ok),
            "verdict": verdict,
            "blocksRecent": acc["blocksRecent"],
            "apps": [a for a, _ in acc["apps"].most_common(4)],
            "recentApps": [a for a, _ in acc["recentApps"].most_common(3)],
            "policies": [p for p, _ in acc["policies"].most_common(3)],
            "controls": [c for c, _ in acc["controls"].most_common(3)],
            "codes": [c for c, _ in acc["codes"].most_common(3)],
        })
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


def _clean_ip(ip: str) -> str:
    if not ip:
        return ""
    ip = ip.strip()
    if ip.startswith("["):
        return ip[1:].split("]")[0]
    if ip.count(":") == 1 and ip.count(".") == 3:
        return ip.split(":")[0]
    return ip


def _clean_user(raw: str) -> str:
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
    if not (d.get("deviceId") or "").strip():
        return "noClaim"
    return "claimCompliant" if d.get("isCompliant") else "claimNotCompliant"


def _device(d: dict) -> str:
    if not d:
        return ""
    bits = [(d.get("operatingSystem") or "").strip() or "unknown OS"]
    if d.get("isManaged"):
        bits.append("compliant" if d.get("isCompliant") else "non-compliant")
    else:
        bits.append("unmanaged")
    return " · ".join(bits)


SCOPE_ALL = "all"
SCOPE_UNKNOWN = "unknown"


async def _members(path: str) -> set | None:
    out, url = set(), path
    for _ in range(10):
        try:
            r = await graph_get(url)
        except httpx.HTTPStatusError as exc:
            return set() if exc.response.status_code == 404 else None
        except Exception:
            return None
        for m in r.get("value") or []:
            if m.get("userPrincipalName"):
                out.add(m["userPrincipalName"].lower())
        url = r.get("@odata.nextLink")
        if not url:
            break
    return out


async def _policy_scope(cond_users: dict) -> object:
    inc_u = cond_users.get("includeUsers") or []
    if "All" in inc_u:
        return SCOPE_ALL
    scope, unresolved = set(), False
    for uid in inc_u:
        if uid in ("None", ""):
            continue
        if uid == "GuestsOrExternalUsers":
            unresolved = True
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
    if unresolved:
        return SCOPE_UNKNOWN
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
    except Exception:
        return ""
    return (u.get("userPrincipalName") or "").lower()


async def _policy_meta() -> dict:
    try:
        pols = (await graph_get("/identity/conditionalAccess/policies")).get("value") or []
    except Exception:
        return {}
    meta = {}
    for p in pols:
        nm = p.get("displayName")
        if not nm:
            continue
        grants = set((p.get("grantControls") or {}).get("builtInControls") or [])
        devfilter = ((p.get("conditions") or {}).get("devices") or {}).get("deviceFilter")
        meta[nm] = {
            "state": p.get("state"),
            "scope": await _policy_scope((p.get("conditions") or {}).get("users") or {}),
            "device": bool(devfilter) or bool(grants & {"compliantDevice", "domainJoinedDevice"}),
        }
    return meta


_STATE_MODE = {
    "enabled": "enforced",
    "enabledForReportingButNotEnforced": "report-only",
    "disabled": "off",
}
MODE_GONE = "gone"


def _policy_mode(name: str, meta: dict, unknown_default: str) -> str:
    state = (meta.get(name) or {}).get("state")
    if state:
        return _STATE_MODE.get(state) or unknown_default
    if meta:
        return MODE_GONE
    return unknown_default


def _policy_eval_rows(ca_eval: dict, users: dict, controls: dict, claims: dict,
                      in_scope: dict, meta: dict, block_last: dict, success_last: dict) -> list:
    rows = []
    for nm, c in ca_eval.items():
        ro = sum(v for k, v in c.items() if k in _RESULTS_REPORT_ONLY)
        en = sum(v for k, v in c.items() if k in _RESULTS_ENFORCED)
        mode = _policy_mode(
            nm, meta,
            "report-only" if ro else "enforced" if en else "unknown")
        scope = (meta.get(nm) or {}).get("scope", SCOPE_UNKNOWN)
        evaluated = sum(c.values())
        applied = (c["success"] + c["reportOnlySuccess"] + c["failure"]
                   + c["reportOnlyFailure"] + c["reportOnlyInterrupted"])
        blocked_users = block_last.get(nm) or {}
        stuck = sorted(u for u, t in blocked_users.items() if success_last.get(u, "") <= t)
        rows.append({
            "policy": nm,
            "mode": mode,
            "switched": bool(ro and en),
            "inScope": (evaluated if scope == SCOPE_ALL
                        else None if scope == SCOPE_UNKNOWN
                        else in_scope.get(nm, 0)),
            "scopeKind": ("all" if scope == SCOPE_ALL
                          else "unknown" if scope == SCOPE_UNKNOWN else "targeted"),
            "evaluated": evaluated,
            "applied": applied,
            "pass": c["success"] + c["reportOnlySuccess"],
            "blocked": c["failure"],
            "blockedUsers": len(blocked_users),
            "stuckUsers": len(stuck),
            "stuckSample": stuck[:5],
            "wouldBlock": c["reportOnlyFailure"],
            "interrupted": c["reportOnlyInterrupted"],
            "notApplied": c["notApplied"] + c["reportOnlyNotApplied"] + c["notEnabled"],
            "usersImpacted": len(users.get(nm) or ()),
            "controls": [ctl for ctl, _ in (controls.get(nm) or Counter()).most_common(5)],
            "noClaim": (claims.get(nm) or Counter())["noClaim"],
            "claimNotCompliant": (claims.get(nm) or Counter())["claimNotCompliant"],
            "claimCompliant": (claims.get(nm) or Counter())["claimCompliant"],
        })
    rows.sort(key=lambda x: (x["stuckUsers"], x["blocked"], x["wouldBlock"] + x["interrupted"],
                             x["evaluated"]), reverse=True)
    return rows


CREDENTIAL_ATTACK_CODES = {
    50126,
    50053,
    50034,
    50055,
}

_POLICY_WORKING_CODES = {
    50074, 50076, 50079,
    50072, 50077,
    53000, 53001, 53002, 53003,
    50105,
    50057,
    50133, 50144,
    50140, 50158,
    65001,
    50097,
}

EGRESS_MIN_SUCCESS = 10
EGRESS_MAX_FAIL_RATE = 0.40


def _declared_egress() -> list:
    out, bad = [], []
    for raw in (settings.signin_egress_ips or "").split(","):
        s = raw.strip()
        if not s:
            continue
        try:
            out.append(ipaddress.ip_network(s, strict=False))
        except ValueError:
            bad.append(s)
    if bad:
        print(f"[risky_signins] ⛔ SIGNIN_EGRESS_IPS 에 해석할 수 없는 항목 {len(bad)}개: "
              f"{', '.join(bad[:5])} — 이 항목들은 출구로 인정되지 않습니다")
    return out


def _ip_in(ip: str, nets: list) -> bool:
    if not nets or not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in nets)

FAIL_THEN_SUCCESS_MIN = 3
HUMAN_RETRY_MAX_MIN = 15
HUMAN_RETRY_MAX_FAILS = 5

RARE_COUNTRY_MAX_SHARE = 0.01


def _aggregate(records: list, truncated: bool, meta: dict | None = None) -> dict:
    meta = meta or {}
    logins = failed = 0
    users, ips = set(), set()
    failed_by_user = Counter()
    failed_by_ip = Counter()
    ip_failed_users = defaultdict(set)
    user_login_ips = defaultdict(set)
    success_by_ip = Counter()
    ip_users_all = defaultdict(set)
    ip_loc = {}
    ip_attack_fails = Counter()
    ip_attack_users = defaultdict(set)
    unclassified_codes = Counter()
    country_counts = Counter()
    pair_fail_ts = defaultdict(list)
    pair_success_ts = defaultdict(list)
    pair_fail_ua = defaultdict(set)
    pair_success_ua = defaultdict(dict)
    pair_success_mfa = defaultdict(dict)
    fail_ctx = defaultdict(list)
    success_rows = []
    disabled_target = []
    failed_by_day = Counter()
    recent_failures = []
    ca_status_counts = Counter()
    ca_fail_by_policy = Counter()
    ca_fail_by_control = Counter()
    ca_failures = []
    ca_eval = defaultdict(Counter)
    ca_eval_users = defaultdict(set)
    ca_eval_controls = defaultdict(Counter)
    ca_eval_claim = defaultdict(Counter)
    ca_in_scope = Counter()
    ca_block_last = defaultdict(dict)
    last_success_ts = {}
    dev_block = defaultdict(lambda: {
        "count": 0, "first": None, "last": None,
        "policies": set(), "browsers": Counter(), "claims": Counter(), "apps": Counter(),
    })
    ro_impact = []
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
        if client in _LEGACY_CLIENTS:
            legacy_by_client[client] += 1
            if upn:
                legacy_users.add(upn)

        if ip:
            ip_loc.setdefault(ip, loc)
            if upn:
                ip_users_all[ip].add(upn)
        ctry = (r.get("location") or {}).get("countryOrRegion")
        if ctry:
            country_counts[ctry] += 1

        if is_success:
            logins += 1
            if upn and ts and ts > last_success_ts.get(upn, ""):
                last_success_ts[upn] = ts
            if upn and ip:
                user_login_ips[upn].add(ip)
            if ip:
                success_by_ip[ip] += 1
            if upn and ip and ts:
                pair_success_ts[(upn, ip)].append(ts)
                dd_s = r.get("deviceDetail") or {}
                pair_success_ua[(upn, ip)][ts] = _ua_family(
                    dd_s.get("browser"), dd_s.get("operatingSystem"))
                pair_success_mfa[(upn, ip)][ts] = any(
                    p.get("result") == "success"
                    and "Mfa" in (p.get("enforcedGrantControls") or [])
                    for p in (r.get("appliedConditionalAccessPolicies") or []))
                success_rows.append({"time": ts, "user": upn, "ip": ip, "location": loc,
                                     "country": ctry, "app": r.get("appDisplayName"),
                                     "client": client,
                                     "homeTenant": r.get("homeTenantId")})
        else:
            failed += 1
            if upn:
                failed_by_user[upn] += 1
            if ip:
                failed_by_ip[ip] += 1
            if ip and upn:
                ip_failed_users[ip].add(upn)
            if code in CREDENTIAL_ATTACK_CODES:
                if ip:
                    ip_attack_fails[ip] += 1
                if ip and upn:
                    ip_attack_users[ip].add(upn)
                if upn and ip and ts:
                    pair_fail_ts[(upn, ip)].append(ts)
                    _ddf = r.get("deviceDetail") or {}
                    pair_fail_ua[(upn, ip)].add(
                        _ua_family(_ddf.get("browser"), _ddf.get("operatingSystem")))
                dd = r.get("deviceDetail") or {}
                fail_ctx[ip].append({
                    "hasDevice": bool(dd.get("deviceId") or dd.get("operatingSystem")),
                    "browser": bool(dd.get("browser")),
                    "app": r.get("appDisplayName"),
                    "ts": ts,
                })
            elif code == 50057:
                disabled_target.append({"time": ts, "user": upn or "(unresolved)", "ip": ip,
                                        "location": loc})
            elif code not in _POLICY_WORKING_CODES:
                unclassified_codes[code] += 1
            if ts:
                failed_by_day[ts[:10]] += 1
            recent_failures.append({
                "time": ts,
                "user": upn or "(unresolved)",
                "ip": ip,
                "code": code,
                "error": _decode(code, status.get("failureReason"))[0],
                "errorKo": _decode(code, status.get("failureReason"))[1],
                "location": loc,
            })

        applied = r.get("appliedConditionalAccessPolicies") or []
        en_names, en_controls = [], []
        ro_names, ro_controls = [], []
        ro_interrupt_only = True
        claim = _claim_state(r.get("deviceDetail") or {})
        for p in applied:
            res = p.get("result")
            nm = p.get("displayName")
            if not nm or not res:
                continue
            ca_eval[nm][res] += 1
            sc = (meta.get(nm) or {}).get("scope")
            if isinstance(sc, set) and upn and upn.lower() in sc:
                ca_in_scope[nm] += 1
            if res not in _RESULTS_IMPACT:
                continue
            controls = [c for c in ((p.get("enforcedGrantControls") or [])
                                    + (p.get("enforcedSessionControls") or [])) if c]
            if upn:
                ca_eval_users[nm].add(upn)
            ca_eval_claim[nm][claim] += 1
            for ctl in controls:
                ca_eval_controls[nm][ctl] += 1
            if res in _RESULTS_REPORT_ONLY:
                if _policy_mode(nm, meta, "report-only") != "report-only":
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
                if upn and (meta.get(nm) or {}).get("device"):
                    d = dev_block[upn]
                    d["count"] += 1
                    if ts:
                        if not d["first"] or ts < d["first"]:
                            d["first"] = ts
                        if not d["last"] or ts > d["last"]:
                            d["last"] = ts
                    d["policies"].add(nm)
                    d["claims"][claim] += 1
                    dd = r.get("deviceDetail") or {}
                    d["browsers"][(dd.get("browser") or r.get("clientAppUsed") or "?")] += 1
                    d["apps"][r.get("appDisplayName") or "?"] += 1

        if ca_status == "failure":
            ca_failures.append({
                "time": ts, "user": upn or "(unresolved)", "ip": ip, "location": loc,
                "policies": en_names, "controls": sorted(set(en_controls)),
                "code": code,
                "error": _decode(code, status.get("failureReason"))[0],
                "errorKo": _decode(code, status.get("failureReason"))[1],
            })

        if ro_names:
            if upn:
                ro_impact_users.add(upn)
            for ctl in set(ro_controls):
                ro_by_control[ctl] += 1
            ro_by_claim[claim] += 1
            ro_impact.append({
                "claim": claim,
                "time": ts, "user": upn or "(unresolved)", "ip": ip, "location": loc,
                "policies": sorted(set(ro_names)), "controls": sorted(set(ro_controls)),
                "app": r.get("appDisplayName") or "",
                "client": client or "",
                "device": _device(r.get("deviceDetail") or {}),
                "severity": "interrupt" if ro_interrupt_only else "block",
                "signInSucceeded": is_success,
            })

    total = logins + failed

    egress = []
    egress_ips = set()
    for ip, succ in success_by_ip.items():
        tot = succ + failed_by_ip.get(ip, 0)
        if succ >= EGRESS_MIN_SUCCESS and tot and (failed_by_ip.get(ip, 0) / tot) <= EGRESS_MAX_FAIL_RATE:
            egress_ips.add(ip)
            egress.append({"ip": ip, "success": succ, "failed": failed_by_ip.get(ip, 0),
                           "users": len(ip_users_all.get(ip, ())), "location": ip_loc.get(ip)})
    declared = _declared_egress()
    matched_declared = sorted(ip for ip in success_by_ip if _ip_in(ip, declared))
    egress_ips |= set(matched_declared)
    egress.sort(key=lambda x: x["success"], reverse=True)

    spray = sorted(
        ({"ip": ip, "failed": ip_attack_fails[ip], "users": len(u),
          "location": ip_loc.get(ip), "success": success_by_ip.get(ip, 0)}
         for ip, u in ip_attack_users.items()
         if len(u) >= 2 and ip not in egress_ips),
        key=lambda x: (x["users"], x["failed"]), reverse=True,
    )[:10]

    signals = []

    for (upn, ip), fts in pair_fail_ts.items():
        if len(fts) < FAIL_THEN_SUCCESS_MIN:
            continue
        last_fail = max(fts)
        succ_ts = pair_success_ts.get((upn, ip), ())
        after = [t for t in succ_ts if t > last_fail]
        before = [t for t in succ_ts if t < min(fts)]
        if not after:
            continue

        hit_ts = min(after)
        f_ua = pair_fail_ua.get((upn, ip)) or set()
        s_ua = pair_success_ua.get((upn, ip), {}).get(hit_ts)
        same_ua = bool(f_ua) and bool(s_ua) and s_ua in f_ua
        span = _mins_between(min(fts), hit_ts)
        mfa_ok = bool(pair_success_mfa.get((upn, ip), {}).get(hit_ts))

        human_retry = (same_ua and len(fts) <= HUMAN_RETRY_MAX_FAILS
                       and span is not None and span <= HUMAN_RETRY_MAX_MIN)
        known_egress = bool(before) and ip in egress_ips

        if human_retry or known_egress:
            why_en = ("same client, {0} failure(s) within {1:.0f} min, then a success"
                      .format(len(fts), span if span is not None else -1) if human_retry
                      else "this person already succeeded from this corporate egress IP before")
            why_ko = ("같은 클라이언트에서 {0}회 실패 후 {1:.0f}분 안에 성공"
                      .format(len(fts), span if span is not None else -1) if human_retry
                      else "이 사람은 이 회사 출구 IP 에서 평소에도 성공하던 사람입니다")
            signals.append({
                "severity": "low", "kind": "failThenSuccess", "verdict": "humanRetry",
                "user": upn, "ip": ip, "location": ip_loc.get(ip), "count": len(fts),
                "firstSeen": min(fts), "lastSeen": hit_ts,
                "detailEn": (f"{len(fts)} credential failures then a success - looks like the "
                             f"person mistyping ({why_en})"
                             + (", and an MFA-requiring policy was satisfied." if mfa_ok else ".")),
                "detailKo": (f"자격증명 실패 {len(fts)}회 뒤 성공 — **오타로 보입니다** ({why_ko})"
                             + (". MFA 를 요구하는 정책도 통과했습니다." if mfa_ok else ".")),
            })
        else:
            bits = []
            if not same_ua:
                bits.append("the client changed between the failures and the success")
            if len(fts) > HUMAN_RETRY_MAX_FAILS:
                bits.append(f"{len(fts)} failures")
            if span is not None and span > HUMAN_RETRY_MAX_MIN:
                bits.append(f"spread over {span:.0f} min")
            if span is None:
                bits.append("timestamps unparseable")
            bits_ko = []
            if not same_ua:
                bits_ko.append("실패와 성공의 클라이언트가 다릅니다")
            if len(fts) > HUMAN_RETRY_MAX_FAILS:
                bits_ko.append(f"실패가 {len(fts)}회입니다")
            if span is not None and span > HUMAN_RETRY_MAX_MIN:
                bits_ko.append(f"{span:.0f}분에 걸쳐 있습니다")
            if span is None:
                bits_ko.append("시각을 해석하지 못했습니다")
            signals.append({
                "severity": "high", "kind": "failThenSuccess", "verdict": "unexplained",
                "user": upn, "ip": ip, "location": ip_loc.get(ip), "count": len(fts),
                "firstSeen": min(fts), "lastSeen": hit_ts,
                "detailEn": (f"{len(fts)} credential failures then a SUCCESS from the same IP - "
                             + "; ".join(bits) + ". Not the mistyping pattern."
                             + ("" if mfa_ok else " No MFA-requiring policy was satisfied.")),
                "detailKo": (f"같은 IP 에서 자격증명 실패 {len(fts)}회 뒤 **성공** — "
                             + " · ".join(bits_ko) + ". 오타 패턴이 아닙니다."
                             + ("" if mfa_ok else " MFA 를 요구하는 정책도 통과하지 않았습니다.")),
            })

    ctry_total = sum(country_counts.values())
    rare = {c for c, n in country_counts.items()
            if ctry_total and (n / ctry_total) < RARE_COUNTRY_MAX_SHARE}
    rare_grp = {}
    for row in success_rows:
        if row.get("country") in rare and row["ip"] not in egress_ips:
            e = rare_grp.setdefault((row["user"], row["country"]),
                                    {"n": 0, "ips": set(), "loc": row["location"],
                                     "first": row["time"], "last": row["time"],
                                     "home": row.get("homeTenant")})
            e["n"] += 1
            e["ips"].add(row["ip"])
            e["first"] = min(e["first"], row["time"])
            e["last"] = max(e["last"], row["time"])
            if not e.get("home"):
                e["home"] = row.get("homeTenant")
    for (u, c), e in rare_grp.items():
        external = bool(e.get("home")) and e["home"] != settings.tenant_id
        if external:
            signals.append({
                "severity": "low", "kind": "rareCountrySuccess", "user": u,
                "ip": ", ".join(sorted(e["ips"])[:3]), "location": e["loc"], "count": e["n"],
                "firstSeen": e["first"], "lastSeen": e["last"],
                "detailEn": f"{e['n']} successful sign-in(s) from {c} by a guest whose account "
                            "lives in another tenant. This tenant's traffic mix is not their "
                            "baseline, so 'rare country' says nothing here - their home country "
                            "is expected. Judge it by who invited them and what they reached.",
                "detailKo": f"{c} 에서 **성공한** 사인인 {e['n']}건 — **다른 테넌트에 사는 "
                            "게스트**입니다. 우리 트래픽 분포는 이 사람의 기준선이 아니므로 "
                            "'드문 국가' 가 여기서는 아무것도 말해 주지 않습니다(홈이 그쪽이면 "
                            "그 나라가 정상입니다). **누가 초대했고 무엇에 접근했는지**로 "
                            "판단하십시오.",
            })
            continue
        signals.append({
            "severity": "high", "kind": "rareCountrySuccess", "user": u,
            "ip": ", ".join(sorted(e["ips"])[:3]), "location": e["loc"], "count": e["n"],
            "firstSeen": e["first"], "lastSeen": e["last"],
            "detailEn": f"{e['n']} successful sign-in(s) from {c}, under "
                        f"{int(RARE_COUNTRY_MAX_SHARE * 100)}% of this tenant's traffic. "
                        f"Travel looks the same as a takeover here - ask the person.",
            "detailKo": f"이 테넌트 트래픽의 {int(RARE_COUNTRY_MAX_SHARE * 100)}% 미만인 "
                        f"{c} 에서 **성공한** 사인인 {e['n']}건. 출장과 탈취는 여기서 같은 "
                        f"모양입니다 — 본인에게 물어보는 것이 가장 빠릅니다.",
        })

    for ip, n in ip_attack_fails.items():
        if success_by_ip.get(ip, 0) == 0 and n >= 1:
            ctxs = fail_ctx.get(ip, [])
            humanish = any(c["hasDevice"] or c["browser"] for c in ctxs)
            if n < 2 and humanish:
                continue
            us = sorted(ip_attack_users.get(ip, ()))
            tss = sorted(c["ts"] for c in ctxs if c.get("ts"))
            signals.append({
                "severity": "med" if n < 5 else "high", "kind": "noSuccessIpAttack",
                "user": us[0] if len(us) == 1 else f"{len(us)} accounts", "ip": ip,
                "location": ip_loc.get(ip), "count": n,
                "firstSeen": tss[0] if tss else None, "lastSeen": tss[-1] if tss else None,
                "detailEn": f"{n} credential failure(s) from an IP with zero successful sign-ins.",
                "detailKo": f"성공한 사인인이 **하나도 없는** IP 에서 자격증명 실패 {n}건.",
            })

    by_user = {}
    for d in disabled_target:
        e = by_user.setdefault(d["user"], {"n": 0, "ips": set(), "loc": d["location"],
                                           "first": d["time"], "last": d["time"]})
        e["n"] += 1
        e["ips"].add(d["ip"])
        e["last"] = max(e["last"] or "", d["time"] or "")
        if d["time"] and (not e["first"] or d["time"] < e["first"]):
            e["first"] = d["time"]
    for u, e in by_user.items():
        signals.append({
            "severity": "low", "kind": "disabledAccountTargeted", "user": u,
            "ip": ", ".join(sorted(x for x in e["ips"] if x)) or "?", "location": e["loc"],
            "count": e["n"], "firstSeen": e["first"], "lastSeen": e["last"],
            "detailEn": f"{e['n']} sign-in attempt(s) against a DISABLED account.",
            "detailKo": f"**비활성 계정**을 상대로 한 사인인 시도 {e['n']}건.",
        })

    _sev_order = {"high": 0, "med": 1, "low": 2}
    signals.sort(key=lambda x: (_sev_order.get(x["severity"], 9), -x["count"]))
    signals = signals[:40]
    multi_ip = sorted(
        ({"user": u, "ips": len(s), "ipList": sorted(s)} for u, s in user_login_ips.items()
         if len(s) >= MULTI_IP_THRESHOLD),
        key=lambda x: x["ips"], reverse=True,
    )[:10]

    recent_failures.sort(key=lambda x: x["time"], reverse=True)
    ca_failures.sort(key=lambda x: x["time"], reverse=True)
    ro_impact.sort(key=lambda x: (x["severity"] == "block", x["time"]), reverse=True)
    policy_eval = _policy_eval_rows(ca_eval, ca_eval_users, ca_eval_controls, ca_eval_claim,
                                    ca_in_scope, meta, ca_block_last, last_success_ts)
    ro_blocks = sum(1 for x in ro_impact if x["severity"] == "block")

    _recent_cut = _iso(_now() - timedelta(hours=24))
    dev_block_rows = []
    for u, d in sorted(dev_block.items(), key=lambda kv: (-kv[1]["count"], kv[0])):
        dev_block_rows.append({
            "user": u,
            "count": d["count"],
            "first": d["first"],
            "last": d["last"],
            "policies": sorted(d["policies"]),
            "claim": (d["claims"].most_common(1) or [("unknown", 0)])[0][0],
            "claims": dict(d["claims"]),
            "browsers": [{"name": n, "count": c} for n, c in d["browsers"].most_common(4)],
            "apps": [{"name": n, "count": c} for n, c in d["apps"].most_common(3)],
        })

    return {
        "windowDays": WINDOW_DAYS,
        "windowEnd": _iso(_now()),
        "recordCount": len(records),
        "truncated": truncated,
        "logins": logins,
        "failed": failed,
        "recent": total,
        "failRate": round(failed / total * 100, 1) if total else 0,
        "uniqueUsers": len(users),
        "uniqueIps": len(ips),
        "topFailedUsers": [{"user": u, "count": c} for u, c in failed_by_user.most_common(10)],
        "sprayIps": spray,
        "egressIps": egress[:10],
        "egressIpCount": len(egress),
        "egressDeclaredCount": len(declared),
        "egressDeclaredMatched": matched_declared[:10],
        "egressDeclaredMatchedCount": len(matched_declared),
        "riskSignals": signals,
        "riskSignalCount": len(signals),
        "riskSignalHigh": len([x for x in signals if x["severity"] == "high"]),
        "unclassifiedFailCodes": dict(unclassified_codes.most_common(10)),
        "multiIpUsers": multi_ip,
        "failedByDay": [{"date": d, "count": failed_by_day[d]} for d in sorted(failed_by_day)],
        "recentFailures": recent_failures[:25],
        "caStatusCounts": dict(ca_status_counts),
        "deviceCaClassifiable": bool(meta),
        "deviceCaBlockUsers": len(dev_block_rows),
        "deviceCaBlockEvents": sum(r["count"] for r in dev_block_rows),
        "deviceCaBlockUsers24h": sum(1 for r in dev_block_rows
                                     if (r["last"] or "") >= _recent_cut),
        "deviceCaBlockEvents24h": sum(r["count"] for r in dev_block_rows
                                      if (r["last"] or "") >= _recent_cut),
        "deviceCaBlocks": dev_block_rows[:30],
        "deviceCaPolicies": sorted(nm for nm, mm in meta.items()
                                   if mm.get("device") and mm.get("state") == "enabled"),
        "caFailedCount": len(ca_failures),
        "caFailByPolicy": [{"policy": p, "count": c} for p, c in ca_fail_by_policy.most_common(10)],
        "caFailByControl": [{"control": c, "count": n} for c, n in ca_fail_by_control.most_common()],
        "caFailures": ca_failures[:25],
        "caPolicyEval": policy_eval,
        "caPolicyEvalCount": len(policy_eval),
        "caReportOnlyPolicyCount": sum(1 for p in policy_eval if p["mode"] == "report-only"),
        "caGonePolicies": [p["policy"] for p in policy_eval if p["mode"] == MODE_GONE],
        "caSwitchedPolicies": [p["policy"] for p in policy_eval if p["switched"]],
        "caPolicyMetaAvailable": bool(meta),
        "caReportOnlyImpactCount": len(ro_impact),
        "caReportOnlyBlockCount": ro_blocks,
        "caReportOnlyInterruptCount": len(ro_impact) - ro_blocks,
        "caReportOnlyUsers": len(ro_impact_users),
        "caReportOnlyByControl": [{"control": c, "count": n} for c, n in ro_by_control.most_common()],
        "caReportOnlyByClaim": {
            "noClaim": ro_by_claim["noClaim"],
            "claimNotCompliant": ro_by_claim["claimNotCompliant"],
            "claimCompliant": ro_by_claim["claimCompliant"],
        },
        "caReportOnlyImpact": ro_impact[:40],
        "legacyAuthCount": sum(legacy_by_client.values()),
        "legacyUsers": len(legacy_users),
        "legacyByClient": [{"client": c, "count": n} for c, n in legacy_by_client.most_common()],
    }


async def fetch() -> dict:
    records, truncated = await _fetch_signins()
    agg = _aggregate(records, truncated, await _policy_meta())
    agg["nonInteractive"] = await _noninteractive_pass(records)
    return {"available": True, "pending": False, "note": None,
            "signinData": signin_cache.stale_info(), **agg}
