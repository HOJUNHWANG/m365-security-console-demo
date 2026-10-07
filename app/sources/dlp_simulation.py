import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..config import settings
from ._i18n import finding, unavailable

_SNAPSHOT = Path(__file__).resolve().parents[2] / "data" / "dlp_simulation.json"
_SPO = Path(__file__).resolve().parents[2] / "data" / "spo_sharing.json"

_STALE_HOURS = 26
_REVIEW_DAYS = 14
_DISTRIBUTED = {"success", "completed", "distributed"}
_TEST_MODES = {"testwithoutnotifications", "testwithnotifications", "disable"}
_AT_REST = {"onedrive", "sharepoint"}


def _domains():
    own = {d.strip().lower() for d in (settings.hunt_own_domains or "").split(",") if d.strip()}
    aff = {d.strip().lower() for d in (settings.hunt_allowlist_domains or "").split(",") if d.strip()}
    return own, aff - own


def _parse(ts):
    if not ts:
        return None
    try:
        return datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
    except ValueError:
        return None


def _sharing_map():
    if not _SPO.exists():
        return None
    try:
        data = json.loads(_SPO.read_text(encoding="utf-8-sig"))
    except Exception:
        return None
    return {str(s.get("url") or "").rstrip("/").lower(): str(s.get("sharingCapability") or "")
            for s in (data.get("sites") or [])}


def _annotate_sites(rows, smap):
    out, open_count, anon_count, unknown = [], 0, 0, 0
    for r in rows or []:
        url = str(r.get("key") or "")
        cap = None if smap is None else (smap.get(url.rstrip("/").lower()) or "")
        low = (cap or "").lower()
        anon = low == "externaluserandguestsharing"
        shareable = bool(cap) and low != "disabled"
        if cap is None or cap == "":
            unknown += int(r.get("count") or 0)
        elif anon:
            anon_count += int(r.get("count") or 0)
        elif shareable:
            open_count += int(r.get("count") or 0)
        out.append({**r, "sharingCapability": cap, "externallyShareable": shareable, "anonymous": anon})
    return out, {"open": open_count, "anonymous": anon_count, "unknown": unknown}


def _classify_exchange(rows):
    own, aff = _domains()
    by_domain, cls_count = {}, {"internal": 0, "affiliate": 0, "external": 0}
    for r in rows or []:
        key = str(r.get("key") or "")
        n = int(r.get("count") or 0)
        dom = key.split("@")[-1].strip().lower() if "@" in key else key.strip().lower()
        if not dom:
            continue
        kind = "internal" if dom in own else ("affiliate" if dom in aff else "external")
        e = by_domain.setdefault(dom, {"domain": dom, "count": 0, "kind": kind})
        e["count"] += n
        cls_count[kind] += n
    ordered = sorted(by_domain.values(), key=lambda x: (-x["count"], x["domain"]))
    return ordered, cls_count


async def fetch() -> dict:
    if not _SNAPSHOT.exists():
        return unavailable(
            en="No DLP snapshot. Run "
               "pwsh -File .\\scripts\\purview\\dlp_simulation_collector.ps1 first.",
            ko="DLP 스냅샷이 없습니다. "
               "pwsh -File .\\scripts\\purview\\dlp_simulation_collector.ps1 를 먼저 돌리십시오.")
    try:
        data = json.loads(_SNAPSHOT.read_text(encoding="utf-8-sig"))
    except Exception as exc:
        return unavailable(en=f"Could not read the snapshot: {type(exc).__name__}: {exc}",
                           ko=f"스냅샷을 읽지 못했습니다: {type(exc).__name__}: {exc}")

    now = datetime.now(timezone.utc)
    collected = _parse(data.get("collectedAt"))
    age_h = round((now - collected).total_seconds() / 3600, 1) if collected else None

    policies = data.get("policies") or []
    findings = []

    sim = next((p for p in policies if p.get("isSimulationPolicy")), None) or (policies[0] if policies else None)

    out = {
        "available": True,
        "collectedAt": data.get("collectedAt"),
        "connectedAs": data.get("connectedAs"),
        "ageHours": age_h,
        "stale": bool(age_h is not None and age_h > _STALE_HOURS),
        "staleHours": _STALE_HOURS,
        "policyCount": len(policies),
        "policies": [{k: v for k, v in p.items() if k != "topLocations"} for p in policies],
        "detailReport": data.get("detailReport") or {},
        "activityExplorer": data.get("activityExplorer") or {},
    }

    if not policies:
        findings.append(finding(
            "high",
            en="There is no DLP policy at all, which means nothing is measuring what leaves. "
               "Start with measurement (it blocks nobody): "
               "scripts/purview/Set-PurviewBaseline.ps1 -DlpSimulation -Apply",
            ko="DLP 정책이 하나도 없습니다. 무엇이 흘러나가는지 재는 장치가 없다는 뜻입니다. "
               "scripts/purview/Set-PurviewBaseline.ps1 -DlpSimulation -Apply 로 "
               "측정(차단 없음)부터 시작하십시오."))
        out.update({"findings": findings, "findingCount": len(findings),
                    "highFindingCount": 1, "simulation": None})
        return out

    mode = str(sim.get("mode") or "")
    testing = mode.lower() in _TEST_MODES
    dist = str(sim.get("distributionStatus") or "")
    distributed = dist.lower() in _DISTRIBUTED
    created = _parse(sim.get("whenCreated"))
    review_on = (created + timedelta(days=_REVIEW_DAYS)).date().isoformat() if created else None
    days_to_review = (created + timedelta(days=_REVIEW_DAYS) - now).days if created else None

    ws = sim.get("workloadStatistics") or {}
    at_rest = sum(int(v or 0) for k, v in ws.items() if k.lower() in _AT_REST)
    in_mail = int(ws.get("Exchange") or 0)
    top = sim.get("topLocations") or {}
    ex_domains, ex_class = _classify_exchange(top.get("Exchange"))
    smap = _sharing_map()
    spo_sites, spo_overlap = _annotate_sites(top.get("SharePoint"), smap)
    if smap is not None:
        top = {**top, "SharePoint": spo_sites}
    sampled = sum(d["count"] for d in ex_domains)

    rules = sim.get("rules") or []
    sit_names = [t.get("name") for r in rules for t in (r.get("sensitiveTypes") or [])]
    blocking_rule = any(r.get("blockAccess") for r in rules)
    notifying = any(r.get("notifyUser") for r in rules)

    if not rules:
        findings.append(finding(
            "high",
            en=f"Policy '{sim.get('name')}' exists but has no rule. A policy without a rule "
               "catches nothing - the quietest failure there is.",
            ko=f"'{sim.get('name')}' 정책은 있는데 규칙이 없습니다. 규칙 없는 정책은 "
               "아무것도 잡지 않습니다 - 가장 조용한 실패입니다."))
    if not testing or blocking_rule:
        _blk = " · BlockAccess=True" if blocking_rule else ""
        findings.append(finding(
            "med",
            en=f"This policy is no longer measurement-only (Mode={mode}{_blk}). It now blocks work "
               "or notifies users. Confirm the change was intended.",
            ko=f"이 정책은 더 이상 측정 전용이 아닙니다 (Mode={mode}{_blk}). 실제로 사람의 작업을 "
               "막거나 알림을 보냅니다. 의도한 변경인지 확인하십시오."))
    if not distributed:
        age_txt = f" (생성 {sim.get('whenCreated', '')[:10]})" if created else ""
        age_txt_en = f" (created {sim.get('whenCreated', '')[:10]})" if created else ""
        findings.append(finding(
            "med" if (created and (now - created).days >= 2) else "info",
            en=f"Distribution status is '{dist}'{age_txt_en}. Until it completes the policy may not "
               "be covering the whole scope, so read the numbers below as a floor, not a total.",
            ko=f"배포 상태가 '{dist}' 입니다{age_txt}. 배포가 끝나기 전에는 전 범위를 "
               "재고 있지 않을 수 있으므로, 지금 숫자는 하한으로 보십시오."))
    if ex_class["external"] > 0:
        _doms = ", ".join(d["domain"] for d in ex_domains if d["kind"] == "external")
        findings.append(finding(
            "high",
            en=f"{ex_class['external']} mail match(es) involve external domains ({_doms}). "
               "This is the evidence for deciding whether to enforce - but the field does not say "
               "which direction the mail went, so confirm with the detail report or message trace "
               "before you turn blocking on.",
            ko=f"민감정보가 든 메일에 외부 도메인이 {ex_class['external']}건 얽혀 있습니다 "
               f"({_doms}). ★ 차단 모드로 올릴지의 결정 근거가 여기입니다 - 다만 이 필드는 "
               "방향(보냄/받음)을 말해 주지 않으므로, 올리기 전에 상세 리포트나 메시지 추적으로 "
               "확인하십시오."))
    elif in_mail > 0:
        findings.append(finding(
            "info",
            en=f"All {in_mail} mail match(es) are internal or affiliate in the sample. Nothing so far "
               "points to sensitive content leaving the group (top-locations sample).",
            ko=f"메일 매치 {in_mail}건은 표본상 전부 사내·계열입니다. 지금까지는 외부로 나간 "
               "정황이 없습니다 (상위 위치 표본 기준)."))
    if at_rest > 0:
        findings.append(finding(
            "med",
            en=f"{at_rest} file(s) holding sensitive data are stored in OneDrive/SharePoint. That is "
               "storage, not a leak - but it is the amount exposed if one of those accounts or sites "
               "is compromised, so check whether it overlaps sites with external sharing open.",
            ko=f"OneDrive·SharePoint 에 민감정보가 든 파일이 {at_rest}건 쌓여 있습니다. "
               "이건 유출이 아니라 보관 상태입니다 - 다만 그 계정이나 사이트가 뚫리면 "
               "그대로 노출되는 양이고, 외부 공유가 열린 사이트와 겹치는지 봐야 합니다."))
    if smap is None:
        findings.append(finding(
            "low",
            en="No per-site sharing snapshot (data/spo_sharing.json), so the sites holding sensitive "
               "files could not be checked against external sharing. Run spo_sharing_collector.ps1.",
            ko="사이트별 공유 스냅샷(data/spo_sharing.json)이 없어, 민감파일이 쌓인 사이트가 "
               "외부로 열려 있는지 대조하지 못했습니다. spo_sharing_collector.ps1 를 돌리십시오."))
    elif spo_overlap["anonymous"]:
        findings.append(finding(
            "high",
            en=f"{spo_overlap['anonymous']} file(s) holding sensitive data sit on sites where "
               "anonymous links are allowed. An anonymous link carries no identity, so Conditional "
               "Access and MFA never see that access - this combination is the shortest path out of "
               "the tenant.",
            ko=f"민감정보가 든 파일 {spo_overlap['anonymous']}건이 익명 링크가 허용된 "
               "사이트에 있습니다. 익명 링크는 신원이 없어 CA·MFA 가 닿지 않습니다 - "
               "이 조합이 이 테넌트에서 가장 짧은 유출 경로입니다."))
    elif spo_overlap["open"]:
        findings.append(finding(
            "med",
            en=f"{spo_overlap['open']} file(s) holding sensitive data sit on sites with external "
               "sharing open (guest invite). That is not anonymous - an identity is still required, "
               "so Conditional Access applies - but it means the sites holding the most sensitive "
               "files are also the ones open to outsiders.",
            ko=f"민감정보가 든 파일 {spo_overlap['open']}건이 외부 공유(게스트 초대)가 열린 "
               "사이트에 있습니다. 익명이 아니라 신원이 남으므로 CA 가 적용되지만, "
               "민감파일이 가장 많이 쌓인 곳과 외부로 열린 곳이 같다는 뜻입니다."))

    if distributed and int(sim.get("matchedItemsCount") or 0) == 0:
        findings.append(finding(
            "med",
            en="Distribution finished and nothing matched. That may mean there is nothing to find, "
               "but it more often means the detection types do not fit this organisation's actual "
               "data. Adjust the types.",
            ko="배포가 끝났는데 매치가 0건입니다. 안전하다는 뜻일 수도 있지만, 탐지 유형이 "
               "이 조직의 실제 데이터와 안 맞는다는 뜻일 가능성이 더 큽니다. 유형을 조정하십시오."))
    if days_to_review is not None and days_to_review <= 0:
        findings.append(finding(
            "med",
            en=f"The review date ({review_on}) has passed. The simulation is still running and still "
               "blocks nobody, but measuring without deciding just leaves a policy behind.",
            ko=f"리뷰 기한({review_on})이 지났습니다. 시뮬레이션은 계속 도는 중이고 아무도 "
               "막지 않지만, 재기만 하고 결정하지 않으면 이 정책은 그냥 남는 설정이 됩니다."))
    dr = data.get("detailReport") or {}
    if dr.get("available") and not dr.get("rowCount"):
        findings.append(finding(
            "info",
            en="Get-DlpDetailReport returned 0 rows. The policy counters do show matches, so this "
               "means 'the report has not filled yet', not 'there is nothing'. Direction of travel "
               "only becomes readable once it fills.",
            ko="Get-DlpDetailReport 는 0행입니다. 정책 통계에는 매치가 있으므로 이건 "
               "'없다' 가 아니라 '리포트가 아직 안 찼다' 입니다. 방향(보냄/받음)을 보려면 "
               "이 리포트가 차야 합니다."))
    elif dr.get("reason"):
        findings.append(finding(
            "med",
            en=f"The detail report could not be read ({dr.get('reason')}). Direction of travel cannot "
               "be judged; only the policy counters are available.",
            ko=f"상세 리포트를 읽지 못했습니다 ({dr.get('reason')}). 방향 판정은 불가능하고, "
               "정책 통계만으로 판단해야 합니다."))
    if out["stale"]:
        sev = "high" if age_h > _STALE_HOURS * 3 else "med"
        days = round(age_h / 24, 1)
        extra_en = ("" if sev == "med" else
                    f" This is {days} days, not a late run - treat the collector as DEAD and "
                    f"check data/collect_exit.json. ⛔ EVERY other finding on this card was "
                    f"computed from that {days}-day-old snapshot, including the high ones.")
        extra_ko = ("" if sev == "med" else
                    f" {days}일입니다. 수집이 **늦은 것이 아니라 죽은 것**으로 보고 "
                    f"data/collect_exit.json 을 확인하십시오. ⛔ **이 카드의 다른 판정은 "
                    f"전부 그 {days}일 전 스냅샷으로 계산된 것입니다** — high 판정도 "
                    f"포함입니다. 먼저 수집을 되살리고 그 다음에 내용을 보십시오.")
        findings.append(finding(
            sev,
            en=f"The snapshot is {age_h}h old (over {_STALE_HOURS}h). "
               f"Re-run scripts/purview/dlp_simulation_collector.ps1." + extra_en,
            ko=f"수집이 {age_h}시간 전입니다 ({_STALE_HOURS}시간 초과). "
               f"scripts/purview/dlp_simulation_collector.ps1 를 다시 돌리십시오." + extra_ko))

    out["simulation"] = {
        "name": sim.get("name"),
        "mode": mode,
        "testing": testing,
        "enabled": bool(sim.get("enabled")),
        "isSimulationPolicy": bool(sim.get("isSimulationPolicy")),
        "simulationStatus": sim.get("simulationStatus"),
        "distributionStatus": dist,
        "distributed": distributed,
        "whenCreated": sim.get("whenCreated"),
        "reviewOn": review_on,
        "daysToReview": days_to_review,
        "locations": sim.get("locations") or {},
        "matchedItemsCount": int(sim.get("matchedItemsCount") or 0),
        "workloadStatistics": ws,
        "atRestCount": at_rest,
        "inMailCount": in_mail,
        "exchangeDomains": ex_domains,
        "exchangeByClass": ex_class,
        "exchangeSampledCount": sampled,
        "topLocations": top,
        "spoOverlap": (None if smap is None else spo_overlap),
        "ruleCount": len(rules),
        "rules": rules,
        "sensitiveTypes": sit_names,
        "blockingRule": blocking_rule,
        "notifyingUsers": notifying,
    }
    _rank = {"high": 0, "med": 1, "low": 2, "info": 3}
    findings.sort(key=lambda f: _rank.get(f["severity"], 9))
    out["findings"] = findings
    out["findingCount"] = len(findings)
    out["highFindingCount"] = sum(1 for f in findings if f["severity"] == "high")
    return out
