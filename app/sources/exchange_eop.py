import fnmatch
import json
from datetime import datetime, timezone
from pathlib import Path

from ._i18n import finding

SNAPSHOT = Path(__file__).resolve().parent.parent.parent / "data" / "exo_snapshot.json"
FORWARD_INTENT = Path(__file__).resolve().parent.parent.parent / "data" / "forwarding-intent.json"
ADDIN_INTENT = Path(__file__).resolve().parent.parent.parent / "data" / "addin-intent.json"

EXO_COLLECT_TIMES = ["10:00", "13:00", "16:00"]
EXO_STALE_HOURS = 20


async def fetch() -> dict:
    if not SNAPSHOT.exists():
        return {
            "available": False,
            "reason": "No EXO snapshot found. Run scripts/exo_collector.ps1 first.",
        }
    try:
        data = json.loads(SNAPSHOT.read_text(encoding="utf-8-sig"))
    except Exception as e:
        return {"available": False, "reason": f"Failed to read snapshot: {e}"}

    age_h = None
    stale = False
    collected = data.get("collectedAt")
    if collected:
        try:
            dt = datetime.fromisoformat(collected.replace("Z", "+00:00"))
            age_h = round((datetime.now(timezone.utc) - dt).total_seconds() / 3600, 1)
            stale = age_h > EXO_STALE_HOURS
        except ValueError:
            pass

    data["available"] = True
    data["ageHours"] = age_h
    data["stale"] = stale
    data["collectTimes"] = EXO_COLLECT_TIMES
    findings = []
    for review in (_forwarding_review(data), _addin_review(data)):
        findings += review.pop("findings", [])
        data.update(review)
    data["findings"] = findings
    return data


def _own_domains(data: dict) -> list:
    return [d.lower() for d in ((data.get("allowlist") or {}).get("ownDomains") or [])]


def _is_external(addr: str, own: list) -> bool:
    if not addr or "@" not in addr or not own:
        return False
    dom = addr.rsplit("@", 1)[-1].lower()
    return not any(dom == d or dom.endswith("." + d) for d in own)


def _matches(addr: str, pattern: str) -> bool:
    a, p = (addr or "").lower(), (pattern or "").lower()
    if not p:
        return False
    if "*" in p or "?" in p:
        return fnmatch.fnmatch(a, p) or fnmatch.fnmatch(a.rsplit("@", 1)[-1], p)
    return a == p or a.rsplit("@", 1)[-1] == p


def _forwarding_review(data: dict) -> dict:
    out = {"forwardingExternal": [], "forwardingExternalCount": 0,
           "forwardingDrift": [], "forwardingDriftCount": 0,
           "forwardingIntentAvailable": False, "findings": []}
    own = _own_domains(data)
    rows = data.get("forwarding") or []

    scan_errs = [e for e in (data.get("errors") or []) if "mailbox" in str(e).lower()]
    if scan_errs:
        out["forwardingScanIncomplete"] = True
        out["findings"].append(finding(
            "med",
            en="The mailbox scan in the EXO collector reported an error, so the forwarding, "
               "inbox-rule and delegation lists are INCOMPLETE. Forwarding drift is not being "
               f"judged - a zero here would be a lie. Re-run scripts/exo_collector.ps1. ({scan_errs[0]})",
            ko="EXO 수집기의 사서함 스캔이 오류를 냈습니다. 그래서 전달·인박스 룰·위임 목록이 "
               "**불완전합니다.** 전달 드리프트를 판정하지 않습니다 — 여기서 0 은 거짓입니다. "
               f"scripts/exo_collector.ps1 을 다시 돌리십시오. ({scan_errs[0]})"))
        return out

    intent, intent_err = None, None
    if FORWARD_INTENT.exists():
        try:
            intent = json.loads(FORWARD_INTENT.read_text(encoding="utf-8-sig"))
        except Exception as exc:
            intent_err = f"{type(exc).__name__}: {exc}"
    out["forwardingIntentAvailable"] = intent is not None
    declared = (intent or {}).get("intended") or []

    if not own:
        out["findings"].append(finding(
            "med",
            en="The tenant's own-domain list is missing from the EXO snapshot, so internal and "
               "external forwarding cannot be told apart. Forwarding drift is NOT being judged.",
            ko="EXO 스냅샷에 테넌트 자체 도메인 목록이 없어서 내부/외부 전달을 구별할 수 "
               "없습니다. 전달 드리프트를 **판정하지 않고 있습니다.**"))
        return out

    for r in rows:
        addr = r.get("forwardingSmtpAddress") or ""
        if not _is_external(addr, own):
            continue
        hit = next((d for d in declared
                    if (d.get("mailbox") or "").lower() == (r.get("mailbox") or "").lower()
                    and _matches(addr, d.get("forwardTo"))), None)
        item = {"mailbox": r.get("mailbox"), "to": addr,
                "keepsCopy": bool(r.get("deliverToMailboxAndForward")),
                "declared": hit is not None,
                "confirmed": bool(hit.get("confirmed")) if hit else False,
                "reason": (hit or {}).get("reason")}
        out["forwardingExternal"].append(item)
        if not hit:
            out["forwardingDrift"].append(item)
    out["forwardingExternalCount"] = len(out["forwardingExternal"])
    out["forwardingDriftCount"] = len(out["forwardingDrift"])

    if intent_err:
        out["findings"].append(finding(
            "med",
            en=f"data/forwarding-intent.json could not be read ({intent_err}). Every external "
               "forward below is therefore reported as unrecorded - fix the file, not the mailboxes.",
            ko=f"data/forwarding-intent.json 을 읽지 못했습니다 ({intent_err}). 그래서 아래 외부 "
               "전달이 전부 '기록 없음' 으로 잡힙니다 — 사서함이 아니라 파일을 고치십시오."))
    elif intent is None and out["forwardingExternalCount"]:
        out["findings"].append(finding(
            "med",
            en=f"{out['forwardingExternalCount']} mailbox(es) auto-forward outside the tenant and "
               "there is no intent record to judge them against. Write data/forwarding-intent.json.",
            ko=f"테넌트 밖으로 자동전달하는 사서함이 {out['forwardingExternalCount']}개인데, "
               "대조할 의도 기록이 없습니다. data/forwarding-intent.json 을 만드십시오."))

    if out["forwardingDriftCount"]:
        out["findings"].append(finding(
            "high",
            en=f"{out['forwardingDriftCount']} mailbox(es) auto-forward outside the tenant without "
               "a record. This path needs no app consent and no sign-in, so app-consent and "
               "Conditional Access controls do not touch it. Deliberate exceptions belong in "
               "data/forwarding-intent.json; anything not listed there is drift.",
            ko=f"기록에 없는 외부 자동전달 사서함이 {out['forwardingDriftCount']}개 있습니다. "
               "이 경로는 **앱 동의도 사인인도 필요하지 않아서** 앱 동의 차단과 Conditional "
               "Access 가 닿지 않습니다. 의도된 예외는 data/forwarding-intent.json 에 적고, "
               "여기 없으면 그것이 드리프트입니다."))

    unconfirmed = [x for x in out["forwardingExternal"] if x["declared"] and not x["confirmed"]]
    if unconfirmed:
        out["findings"].append(finding(
            "low",
            en=f"{len(unconfirmed)} recorded external forward(s) are not yet confirmed "
               "(confirmed=false). Settle the record.",
            ko=f"기록에는 있으나 아직 확인되지 않은 외부 전달이 {len(unconfirmed)}건 있습니다 "
               "(confirmed=false). 기록을 정리하십시오."))
    return out


def read_allowlist() -> dict | None:
    if not SNAPSHOT.exists():
        return None
    try:
        data = json.loads(SNAPSHOT.read_text(encoding="utf-8-sig"))
    except Exception:
        return None
    return data.get("allowlist")


def _addin_review(data: dict) -> dict:
    out = {"addins": [], "addinCount": 0, "addinVendorCount": 0,
           "addinDrift": [], "addinDriftCount": 0, "addinIntentAvailable": False}
    rows = data.get("outlookAddins")

    if rows is None:
        out["addinCollected"] = False
        return out
    out["addinCollected"] = True

    scan_errs = [e for e in (data.get("errors") or []) if "mailbox" in str(e).lower()]
    if scan_errs:
        out["addinScanIncomplete"] = True
        out["findings"] = [finding(
            "med",
            en="The mailbox scan reported an error, so the installed add-in list is INCOMPLETE. "
               "Add-in drift is not being judged - a zero here would be a lie.",
            ko="사서함 스캔이 오류를 냈습니다. 설치된 애드인 목록이 **불완전합니다.** "
               "애드인 드리프트를 판정하지 않습니다 — 여기서 0 은 거짓입니다.")]
        return out

    intent, intent_err = None, None
    if ADDIN_INTENT.exists():
        try:
            intent = json.loads(ADDIN_INTENT.read_text(encoding="utf-8-sig"))
        except Exception as exc:
            intent_err = f"{type(exc).__name__}: {exc}"
    out["addinIntentAvailable"] = intent is not None
    declared = {(d.get("appId") or "").lower(): d for d in ((intent or {}).get("intended") or [])}

    by_app = {}
    for r in rows:
        key = (r.get("appId") or "").lower()
        e = by_app.setdefault(key, {"app": r.get("app"), "provider": r.get("provider"),
                                    "appId": r.get("appId"), "mailboxes": 0, "enabled": 0})
        e["mailboxes"] += 1
        if r.get("enabled"):
            e["enabled"] += 1
    for key, e in by_app.items():
        hit = declared.get(key)
        e["declared"] = hit is not None
        e["confirmed"] = bool(hit.get("confirmed")) if hit else False
        e["reason"] = (hit or {}).get("reason")
        e["openDecision"] = (hit or {}).get("openDecision")
        e["reviewTrigger"] = (hit or {}).get("reviewTrigger")
        out["addins"].append(e)
        if not hit:
            out["addinDrift"].append(e)
    out["addins"].sort(key=lambda a: (a["declared"], -a["mailboxes"]))
    out["addinCount"] = sum(a["mailboxes"] for a in out["addins"])
    out["addinVendorCount"] = len(out["addins"])
    out["addinDriftCount"] = len(out["addinDrift"])

    f = out.setdefault("findings", [])
    if intent_err:
        f.append(finding(
            "med",
            en=f"data/addin-intent.json could not be read ({intent_err}). Every add-in below is "
               "therefore reported as unrecorded - fix the file, not the mailboxes.",
            ko=f"data/addin-intent.json 을 읽지 못했습니다 ({intent_err}). 그래서 아래 애드인이 "
               "전부 '기록 없음' 으로 잡힙니다 — 사서함이 아니라 파일을 고치십시오."))
    if out["addinDriftCount"]:
        f.append(finding(
            "high",
            en=f"{out['addinDriftCount']} third-party Outlook add-in(s) are installed without a "
               "record. If self-installation is blocked, a new one means either IT "
               "deployed it centrally or that block is no longer in effect - check "
               "Get-ManagementRoleAssignment for 'Default Role Assignment Policy'. This surface "
               "needs no Entra consent and produces no sign-in log, so nothing else will show it. "
               "Deliberate exceptions belong in data/addin-intent.json.",
            ko=f"기록에 없는 제3자 Outlook 애드인이 {out['addinDriftCount']}개 있습니다. "
               "자가 설치를 막아 두었는데도 새로 생겼다면 **IT 가 중앙 배포했거나 "
               "그 차단이 풀린 것**입니다 — `Get-ManagementRoleAssignment` 로 역할을 "
               "확인하십시오. 이 축은 **Entra 동의도 사인인 로그도 없어서** 다른 어디에도 "
               "나타나지 않습니다. 의도된 예외는 data/addin-intent.json 에 적으십시오."))
    _addin_offboarding_review(data, out, f)
    _addin_controls_review(data, (intent or {}).get("controls"), out, f)

    undecided = [a for a in out["addins"] if a["declared"] and not a["confirmed"]]
    if undecided:
        f.append(finding(
            "low",
            en=f"{len(undecided)} recorded add-in(s) are not settled (confirmed=false) - a "
               "decision is still open on them.",
            ko=f"기록에는 있으나 아직 결정되지 않은 애드인이 {len(undecided)}개 있습니다 "
               "(confirmed=false) — 그 건들의 판단이 열려 있습니다."))

    triggers = [a for a in out["addins"] if a.get("reviewTrigger")]
    out["addinReviewTriggerCount"] = len(triggers)
    if triggers:
        detail_en = "; ".join(f"{a['app']}: {a['reviewTrigger']}" for a in triggers)
        detail_ko = " / ".join(f"{a['app']} — {a['reviewTrigger']}" for a in triggers)
        f.append(finding(
            "info",
            en=f"{len(triggers)} add-in(s) are approved CONDITIONALLY, not permanently. The "
               f"condition is recorded and still open: {detail_en}. When it is met, remove the "
               "add-in and delete the entry - do not let the approval outlive its reason.",
            ko=f"애드인 {len(triggers)}개는 **조건부 승인**입니다 (영구 승인이 아닙니다). "
               f"기록된 조건이 아직 열려 있습니다: {detail_ko}. 조건이 충족되면 애드인을 "
               "제거하고 항목도 지우십시오 — 승인이 그 이유보다 오래 남지 않게 합니다."))
    return out


def _addin_offboarding_review(data: dict, out: dict, f: list) -> None:
    rows = data.get("outlookAddins") or []
    accounts = data.get("addinAccounts")
    if accounts is None:
        out["addinOffboardingCollected"] = False
        return
    out["addinOffboardingCollected"] = True

    state = {a.get("mailbox"): a.get("accountDisabled") for a in accounts}
    unknown = sorted(mb for mb, v in state.items() if v is None)
    stale = []
    for r in rows:
        if state.get(r.get("mailbox")) is True:
            stale.append({"mailbox": r.get("mailbox"), "app": r.get("app"),
                          "provider": r.get("provider"), "appId": r.get("appId"),
                          "enabled": bool(r.get("enabled"))})
    out["addinStale"] = stale
    out["addinStaleCount"] = len(stale)
    out["addinAccountUnknown"] = unknown

    if unknown:
        f.append(finding(
            "low",
            en=f"The account state of {len(unknown)} mailbox(es) with add-ins could not be read, "
               f"so leftover add-ins on departed accounts are not fully judged.",
            ko=f"애드인이 있는 사서함 {len(unknown)}개의 계정 상태를 읽지 못했습니다. "
               f"퇴사자 잔여 애드인 판정이 **불완전합니다.**"))
    if stale:
        boxes = len({s["mailbox"] for s in stale})
        f.append(finding(
            "med",
            en=f"{len(stale)} third-party Outlook add-in(s) remain on {boxes} mailbox(es) whose "
               f"account is disabled. This is not a live path - sign-in is blocked and add-ins are "
               f"per-user scope, so a delegate opening the mailbox uses their own add-ins. The "
               f"point is that re-enabling the account brings the add-in back with it, and a "
               f"disabled account can belong to someone returning from leave rather than a "
               f"departure. Offboarding removes Entra consent but nothing removes add-ins: "
               f"Remove-OutlookAddin.ps1 -Mailbox <upn> -ExcludeName @().",
            ko=f"계정이 **비활성**인 사서함 {boxes}개에 제3자 Outlook 애드인 {len(stale)}건이 "
               f"남아 있습니다. 지금 뚫린 경로는 아닙니다 — 로그인이 막혀 있고 애드인은 "
               f"사용자 범위라 위임자가 사서함을 열어도 자기 애드인을 씁니다. 요점은 "
               f"**계정을 다시 켜면 애드인도 같이 돌아온다**는 것이고, 비활성 "
               f"계정이 퇴사자가 아니라 **복귀 예정 휴직자**의 것일 수도 있습니다. 오프보딩은 "
               f"Entra 동의를 치우지만 애드인은 아무도 치우지 않습니다: "
               f"`Remove-OutlookAddin.ps1 -Mailbox <upn> -ExcludeName @()`."))


def _addin_controls_review(data: dict, want: dict | None, out: dict, f: list) -> None:
    got = data.get("addinControls")
    if got is None:
        out["addinControlsCollected"] = False
        return
    out["addinControlsCollected"] = True

    if not want:
        out["addinControlsIntent"] = False
        return
    out["addinControlsIntent"] = True

    drift, unread = [], []

    store = got.get("appsForOfficeEnabled")
    want_store = want.get("appsForOfficeEnabled")
    if store is None:
        unread.append("appsForOfficeEnabled")
    elif bool(store) != bool(want_store):
        drift.append(f"appsForOfficeEnabled={store} (의도 {want_store})")

    roles = got.get("addinRoles")
    if roles is None:
        unread.append("addinRoles")
    else:
        want_roles = {str(r) for r in (want.get("addinRoles") or [])}
        have = {str(r) for r in roles}
        extra = sorted(have - want_roles)
        missing = sorted(want_roles - have)
        if extra:
            drift.append("역할이 다시 붙었습니다: " + ", ".join(extra))
        if missing:
            drift.append("의도한 역할이 사라졌습니다: " + ", ".join(missing))

    out["addinControlsDrift"] = drift
    out["addinControlsDriftCount"] = len(drift)
    out["addinControlsUnread"] = unread
    out["addinControlsOk"] = (not drift) and (not unread)

    if unread:
        f.append(finding(
            "med",
            en="The EXO collector could not read " + ", ".join(unread) + ", so whether add-in "
               "self-installation is still blocked is UNKNOWN. This is not the same as 'it is "
               "blocked' - the app-only certificate may be missing an Exchange read role.",
            ko="수집기가 " + ", ".join(unread) + " 를 읽지 못했습니다. 애드인 자가 설치가 "
               "아직 막혀 있는지 **알 수 없습니다.** 이것은 '막혀 있다' 와 다릅니다 — "
               "앱 전용 인증서에 Exchange 읽기 역할이 없을 수 있습니다."))
    if drift:
        f.append(finding(
            "high",
            en="Add-in self-installation controls no longer match the recorded intent: "
               + " · ".join(drift) + ". A self-installed add-in reads the message body through "
               "Office.js with no consent, no sign-in log and no Conditional Access, so this is "
               "the only place it shows up. Restore with Remove-ManagementRoleAssignment / "
               "Set-OrganizationConfig -AppsForOfficeEnabled $false.",
            ko="애드인 자가 설치 통제가 기록된 의도와 다릅니다: " + " · ".join(drift) +
               ". 자가 설치된 애드인은 **동의도 사인인 로그도 CA 도 없이** Office.js 로 메일 "
               "본문을 읽습니다 — 그래서 여기 말고는 드러나는 곳이 없습니다. 되돌리기: "
               "`Remove-ManagementRoleAssignment` · "
               "`Set-OrganizationConfig -AppsForOfficeEnabled $false`. "
               "⛔ Word/Excel 은 이 축이 아닙니다 — config.office.com 입니다."))
