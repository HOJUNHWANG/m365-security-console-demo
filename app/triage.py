import os

DEVICE = "DEVICE"
DEVICE_UNKNOWN = "DEVICE_UNKNOWN"
CLIENT = "CLIENT"
OK = "OK"
PERSONAL = "PERSONAL"

TAG_VALUE = os.environ.get("DEVICE_TAG_VALUE", "Approved-Device")
TAG_ATTRIBUTE = "extensionAttribute1"


def device_health(obj):
    if not obj:
        return None
    tag = (obj.get("extensionAttributes") or {}).get(TAG_ATTRIBUTE)
    return {
        "name": obj.get("displayName"),
        "isManaged": obj.get("isManaged"),
        "isCompliant": obj.get("isCompliant"),
        "tagged": tag == TAG_VALUE,
        "tag": tag,
        "trustType": obj.get("trustType"),
    }


def failing_fields(health):
    if not health:
        return ["기기 객체를 못 찾음"]
    bad = []
    if health.get("isManaged") is not True:
        bad.append(f"isManaged={health.get('isManaged')!r} (Intune 관리 아님)")
    if health.get("isCompliant") is not True:
        bad.append(f"isCompliant={health.get('isCompliant')!r} (CA 가 읽는 준수 상태 — "
                   f"Intune 화면의 compliant 와 다른 값입니다)")
    if not health.get("tagged"):
        bad.append(f"tag={health.get('tag')!r} (승인 태그 없음)")
    return bad


EXTENSION_ID = "ppnbnpeolgkicgegkbkbjmhlideopiji"


def client_family(name):
    n = (name or "").lower()
    if any(k in n for k in ("mobile", "android", "ios", "iphone", "ipad", "safari")):
        return "mobile"
    if n.startswith("edge 18.") or "18.26200" in n:
        return "broker"
    if "edg" in n:
        return "edge"
    if "chrome" in n:
        return "chrome"
    if n.startswith("ie ") or "internet explorer" in n or n.startswith("msie"):
        return "legacy"
    return "other"


_ADVICE = {
    ("edge", "never"): (
        "작업 프로필로 접속한 적이 한 번도 없습니다",
        "Edge 우상단 프로필 아이콘 → 회사 계정 추가 → 그 창에서 회사 사이트를 여십시오. "
        "확장 설치 필요 없습니다 (30초)"),
    ("edge", "sometimes"): (
        "작업 프로필은 되는데 개인 프로필로도 접속하고 있습니다",
        "작업 프로필을 기본으로 두거나, 회사 사이트는 작업 프로필 창에서만 여십시오. "
        "★ 로그에서는 두 프로필이 똑같이 'Edge' 로 보입니다 — 기기 고장이 아닙니다"),
    ("chrome", "never"): (
        "확장이 없거나 꺼져 있습니다",
        f"chrome://extensions → Microsoft Single Sign On ({EXTENSION_ID}) 설치·활성화 → "
        "★ 반드시 로그아웃 후 재로그인 (세션이 살아 있으면 안 붙습니다). 시크릿 모드로 확인 금지"),
    ("chrome", "sometimes"): (
        "확장이 붙긴 하는데 매번은 아닙니다",
        "chrome://extensions 에서 켜져 있는지 확인 → 로그아웃 후 재로그인. "
        "Chrome 업데이트가 확장을 조용히 되돌리는 경우가 있습니다"),
    ("legacy", "never"): (
        "IE 는 기기 클레임을 실을 방법이 없습니다",
        "쓰지 마십시오. Edge 작업 프로필로 대체하십시오"),
    ("legacy", "sometimes"): (
        "IE 는 기기 클레임을 실을 방법이 없습니다",
        "쓰지 마십시오. Edge 작업 프로필로 대체하십시오"),
    ("broker", "never"): (
        "데스크톱 앱(Outlook·Teams) 인증이 클레임을 못 싣습니다",
        "사용자가 브라우저로 고칠 수 있는 부분이 아닙니다 — 기기 쪽을 보십시오"),
    ("broker", "sometimes"): (
        "데스크톱 앱 인증이 가끔 클레임을 못 싣습니다",
        "앱 재시작 후 재현되는지 확인. 계속되면 기기 쪽입니다"),
    ("mobile", "never"): (
        "휴대폰입니다 — device CA 범위(windows·macOS) 밖입니다",
        "차단이 아닙니다. 조치 불필요"),
    ("mobile", "sometimes"): (
        "휴대폰입니다 — device CA 범위 밖입니다",
        "차단이 아닙니다. 조치 불필요"),
    ("other", "never"): (
        "이 클라이언트는 클레임을 실은 적이 없습니다",
        "Edge 작업 프로필로 접속하게 하십시오"),
    ("other", "sometimes"): (
        "이 클라이언트가 가끔 클레임을 못 싣습니다",
        "Edge 작업 프로필로 접속하게 하십시오"),
}


def client_rows(clients):
    rows = []
    for name, t in (clients or {}).items():
        claim, noclaim = t.get("claim", 0), t.get("noclaim", 0)
        if not noclaim:
            state = "ok"
        elif claim:
            state = "sometimes"
        else:
            state = "never"
        fam = client_family(name)
        last_c, last_n = t.get("lastClaim") or "", t.get("lastNoClaim") or ""
        working = None
        if last_c or last_n:
            working = bool(last_c) and last_c > last_n
        if state == "ok":
            cause, action = "정상 — 이 클라이언트는 매번 클레임을 싣습니다", ""
        else:
            cause, action = _ADVICE[(fam, state)]
        rows.append({"client": name, "family": fam, "claim": claim, "noclaim": noclaim,
                     "state": state, "lastClaim": last_c, "lastNoClaim": last_n,
                     "working": working, "cause": cause, "action": action,
                     "actionable": state != "ok" and fam in ("edge", "chrome", "legacy", "other")})
    rows.sort(key=lambda r: (not r["actionable"], -r["noclaim"]))
    return rows


def classify(health, clients, personal=None):
    noclaim = sum(c.get("noclaim", 0) for c in clients.values())
    claim = sum(c.get("claim", 0) for c in clients.values())

    if not noclaim:
        return (OK, "클레임 없는 사인인이 없습니다 — 차단 원인이 다른 데 있습니다.",
                ["정책 판정을 직접 보십시오: 대시보드 CA › Evaluation 첫 패널",
                 "오류 코드가 53003/53000 이 아니면 device CA 가 막은 것이 아닙니다"])

    personal = [str(p) for p in (personal or []) if p]

    if health is None and personal:
        shown = ", ".join(personal[:5]) + (" …" if len(personal) > 5 else "")
        return (PERSONAL,
                "이 사람의 회사(Intune) 기기가 이 창의 클레임에 없습니다 — Intune 재고에 "
                "없는 객체만 있었습니다. 기기 고장은 아니지만 **둘 중 무엇인지 확인이 "
                "필요합니다.**",
                [f"클레임에 등장한 비관리 객체: {shown}",
                 "① 개인 기기로 접속한 경우 → 범위 외입니다. 회사 기기로 접속하게 안내하고,",
                 "   그쪽에서도 막히면 그때 다시 판정하십시오.",
                 "② ⚠ 이름이 회사 기기 명명 규칙을 따르면 **본인 회사 기기의 낡은 객체**일",
                 "   수 있습니다. 재등록은 새 객체를 만들고 옛 객체는 비관리로 남습니다.",
                 "   그 경우 진짜 문제는 'Intune 등록이 끊겼다' 이고 범위 외가 아닙니다.",
                 "   → scripts/support.py <upn> · scripts/check_device_identity.py 로 가리십시오",
                 "⛔ 어느 쪽이든 임시 CA 제외로 풀지 마십시오. ①이면 '개인 기기를 통과시킨다'",
                 "   는 결정이고, ②면 등록을 안 고치고 덮는 것입니다. 제외는 그 사람의 device",
                 "   정책 둘을 모든 브라우저·모든 앱에서 없앱니다."])

    if health is None:
        return (DEVICE_UNKNOWN,
                "이 창에서 어떤 사인인도 기기를 지목하지 못했습니다 — 기기를 볼 수가 없습니다.",
                ["먼저 등록 자체가 있는지 확인: scripts/support.py <upn>",
                 "기기에서 dsregcmd /status → WorkplaceJoined · WorkAccountCount · WorkplaceDeviceId",
                 "⛔ AzureAdPrt 는 보지 마십시오 — 이 함대는 registered 라 정상값이 NO 입니다",
                 "등록이 있는데도 클레임이 0이면 그때 재등록입니다"])

    bad = failing_fields(health)
    if bad:
        return (DEVICE,
                "기기 문제입니다 — CA 가 읽는 객체가 통과할 수 없는 상태입니다.",
                [f"막고 있는 값: {b}" for b in bad] + [
                    "★ 브라우저 안내(확장·프로필·Edge 전환)는 이 상태에서 절대 통하지 않습니다.",
                    "isCompliant 만 어긋났다면 Company Portal 동기화 1회 — 단 몇 번을 눌러도",
                    "  게시가 안 되면 그 경로는 죽은 것이고, 반복해서 시키지 마십시오.",
                    "** 임시 CA 제외가 정당한 경우입니다. 기한을 반드시 적으십시오. **"])

    rows = client_rows(clients)
    todo = [r for r in rows if r["actionable"]]
    actions = []
    for i, r in enumerate(todo, 1):
        if r["working"] is True:
            actions.append(f"{i}. {r['client']}  ✅ 지금은 붙습니다 (마지막 시도가 성공) — 조치 불필요")
            continue
        actions.append(f"{i}. {r['client']}  ⛔ {r['cause']}")
        actions.append(f"   → {r['action']}")
    if not todo:
        actions.append("사용자가 고칠 수 있는 클라이언트가 없습니다 — 정책 판정을 직접 보십시오:")
        actions.append("   대시보드 CA › Evaluation 첫 패널 (Blocked by Device CA)")
    ignored = [r for r in rows if not r["actionable"] and r["state"] != "ok"]
    if ignored:
        actions.append("· 조치 대상 아님: " + ", ".join(
            f"{r['client']} ({r['cause']})" for r in ignored))
    if personal:
        shown = ", ".join(personal[:5]) + (" …" if len(personal) > 5 else "")
        actions.append(f"· ⚠ Intune 재고에 없는 객체도 클레임에 있었습니다: {shown}")
        actions.append("   막힌 사인인이 그쪽에서 온 것이면 브라우저를 고쳐도 안 풀립니다 —")
        actions.append("   먼저 '회사 기기에서도 막히나요?' 를 물어보십시오. 로그로는 안 갈립니다.")
        actions.append("   (이름이 함대 규칙이면 본인 기기의 낡은 재등록 객체일 수 있습니다 — 17.1)")
    return (CLIENT,
            f"기기는 정상입니다 (isManaged·isCompliant·태그 전부 정상). "
            f"클라이언트 문제입니다 — 클레임 없는 사인인 {noclaim}건 / 있는 사인인 {claim}건.",
            actions)
