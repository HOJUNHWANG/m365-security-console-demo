"""Email threat hunting - detailed analysis over the last 7 days via Defender Advanced Hunting (KQL).

Queries EmailEvents / UrlClickEvents / EmailPostDeliveryEvents. Requires ThreatHunting.Read.All.
Queries run concurrently; a transient failure (5xx) on some of them yields a partial result, while
a 403 propagates as a permission error.

Delivered threats are classified three ways: allowlisted (allow), own-domain spoofing (spoof),
and external. The allowlist and own-domain list are auto-synced from the EXO snapshot (anti-spam
allowlist + spoofing rule exceptions + AcceptedDomain), falling back to the .env HUNT_* values
when no snapshot exists.
Note: detailed results (subjects, addresses, URLs - i.e. PII) are for dashboard display only and
are never sent to the AI summary.
"""
import asyncio

from ..config import settings
from ..graph_client import graph_post
from . import exchange_eop

D7 = "Timestamp > ago(7d)"


def _set(v):
    return {x.strip().lower() for x in (v or "").split(",") if x.strip()}


def _norm(lst):
    return {str(x).strip().lower() for x in (lst or []) if str(x).strip()}


def _kqlist(s):
    return ",".join(f"'{x}'" for x in sorted(s))


def _resolve_allowlist():
    """Union of the auto-synced EXO snapshot allowlist and the .env HUNT_* values.

    Auto-sync is the primary source; .env supplements anything auto-extraction misses.
    """
    e_own = _set(settings.hunt_own_domains)
    e_ad = _set(settings.hunt_allowlist_domains)
    e_as = _set(settings.hunt_allowlist_senders)
    e_q = _set(settings.hunt_quarantine_mailboxes)

    al = exchange_eop.read_allowlist()
    if al:
        return (
            e_own | _norm(al.get("ownDomains")),
            e_ad | _norm(al.get("allowDomains")),
            e_as | _norm(al.get("allowSenders")),
            e_q | _norm(al.get("quarantineMailboxes")),
            "auto+env",
        )
    return (e_own, e_ad, e_as, e_q, "env")


async def _run(q: str) -> list[dict]:
    res = await graph_post("/security/runHuntingQuery", {"Query": q})
    return res.get("results", [])


async def fetch() -> dict:
    own, allow_dom, allow_snd, quar, source = _resolve_allowlist()

    excl = f"| where RecipientEmailAddress !in~ ({_kqlist(quar)}) " if quar else ""
    allow_parts = []
    if allow_snd:
        allow_parts.append(f"SenderFromAddress !in~ ({_kqlist(allow_snd)})")
    if allow_dom:
        allow_parts.append(f"SenderFromDomain !in~ ({_kqlist(allow_dom)})")
    allow_excl = ("| where " + " and ".join(allow_parts) + " ") if allow_parts else ""

    queries = {
        "byType": f"EmailEvents | where {D7} | where ThreatTypes != '' | summarize Count=count() by ThreatTypes | top 12 by Count",
        "byAction": f"EmailEvents | where {D7} | where ThreatTypes != '' | summarize Count=count() by DeliveryAction | top 10 by Count",
        "delivered": f"EmailEvents | where {D7} | where ThreatTypes != '' | where DeliveryAction == 'Delivered' | project Timestamp, NetworkMessageId, SenderFromAddress, SenderFromDomain, RecipientEmailAddress, Subject, ThreatTypes, DeliveryLocation | top 300 by Timestamp",
        "deliveredSenders": f"EmailEvents | where {D7} | where ThreatTypes != '' | where DeliveryAction == 'Delivered' | summarize Count=count() by SenderFromAddress, SenderFromDomain | top 200 by Count",
        "senders": f"EmailEvents | where {D7} | where ThreatTypes has 'Phish' {allow_excl}| summarize Count=count() by SenderFromDomain | top 10 by Count",
        "recipients": f"EmailEvents | where {D7} | where ThreatTypes has_any('Phish','Malware') {excl}{allow_excl}| summarize Count=count() by RecipientEmailAddress | top 10 by Count",
        "clicks": f"UrlClickEvents | where {D7} | summarize Count=count() by ActionType | top 10 by Count",
        "riskyClicks": f"UrlClickEvents | where {D7} | where ActionType != 'ClickAllowed' or IsClickedThrough == true | project Timestamp, AccountUpn, Url, ActionType, IsClickedThrough, NetworkMessageId | top 25 by Timestamp",
        "trend": f"EmailEvents | where {D7} | where ThreatTypes has_any('Phish','Malware','Spam') | summarize Count=count() by bin(Timestamp, 1d) | order by Timestamp asc",
        "zap": f"EmailPostDeliveryEvents | where {D7} | summarize Count=count() by ActionType | top 20 by Count",
    }

    def categorize(sender, domain):
        s, d = (sender or "").lower(), (domain or "").lower()
        if s in allow_snd or d in allow_dom:
            return "allow"
        if d in own:
            return "spoof"
        return "external"

    names = list(queries)
    results = await asyncio.gather(*[_run(queries[n]) for n in names], return_exceptions=True)
    raw, partial = {}, False
    for n, r in zip(names, results):
        if isinstance(r, PermissionError):
            raise PermissionError("runHuntingQuery")
        if isinstance(r, Exception):
            partial = True
            raw[n] = []
        else:
            raw[n] = r

    def g(n):
        return raw.get(n, [])

    cat = {"allow": 0, "spoof": 0, "external": 0}
    for r in g("deliveredSenders"):
        cat[categorize(r.get("SenderFromAddress"), r.get("SenderFromDomain"))] += r.get("Count", 0)

    zap = g("zap")
    zap_total = sum(r.get("Count", 0) for r in zap if "ZAP" in (r.get("ActionType") or ""))

    return {
        "available": True,
        "partial": partial,
        "allowlistSource": source,
        # Pre-fills the Cc on the recipient-notification draft. The draft is built and opened in
        # the operator's own mail client - this app holds no send permission and must never hold
        # one, since it is internet-exposed and app-only Mail.Send would let a site compromise
        # send as anyone in the tenant.
        "notifyCc": settings.threat_notify_cc,
        "spoofDelivered": cat["spoof"],
        "externalDelivered": cat["external"],
        "allowDelivered": cat["allow"],
        "zapTotal": zap_total,
        "zap": [{"action": r.get("ActionType") or "Other", "count": r.get("Count", 0)} for r in zap],
        "byType": [{"type": r.get("ThreatTypes") or "Other", "count": r.get("Count", 0)} for r in g("byType")],
        "byAction": [{"action": r.get("DeliveryAction") or "Other", "count": r.get("Count", 0)} for r in g("byAction")],
        "delivered": [
            {
                "time": r.get("Timestamp"), "sender": r.get("SenderFromAddress"),
                "recipient": r.get("RecipientEmailAddress"), "subject": r.get("Subject"),
                "threat": r.get("ThreatTypes"), "location": r.get("DeliveryLocation"),
                "cat": categorize(r.get("SenderFromAddress"), r.get("SenderFromDomain")),
                # For pivoting into the Defender portal - this GUID identifies the message
                # in Advanced Hunting and on the Email entity page.
                "msgId": r.get("NetworkMessageId"),
            }
            for r in g("delivered")
        ],
        "senders": [{"domain": r.get("SenderFromDomain") or "(unknown)", "count": r.get("Count", 0)} for r in g("senders")],
        "recipients": [{"recipient": r.get("RecipientEmailAddress") or "(unknown)", "count": r.get("Count", 0)} for r in g("recipients")],
        "urlClicks": [{"action": r.get("ActionType") or "Other", "count": r.get("Count", 0)} for r in g("clicks")],
        "riskyClicks": [
            {
                "time": r.get("Timestamp"), "user": r.get("AccountUpn"), "url": r.get("Url"),
                "action": r.get("ActionType"), "through": r.get("IsClickedThrough"),
                "msgId": r.get("NetworkMessageId"),
            }
            for r in g("riskyClicks")
        ],
        "trend": [{"date": r.get("Timestamp"), "count": r.get("Count", 0)} for r in g("trend")],
    }
