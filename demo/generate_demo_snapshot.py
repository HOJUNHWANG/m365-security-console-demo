"""Generate the synthetic snapshot the static demo renders from.

Why generate instead of masking a real one
------------------------------------------
A real snapshot of this dashboard holds roughly 300 unique UPNs, 200 object ids, device names,
source IPs and mail subjects spread over 21 sources and ~800 distinct JSON paths. Masking that
means finding every one of them, and a single missed field is a disclosure you cannot prove you
avoided - "I think I got them all" is not a security control.

So this script reads a real snapshot for its SHAPE only - the keys, the types, the list lengths -
and generates every leaf value from scratch. The verifier (`demo/verify_demo.py`) then proves the
result: no string in the output may exist outside an allowlist that this file and the application's
own source code define. That is a claim a machine can check, which is the whole point.

The input snapshot is NOT part of this repository and never will be. Run this only where one
exists; the generated output is committed so the demo works without it.

    python demo/generate_demo_snapshot.py \
        --snapshot ../ms365-security-dashboard/data/graph_snapshot.json \
        --history  ../ms365-security-dashboard/data/graph_history.json \
        --out      app/static/demo-summary.json

Value selection, in priority order:

  1. an authored override for that JSON path          (drives what the UI branches on)
  2. an identifier class matched by regex             (UPN / id / IP / host / timestamp)
  3. verbatim passthrough IF the exact string is a literal in the app's own source, which makes it
     product vocabulary the UI compares against ("compliant", "reportOnlyFailure") rather than
     anything about a tenant
  4. a generated label derived from the path          (never from the real value)

Numbers are jittered rather than reused, because counts ARE the security posture: "4 global admins,
9 of 11 unencrypted" is exactly what must not travel. A small consistency pass then re-derives the
totals that the UI shows next to a list, so the demo does not claim 11 devices above a table of 14.
"""
from __future__ import annotations

import argparse
import json
import pathlib
import random
import re
import sys
from datetime import datetime, timedelta, timezone

# --------------------------------------------------------------------------------------------
# Identifier classes. Anything matching these is replaced structurally, never passed through.
# --------------------------------------------------------------------------------------------
RE_UPN = re.compile(r"^[A-Za-z0-9._%+'-]+(#EXT#)?@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
RE_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
RE_IP = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
RE_IP6 = re.compile(r"^[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}$")
RE_NUMID = re.compile(r"^\d{2,10}$")
RE_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}(T[\d:.]+([+-]\d{2}:?\d{2}|Z)?)?$")
RE_HOST = re.compile(r"^(?:WIN|BOOK|DESKTOP|LAPTOP|PC|NB)[-_][A-Z0-9]{4,}$|^[A-Z]{3,}[0-9]{2,}$")
RE_THUMB = re.compile(r"^[0-9A-Fa-f]{40}$")
RE_LONGHEX = re.compile(r"^[0-9A-Za-z_-]{22,}={0,2}$")   # NetworkMessageId, extension ids, tokens

# Documentation ranges (RFC 5737) and Microsoft's canonical example tenant. Recognisable as fake.
DOMAIN = "contoso.com"
TENANT = "contoso.onmicrosoft.com"
IP_POOL = [f"203.0.113.{n}" for n in range(11, 60)] + \
          [f"198.51.100.{n}" for n in range(11, 60)] + \
          [f"192.0.2.{n}" for n in range(11, 60)]

FIRST = ["ada", "grace", "alan", "edsger", "barbara", "linus", "margaret", "dennis", "ken",
         "radia", "leslie", "donald", "frances", "tim", "vint", "katherine", "jean", "bjarne",
         "anita", "shafi", "james", "sophie", "mateo", "yuki", "omar", "priya", "lucas", "nadia",
         "hugo", "ingrid", "pablo", "elena", "noah", "mila", "theo", "ravi", "clara", "felix",
         "iris", "otto"]
LAST = ["lovelace", "hopper", "turing", "dijkstra", "liskov", "torvalds", "hamilton", "ritchie",
         "thompson", "perlman", "lamport", "knuth", "allen", "berners", "cerf", "johnson",
         "bartik", "stroustrup", "borg", "goldwasser", "gosling", "moreau", "silva", "tanaka",
         "haddad", "nair", "ferreira", "petrova", "martin", "olsen", "reyes", "novak", "weber",
         "kovac", "lindqvist", "menon", "duarte", "brandt", "sorensen", "keller"]

ROOMS = ["conf-atrium", "conf-harbor", "conf-summit", "reception-kiosk", "lobby-display",
         "warehouse-scanner", "training-room"]

# --------------------------------------------------------------------------------------------
# Authored value pools for paths the UI branches on or renders prominently. Everything here is
# public product vocabulary (Microsoft platform terms) or plainly-fake labels - no tenant facts.
# A path is written the way the walker names it: dots for keys, [] for a list element.
# --------------------------------------------------------------------------------------------
BROWSERS = ["Edge 151", "Chrome 151", "Chrome 150", "Firefox 134", "Safari 18",
            "Internet Explorer 11", "Edge 18"]
EDITIONS = ["Windows 11 Pro", "Windows 11 Home", "Windows 11 Enterprise"]
CITIES = ["Seattle, US", "Dublin, IE", "Singapore, SG", "Frankfurt, DE", "Toronto, CA",
          "Seoul, KR", "Sao Paulo, BR"]
MS_APPS = ["Microsoft Azure Portal", "Microsoft 365 Admin Center", "Microsoft Teams",
           "Office 365 Exchange Online", "Microsoft Intune Enrollment", "SharePoint Online",
           "Microsoft Intune Company Portal", "OfficeHome", "Microsoft Authentication Broker"]
CA_POLICIES = ["CA01 - Require MFA for all users", "CA02 - Require MFA for admins",
               "CA03 - Block legacy authentication", "CA04 - Require compliant device",
               "CA05 - Approved device filter", "CA06 - Token protection (Windows)"]
ROLES = ["Global Administrator", "Global Reader", "Exchange Administrator",
         "Intune Administrator", "Security Administrator", "User Administrator",
         "Directory Readers", "Conditional Access Administrator"]
INCIDENTS = ["Suspicious inbox manipulation rule", "Multi-stage phishing campaign",
             "Impossible travel sign-in", "Malware delivered to mailbox",
             "Anonymous sharing link created on sensitive site", "Password spray attempt"]
SUBJECTS = ["Invoice 40218 overdue - action required", "Your mailbox storage is almost full",
            "Shared document: Q3 forecast.xlsx", "Payroll update - confirm your details",
            "Delivery failed: parcel 8842019", "Urgent: verify your account"]
GROUPS = ["SG-All-Employees", "SG-CA-Exclusions-BreakGlass", "SG-Pilot-Wave1",
          "SG-Room-Accounts", "SG-Managed-Devices"]
SITES = ["/sites/marketing", "/sites/projects", "/sites/hr-public", "/sites/vendor-exchange",
         "/personal/demo_user_contoso_com"]

CA_CONTROLS = ["mfa", "compliantDevice", "block", "passwordChange", "AppTokenProtection",
               "SignInTokenProtection", "domainJoinedDevice"]
DEVICE_CLAIMS = ["Windows11 · compliant", "Windows11 · unmanaged", "Windows10 · compliant",
                 "(no device claim)", "iOS · compliant"]
SEVERITIES = ["high", "medium", "low", "informational"]
OS_VERSIONS = ["10.0.26100.3194", "10.0.26200.8875", "10.0.22631.4460", "18.1.1"]
MODELS = ["ThinkPad E14 Gen 5", "Latitude 5450", "Pavilion 15-eh", "Galaxy Book4",
          "Surface Laptop 6", "OptiPlex 7010"]
ENROLL_TYPES = ["userEnrollment", "windowsAzureADJoin", "deviceEnrollmentManager",
                "windowsCoManagement"]
MAIL_LOCATIONS = ["Inbox", "Inbox/folder", "Junk Email", "Quarantine", "Deleted Items"]
SENDER_DOMAINS = ["mail-delivery.example", "invoice-portal.example", "shared-docs.example",
                  "secure-notice.example", "parcel-track.example"]
TRANSPORT_RULES = ["Inbound external banner", "Redirect failed authentication",
                   "Block executable attachments", "Bypass filtering for partner"]
SIMULATIONS = ["Credential harvest - company-wide awareness",
               "Phishing drill - finance team", "Link in attachment - quarterly test",
               "Malware attachment - onboarding cohort"]
# Public Microsoft Secure Score improvement-action titles.
SECURE_SCORE_ACTIONS = [
    "Ensure multifactor authentication is enabled for all users",
    "Block legacy authentication protocols",
    "Require devices to be marked as compliant",
    "Turn on Safe Attachments in block mode",
    "Enable self-service password reset",
    "Do not allow users to grant consent to unmanaged applications",
    "Ensure all users can complete multifactor authentication",
]
AUDIT_ACTIVITIES = ["Add member to role", "Update device", "Update user", "Update policy",
                    "Consent to application", "Add owner to application", "Delete device",
                    "Add app role assignment grant to user", "Reset user password"]
# Public Entra sign-in failure descriptions.
SIGNIN_ERRORS = [
    "Invalid username or password",
    "MFA required — not completed",
    "MFA authentication failed or timed out",
    "Blocked by Conditional Access policy",
    "Account is locked",
    "User account is disabled",
    "Interrupted — 'Keep me signed in'",
]
DEVICE_PROBLEMS = [
    "the object it signs in with is NOT tagged - device-filter policies will block it",
    "two Entra objects exist for this device; Intune points at the one it does not sign in with",
    "enrolled and compliant in Intune, but the Entra object carries no compliance state",
    "no device claim landed in the window, so the verdict comes from the registered object",
]
EOP_POLICY_NAMES = ["Default", "Standard Preset Security Policy", "Strict Preset Security Policy",
                    "Office365 AntiPhish Default"]
TRUST_TYPES = ["Workplace", "AzureAd", "(none)"]
GRAPH_ENDPOINTS = ["/auditLogs/signIns", "/deviceManagement/managedDevices", "/devices",
                   "/identity/conditionalAccess/policies", "/security/secureScores",
                   "/subscribedSkus", "/users", "/security/alerts_v2", "/security/incidents",
                   "/reports/authenticationMethods", "/roleManagement/directory/roleAssignments"]
# The AI summary sits at the top of the Overview tab, so a generated placeholder would be the first
# thing a visitor reads. Written to describe THIS synthetic tenant, in the register the real prompt
# produces: what changed, what to do first, what is only a reporting artefact.
AI_SUMMARY = (
    "Posture is improving but two items need attention before the next Conditional Access change. "
    "MFA registration has risen steadily over the window and the secure score trend is positive, "
    "so the identity baseline is holding. The open risks are elsewhere: a device-dependent policy "
    "is still in report-only while a share of Windows sign-ins arrive without a device claim, and "
    "those sign-ins would be blocked on enforcement even though the devices are enrolled and "
    "compliant - a browser-SSO gap rather than a real compliance failure. Anonymous sharing links "
    "remain on two sites whose sharing ceiling still permits them. Priority: resolve the missing "
    "device claims, then re-read the report-only impact panel before enforcing. Note that a share "
    "of the report-only block count is a reporting artefact of device-based evaluation, so treat it "
    "as an upper bound, not a forecast of lockouts."
)
FINDING_TEXT = [
    "A device-dependent policy is in scope for platforms where no device claim is available.",
    "Anonymous links exist on a site whose sharing ceiling still allows them.",
    "The extension is not proven installed for every account in the pilot group.",
    "Sharing defaults allow anonymous links tenant-wide, so a new site inherits them.",
]
REACH_WHY = [
    "in scope: included by an all-users assignment with no exclusion for this account",
    "in scope: a member of an included group, and the policy carries a blocking grant",
    "out of scope: the policy applies only to legacy client types",
]

OVERRIDES: dict[str, list] = {
    # --- device / OS vocabulary -------------------------------------------------------------
    "browserClaims.byBrowser[].browser": BROWSERS,
    "browserClaims.users[].browsers[].browser": BROWSERS,
    "browserClaims.users[].editions[]": EDITIONS,
    "browserClaims.extensionName": ["Windows Accounts"],
    "browserClaims.pilotGroup": ["CA-Pilot-Users"],
    "browserClaims.scopePlatforms[]": ["windows"],
    "browserClaims.scopePolicies[]": CA_POLICIES[3:6],
    "intuneDevices.byOs": None,          # dict keyed by OS name - handled by KEY_POOLS
    "intuneDevices.devices[].os": ["Windows"],
    "intuneDevices.devices[].edition": EDITIONS,
    "deviceIdentity.tag": ["Approved-Device"],
    # --- locations, apps, policies ----------------------------------------------------------
    "riskySignins.recentFailures[].location": CITIES,
    "riskySignins.caReportOnlyImpact[].location": CITIES,
    "riskySignins.caFailures[].location": CITIES,
    "riskySignins.recentFailures[].app": MS_APPS,
    "riskySignins.caReportOnlyImpact[].app": MS_APPS,
    "riskySignins.caFailures[].app": MS_APPS,
    "riskySignins.nonInteractive.accounts[].apps[]": MS_APPS,
    "browserClaims.users[].browsers[].apps[]": MS_APPS,
    "entraAccess.caPolicies[].name": CA_POLICIES,
    "riskySignins.caPolicyEval[].policy": CA_POLICIES,
    "riskySignins.caFailByPolicy": None,
    "unattendedAccounts.policies[].name": CA_POLICIES,
    # --- identity -------------------------------------------------------------------------
    "adminAccounts.privileged[].role": ROLES,
    "adminAccounts.readPrivileged[].role": ROLES,
    "adminAccounts.otherRoles[].role": ROLES,
    "adminAccounts.servicePrincipalRoles[].role": ROLES,
    "adminAccounts.topAccounts[].roles[]": ROLES,
    # --- threats ---------------------------------------------------------------------------
    "securityIncidents.incidents[].title": INCIDENTS,
    "securityAlerts.alerts[].title": INCIDENTS,
    "threatHunting.delivered[].subject": SUBJECTS,
    "threatHunting.riskyClicks[].subject": SUBJECTS,
    "threatHunting.urlClicks[].subject": SUBJECTS,
    # --- sharing ---------------------------------------------------------------------------
    "sharingLinks.sites[].path": SITES,
    "sharingLinks.links[].site": SITES,
    "sharepointSharing.newSites[].url": SITES,
    "sharingLinks.newSites[].url": SITES,
    "sharingLinks.newSites[].name": ["Marketing", "Projects", "HR Public", "Vendor Exchange"],

    # --- Conditional Access evaluation ------------------------------------------------------
    "riskySignins.caReportOnlyImpact[].controls[]": CA_CONTROLS,
    "riskySignins.caReportOnlyImpact[].policies[]": CA_POLICIES,
    "riskySignins.caFailures[].controls[]": CA_CONTROLS,
    "riskySignins.caFailures[].policies[]": CA_POLICIES,
    "riskySignins.caPolicyEval[].controls[]": CA_CONTROLS,
    "riskySignins.caReportOnlyImpact[].device": DEVICE_CLAIMS,
    "riskySignins.caFailures[].device": DEVICE_CLAIMS,
    "entraAccess.caPolicies[].users": ["All users", "1 group", "2 groups, 1 excluded",
                                       "3 groups, 2 excluded"],
    "entraAccess.caPolicies[].operator": ["OR", "AND"],
    "entraAccess.caPolicies[].sessionControls[]": ["secureSignInSession", "signInFrequency",
                                                   "persistentBrowser"],
    "unattendedAccounts.policies[].reachWhy": REACH_WHY,
    "unattendedAccounts.findings[].reachWhy": REACH_WHY,

    # --- sign-in failure reasons (public Entra error text) ----------------------------------
    "riskySignins.recentFailures[].error": SIGNIN_ERRORS,
    "riskySignins.caFailures[].error": SIGNIN_ERRORS,
    "riskySignins.nonInteractive.accounts[].recentApps[]": MS_APPS,

    # --- device inventory -------------------------------------------------------------------
    "intuneDevices.devices[].osVersion": OS_VERSIONS,
    "intuneDevices.devices[].model": MODELS,
    "intuneDevices.devices[].manufacturer": ["Lenovo", "Dell Inc.", "HP", "Samsung", "Microsoft"],
    "deviceIdentity.devices[].enrollmentType": ENROLL_TYPES,
    "intuneDevices.devices[].enrollmentType": ENROLL_TYPES,
    "deviceIdentity.devices[].problems[]": DEVICE_PROBLEMS,
    "deviceIdentity.devices[].warnings[]": DEVICE_PROBLEMS,

    # --- threats -----------------------------------------------------------------------------
    "securityIncidents.incidents[].displayName": INCIDENTS,
    "securityAlerts.alerts[].displayName": INCIDENTS,
    "securityIncidents.incidents[].severity": SEVERITIES,
    "securityAlerts.alerts[].severity": SEVERITIES,
    "securityAlerts.alerts[].status": ["newAlert", "inProgress", "resolved"],
    "securityIncidents.incidents[].status": ["active", "inProgress", "resolved"],
    "attackSimulation.simulations[].displayName": SIMULATIONS,
    "attackSimulation.simulations[].status": ["completed", "running", "scheduled"],
    "attackSimulation.simulations[].attackType": ["credentialHarvest", "attachmentMalware",
                                                  "linkInAttachment", "linkToMalwareFile"],
    "threatHunting.delivered[].location": MAIL_LOCATIONS,
    "threatHunting.riskyClicks[].location": MAIL_LOCATIONS,
    "threatHunting.zap[].action": ["MovedToJunk", "MovedToQuarantine", "NoAction"],
    "threatHunting.byType[].type": ["Phish", "Malware", "Spam", "BulkMail"],
    "threatHunting.senders[].domain": SENDER_DOMAINS,
    "threatHunting.delivered[].senderDomain": SENDER_DOMAINS,

    # --- Exchange / EOP ----------------------------------------------------------------------
    "exchangeEop.delegations[].access": ["FullAccess", "SendAs", "SendOnBehalf"],
    "exchangeEop.transportRules[].name": TRANSPORT_RULES,
    "exchangeEop.transportRules[].description": [
        "Prepend an external-sender warning banner to inbound mail from outside the organisation.",
        "Redirect messages that fail sender authentication to the review mailbox.",
        "Block attachments with executable content for all recipients.",
    ],
    "exchangeEop.riskyRules[].rule": ["Move invoices", "Forward to personal", "Delete receipts",
                                      "Hide replies"],
    "exchangeEop.riskyRules[].actions[]": ["MoveToFolder", "ForwardTo", "DeleteMessage",
                                           "RedirectTo", "MarkAsRead"],
    "exchangeEop.riskyRules[].targets[]": ["archive@partner.example", "backup@mail.example",
                                           "RSS Subscriptions", "Deleted Items"],
    "exchangeEop.forwarding[].forwardingSmtpAddress": ["smtp:archive@partner.example",
                                                        "smtp:backup@mail.example"],
    "exchangeEop.forwarding[].forwardingAddress": ["archive@partner.example",
                                                    "backup@mail.example"],

    # --- posture / audit ---------------------------------------------------------------------
    "secureScoreActions.recommendations[].title": SECURE_SCORE_ACTIONS,
    "recentAudits.items[].activity": AUDIT_ACTIVITIES,
    "unattendedAccounts.findings[].name": ROOMS,
    "unattendedAccounts.accounts[].name": ROOMS,
    "unattendedAccounts.candidates[].name": ROOMS,
    "unattendedAccounts.findings[].policy": CA_POLICIES,
    "unattendedAccounts.policies[].policy": CA_POLICIES,

    # --- remaining named things -------------------------------------------------------------
    "accountSummary.guestList[].state": ["Accepted", "PendingAcceptance"],
    "licenses.skus[].sku": ["SPB", "THREAT_INTELLIGENCE", "POWER_BI_STANDARD",
                            "Microsoft_365_Copilot", "EXCHANGESTANDARD"],
    "exchangeEop.allowlist.allowDomains[]": ["partner.example", "affiliate.example"],
    "exchangeEop.allowlist.ownDomains[]": [DOMAIN, TENANT],
    "exchangeEop.quarantine.byType[].type": ["Phish", "Spam", "Malware", "HighConfPhish", "Bulk"],
    "riskySignins.caReportOnlyByControl[].control": CA_CONTROLS,
    "riskySignins.caFailByControl[].control": CA_CONTROLS,
    "exchangeEop.outboundForwarding[].Name": EOP_POLICY_NAMES,
    "exchangeEop.policies.malware[].Name": EOP_POLICY_NAMES,
    "exchangeEop.policies.contentFilter[].Name": EOP_POLICY_NAMES,
    "exchangeEop.policies.antiPhish[].Name": EOP_POLICY_NAMES,
    "exchangeEop.safeLinks[].Name": EOP_POLICY_NAMES,
    "exchangeEop.safeAttachments[].Name": EOP_POLICY_NAMES,
    "exchangeEop.policies.antiPhish[].PhishThresholdLevel": ["1", "2", "3"],
    "sharingLinks.scannedSites[]": SITES,
    "sharingLinks.configuredPaths[]": SITES,
    "entraAccess.caPolicies[].apps": ["All apps", "Office 365", "1 app selected",
                                      "2 apps selected"],
    "intuneDevices.compliancePolicies[].name": ["Windows baseline compliance",
                                                "Encryption required",
                                                "Minimum OS version"],
    "riskySignins.caFailByPolicy[].policy": CA_POLICIES,
    "deviceIdentity.devices[].signInTrustType": TRUST_TYPES,
    "deviceIdentity.devices[].intuneObjectTrustType": TRUST_TYPES,
    "deviceIdentity.multiAccountDevices[].device": None,      # HOST_PATHS handles it
    "intuneDevices.devices[].joinType": ["azureADRegistered", "azureADJoined"],
    "exchangeEop.policies.contentFilter[].SpamAction": ["MoveToJmf", "Quarantine"],
    "exchangeEop.safeAttachments[].Action": ["Block", "Replace", "DynamicDelivery"],
    "exchangeEop.errors[]": [
        "One mailbox scan retried after a dropped connection and then completed.",
    ],
    "threatHunting.notifyCc": [""],
    "sharingLinks.note": [
        "Per-site sharing capability is not exposed by Microsoft Graph, so this card enumerates the "
        "anonymous links that actually exist on the configured sites rather than reading a setting.",
    ],
    "_aiOverview.text": [AI_SUMMARY],
    # Public Microsoft Graph resource paths - API surface, not anything about a tenant.
    "_health.graph.endpoints[].endpoint": GRAPH_ENDPOINTS,
    "_health.graph.slowest[].endpoint": GRAPH_ENDPOINTS,
    "_health.graph.worstEndpoint": GRAPH_ENDPOINTS,
    "browserClaims.findings[].text": FINDING_TEXT,
    "sharepointSharing.findings[].text": FINDING_TEXT,
    "sharingLinks.findings[].text": FINDING_TEXT,
}

# Paths that always name a device, whatever the original string looked like.
HOST_PATHS = {
    "intuneDevices.devices[].name",
    "deviceIdentity.devices[].device",
    "browserClaims.users[].browsers[].devices[]",
    "browserClaims.users[].devices[]",
    "deviceIdentity.enrolledNotTagged[]",
    "deviceIdentity.taggedNotEnrolled[]",
    "deviceIdentity.multiAccountDevices[].device",
}

# Paths that name a person or a service principal. Which of the two is decided from the SHAPE of
# the original (an app name carries a platform word), never from its content.
PERSON_PATHS = {
    "adminAccounts.globalAdmins[].name",
    "adminAccounts.privileged[].members[].name",
    "adminAccounts.readPrivileged[].members[].name",
    "adminAccounts.otherRoles[].members[].name",
    "adminAccounts.topAccounts[].name",
    "adminAccounts.servicePrincipalRoles[].name",
    "accountSummary.guestList[].name",
    "recentAudits.items[].by",
    "exchangeEop.riskyRules[].mailboxOwner",
}
APP_HINTS = ("api", "microsoft", "portal", "client", "service", "app", "sync", "graph", "prod",
             "assist", "bot", "connector")
APP_NAMES = ["Microsoft Graph Command Line Tools", "Device Registration Service",
             "Intune Compliance Client", "Microsoft Approval Management",
             "Windows Configuration Designer", "Custom Reporting App", "Microsoft Teams Services"]

# Dicts whose KEYS are data rather than field names (a histogram keyed by browser, OS, policy...).
KEY_POOLS: dict[str, list] = {
    "intuneDevices.byOs": ["Windows", "iOS", "Android"],
    "intuneDevices.byOwnership": ["company", "personal"],
    "browserClaims.byBrowser": BROWSERS,
    "riskySignins.caFailByPolicy": CA_POLICIES,
    "riskySignins.caFailByControl": ["mfa", "compliantDevice", "block", "passwordChange"],
    "riskySignins.caReportOnlyByControl": ["mfa", "compliantDevice", "block"],
    "riskySignins.legacyByClient": ["IMAP4", "POP3", "SMTP Auth", "Exchange ActiveSync"],
    "riskySignins.caStatusCounts": ["success", "failure", "notApplied"],
    "exchangeEop.quarantineTrend": None,     # date-keyed: handled generically
}

# --------------------------------------------------------------------------------------------
# List lengths are data too. "4 global admins, 29 enrolled devices, 6 guests" is exactly the
# posture that must not travel, and it survives value-level masking untouched - the length of a
# list carries it even when every element inside is fake.
#
# So every list is resized by ONE shared factor rather than per-list jitter: sources that describe
# the same fleet from different angles (intuneDevices, deviceIdentity, browserClaims) then stay
# consistent with each other, which per-list randomness would destroy.
LIST_SCALE = 1.62
LIST_CAP = 60          # keeps the committed fixture small enough to serve as a static asset

# Lists whose length is a MEANING rather than a count: days in a window, configured collection
# times, platforms in scope. Scaling these would contradict the numbers printed beside them.
FIXED_LENGTH_PATHS = {
    "riskySignins.failedByDay",
    "riskySignins.nonInteractive.byDay",
    "exchangeEop.collectTimes",
    "exchangeEop.quarantineTrend",
    "browserClaims.scopePlatforms",
    "secureScore.trend",
    "_history",
}

# Totals the UI prints next to a list. Re-derived after generation so the two agree.
# path of the number  ->  path of the list it counts
DERIVED_TOTALS = {
    "intuneDevices.total": "intuneDevices.devices",
    "adminAccounts.globalAdminCount": "adminAccounts.globalAdmins",
    "accountSummary.guests": "accountSummary.guestList",
    "entraAccess.caPolicyCount": "entraAccess.caPolicies",
    "securityIncidents.activeCount": "securityIncidents.incidents",
    "securityAlerts.activeCount": "securityAlerts.alerts",
    "sharingLinks.anonymousLinkCount": "sharingLinks.links",
    "deviceIdentity.enrolled": "deviceIdentity.devices",
}


class Gen:
    def __init__(self, vocab: set[str], base: datetime):
        self.vocab = vocab
        self.base = base
        self.rng = random.Random(20260813)      # fixed: reruns produce the same file
        self.upns: dict[str, str] = {}
        self.ids: dict[str, str] = {}
        self.hosts: dict[str, str] = {}
        self.ips: dict[str, str] = {}
        self.fallbacks: dict[str, int] = {}
        self.passthrough: set[str] = set()
        self._n = 0

    # -- identifier synthesis. Consistent per input, so cross-references stay coherent: the same
    # -- person referenced by two sources gets the same fake UPN in both.
    def upn(self, real: str) -> str:
        if real not in self.upns:
            i = len(self.upns)
            f, l = FIRST[i % len(FIRST)], LAST[(i // len(FIRST) + i) % len(LAST)]
            if "#EXT#" in real:
                self.upns[real] = f"{f}.{l}_partner.example#EXT#@{TENANT}"
            elif any(r in real.lower() for r in ("room", "conf", "kiosk", "scan", "display")):
                self.upns[real] = f"{ROOMS[i % len(ROOMS)]}@{DOMAIN}"
            else:
                self.upns[real] = f"{f}.{l}@{DOMAIN}"
        return self.upns[real]

    def gid(self, real: str) -> str:
        if real not in self.ids:
            n = len(self.ids) + 1
            self.ids[real] = f"{n:08x}-1111-4222-8333-{n:012x}"
        return self.ids[real]

    def host(self, real: str) -> str:
        if real not in self.hosts:
            n = len(self.hosts) + 1
            self.hosts[real] = f"LAPTOP-DEMO{n:03d}"
        return self.hosts[real]

    def ip(self, real: str) -> str:
        if real not in self.ips:
            self.ips[real] = IP_POOL[len(self.ips) % len(IP_POOL)]
        return self.ips[real]

    def ip6(self, real: str) -> str:
        """RFC 3849 documentation prefix, so the value is recognisably not routable."""
        if real not in self.ips:
            n = len(self.ips) + 1
            self.ips[real] = f"2001:db8:{n:x}:{n * 7 % 65536:x}::{n:x}"
        return self.ips[real]

    def person(self, real: str) -> str:
        """A display name. Service principals stay service principals - decided from the shape of
        the original (an application name carries a platform word), never from its content."""
        if real not in self.upns:
            i = len(self.upns)
            if any(h in real.lower() for h in APP_HINTS):
                self.upns[real] = APP_NAMES[i % len(APP_NAMES)]
            else:
                f, l = FIRST[i % len(FIRST)], LAST[(i // len(FIRST) + i) % len(LAST)]
                self.upns[real] = f"{f.title()} {l.title()}"
        return self.upns[real]

    def when(self, real: str) -> str:
        """A timestamp at a similar distance from 'now' as the original was from its own
        collection time - so trends keep their shape - but never the original instant."""
        try:
            t = datetime.fromisoformat(real.replace("Z", "+00:00"))
        except ValueError:
            return self.base.isoformat()
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        # Preserve the day offset, resynthesise the time of day.
        days = (self.base - t).days
        days = max(0, min(days, 400))
        out = self.base - timedelta(days=days,
                                    hours=self.rng.randint(0, 9),
                                    minutes=self.rng.randint(0, 59))
        return out.date().isoformat() if len(real) == 10 else out.isoformat()

    def label(self, path: str, hint: str) -> str:
        """Readable filler derived from the PATH, never from the value."""
        self.fallbacks[path] = self.fallbacks.get(path, 0) + 1
        leaf = path.rstrip("[]").split(".")[-1].replace("[]", "")
        parent = [p for p in path.split(".") if p.endswith("[]")]
        base = (parent[-1][:-2] if parent else leaf)
        base = re.sub(r"(?<!^)(?=[A-Z])", " ", base).title()
        if base.endswith("ies"):
            base = base[:-3] + "y"
        elif base.endswith("s"):
            base = base[:-1]
        n = self.fallbacks[path]
        return f"{base} {n}" if hint != "long" else \
            f"{base} {n} - synthetic text generated for the public demo; no tenant data is used."

    def string(self, real: str, path: str):
        if path in OVERRIDES and OVERRIDES[path]:
            pool = OVERRIDES[path]
            self._n += 1
            return pool[self._n % len(pool)]
        if path in HOST_PATHS:
            return self.host(real)
        if path in PERSON_PATHS and not RE_UPN.match(real):
            return self.person(real)
        if RE_ISO.match(real):
            return self.when(real)
        if RE_UPN.match(real):
            return self.upn(real)
        if RE_GUID.match(real):
            return self.gid(real)
        if RE_IP.match(real):
            return self.ip(real)
        if RE_IP6.match(real) and real.count(":") >= 2:
            return self.ip6(real)
        if RE_HOST.match(real):
            return self.host(real)
        if RE_NUMID.match(real):
            # Short numeric strings are ids (incident numbers, error codes), not free text.
            return str(1000 + (len(self.ids) * 37) % 9000) if len(real) > 3 else real
        if RE_THUMB.match(real) or RE_LONGHEX.match(real):
            return self.gid(real).replace("-", "")[:len(real)]
        if real == "":
            return ""
        # Product vocabulary: the exact string is a literal in the application's own source, so it
        # is a term the UI compares against, not a fact about a tenant.
        if real.lower() in self.vocab and len(real) <= 48 and "@" not in real:
            self.passthrough.add(real)
            return real
        return self.label(path, "long" if len(real) > 60 else "short")

    def number(self, real, path: str):
        if isinstance(real, bool):
            return real
        if real == 0:
            return 0
        if isinstance(real, float):
            return round(self.rng.uniform(0.55, 0.97) * 100, 1) if real <= 100 else \
                round(real * self.rng.uniform(0.4, 1.6), 1)
        lo, hi = 0.35, 1.8
        out = int(round(real * self.rng.uniform(lo, hi)))
        return max(1, out) if real > 0 else out

    def walk(self, node, path=""):
        if isinstance(node, dict):
            pool = KEY_POOLS.get(path)
            out = {}
            for i, (k, v) in enumerate(node.items()):
                nk = k
                if pool:
                    nk = pool[i % len(pool)]
                elif RE_ISO.match(k) or RE_GUID.match(k) or RE_UPN.match(k):
                    nk = self.string(k, f"{path}<key>")
                out[nk] = self.walk(v, f"{path}.{k}" if path else k)
            return out
        if isinstance(node, list):
            n = len(node)
            if n and path not in FIXED_LENGTH_PATHS:
                n = max(1, min(LIST_CAP, int(round(n * LIST_SCALE))))
            # Elements beyond the original length are produced by walking the existing ones again;
            # the generators are stateful, so each pass yields different synthetic values.
            return [self.walk(node[i % len(node)], f"{path}[]") for i in range(n)] if node else []
        if isinstance(node, bool):
            return node
        if isinstance(node, (int, float)):
            return self.number(node, path)
        if node is None:
            return None
        return self.string(node, path)


def source_vocabulary(root: pathlib.Path) -> set[str]:
    """Every quoted string literal in the application's own source, lowercased.

    This is what makes rule 3 safe: a value only survives verbatim if the code itself names it.
    Tenant-specific strings (a policy name, a person, a hostname) never appear in source, so they
    cannot pass - while the enum tokens the UI branches on always do.
    """
    lits: set[str] = set()
    pat = re.compile(r"""(?:'([^'\n]{1,48})'|"([^"\n]{1,48})"|`([^`\n]{1,48})`)""")
    for p in list(root.rglob("*.py")) + list(root.rglob("*.html")) + list(root.rglob("*.js")):
        if "demo" in p.parts:
            continue
        try:
            text = p.read_text(encoding="utf-8")
        except OSError:
            continue
        for m in pat.finditer(text):
            for g in m.groups():
                if g:
                    lits.add(g.strip().lower())
    return {x for x in lits if x}


def set_path(obj, dotted: str, value) -> bool:
    cur = obj
    parts = dotted.split(".")
    for p in parts[:-1]:
        if not isinstance(cur, dict) or p not in cur:
            return False
        cur = cur[p]
    if isinstance(cur, dict) and parts[-1] in cur:
        cur[parts[-1]] = value
        return True
    return False


def get_path(obj, dotted: str):
    cur = obj
    for p in dotted.split("."):
        if not isinstance(cur, dict) or p not in cur:
            return None
        cur = cur[p]
    return cur


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot", required=True)
    ap.add_argument("--history", default=None)
    ap.add_argument("--health", default=None,
                    help="a saved /api/health response, for the Data Health tab. That payload is "
                         "built per request rather than stored in the snapshot, so without it the "
                         "tab renders empty in a static demo.")
    ap.add_argument("--out", required=True)
    ap.add_argument("--report", default=None, help="write the fallback-path report here")
    a = ap.parse_args()

    root = pathlib.Path(__file__).resolve().parents[1]
    real = json.loads(pathlib.Path(a.snapshot).read_text(encoding="utf-8"))
    vocab = source_vocabulary(root / "app")
    print(f"source vocabulary: {len(vocab)} literals")

    base = datetime.now(timezone.utc).replace(microsecond=0)
    g = Gen(vocab, base)
    out = g.walk(real)
    out["_collectedAt"] = base.isoformat()

    # History: same shape, synthetic series. Regenerated rather than walked so the trend lines
    # look like a plausible improving posture instead of noise.
    if a.history:
        hist_real = json.loads(pathlib.Path(a.history).read_text(encoding="utf-8"))
        keys = [k for k in (hist_real[0] if hist_real else {}) if k != "ts"]
        series, n = [], min(len(hist_real), 240)
        for i in range(n):
            ts = base - timedelta(hours=(n - i) * 2)
            row = {"ts": ts.isoformat()}
            for k in keys:
                if "Pct" in k or "Percent" in k:
                    row[k] = round(62 + 22 * (i / max(1, n - 1)) + g.rng.uniform(-1.5, 1.5), 1)
                else:
                    row[k] = max(0, int(round(8 - 6 * (i / max(1, n - 1))
                                             + g.rng.uniform(-1.5, 1.5))))
            series.append(row)
        out["_history"] = series

    # Data Health describes the COLLECTION rather than the tenant, and the backend assembles it per
    # request. Walk it like everything else, then re-derive the parts that must agree with the
    # snapshot actually being shipped - a health tab that contradicts the data it describes is worse
    # than an empty one.
    if a.health:
        health = g.walk(json.loads(pathlib.Path(a.health).read_text(encoding="utf-8")), "_health")
        src_keys = [k for k, v in out.items()
                    if not k.startswith("_") and isinstance(v, dict) and "available" in v]
        health["sources"] = [
            {"key": k, "state": "fresh", "reason": None, "ageMin": None,
             "bytes": len(json.dumps(out[k], ensure_ascii=False))}
            for k in sorted(src_keys, key=lambda k: -len(json.dumps(out[k], ensure_ascii=False)))
        ]
        col = health.setdefault("collection", {})
        col["lastCollectedAt"] = base.isoformat()
        col["snapshotAgeMin"] = 2.4
        col["snapshotBytes"] = len(json.dumps(out, ensure_ascii=False))
        col["intervalMin"] = 20
        col["skipIfYoungerMin"] = 10.0
        col["activeHours"] = "7-17"
        col["withinWindow"] = True
        col["outsideButRunning"] = False
        for i, c in enumerate(col.get("cycles") or []):
            c["at"] = (base - timedelta(minutes=20 * i + 2)).isoformat()
            c["total"] = len(src_keys)
            c["fresh"] = len(src_keys)
            c["carried"], c["down"] = 0, 0
            c["downKeys"], c["carriedKeys"] = [], []
            c["trigger"] = "loop" if i else "live"
        out["_dataHealth"] = health

    # Consistency: a total the UI prints beside a list must match that list.
    fixed = []
    for num_path, list_path in DERIVED_TOTALS.items():
        lst = get_path(out, list_path)
        if isinstance(lst, list) and set_path(out, num_path, len(lst)):
            fixed.append(f"{num_path}={len(lst)}")
    if fixed:
        print("derived totals: " + ", ".join(fixed))

    dst = pathlib.Path(a.out)
    dst.parent.mkdir(parents=True, exist_ok=True)
    dst.write_text(json.dumps(out, ensure_ascii=False, indent=1), encoding="utf-8", newline="\n")

    print(f"\nwrote {dst}  ({dst.stat().st_size // 1024} kB)")
    print(f"synthesised: {len(g.upns)} UPNs, {len(g.ids)} ids, {len(g.hosts)} hosts, "
          f"{len(g.ips)} IPs")
    print(f"passed through as product vocabulary: {len(g.passthrough)} distinct strings")
    print(f"generated labels at {len(g.fallbacks)} paths")

    if a.report:
        lines = [f"{n:5}  {p}" for p, n in sorted(g.fallbacks.items(), key=lambda x: -x[1])]
        pathlib.Path(a.report).write_text(
            "PATHS THAT FELL BACK TO A GENERATED LABEL\n" + "\n".join(lines)
            + "\n\nPASSED THROUGH VERBATIM (product vocabulary)\n"
            + "\n".join(sorted(g.passthrough)), encoding="utf-8")
        print(f"report: {a.report}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
