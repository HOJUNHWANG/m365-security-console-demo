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

RE_UPN = re.compile(r"^[A-Za-z0-9._%+'-]+(#EXT#)?@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")
RE_GUID = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
RE_IP = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
RE_IP6 = re.compile(r"^[0-9a-fA-F]{0,4}(:[0-9a-fA-F]{0,4}){2,7}$")
RE_NUMID = re.compile(r"^\d{2,10}$")
RE_ISO = re.compile(r"^\d{4}-\d{2}-\d{2}(T[\d:.]+([+-]\d{2}:?\d{2}|Z)?)?$")
RE_HOST = re.compile(r"^(?:WIN|BOOK|DESKTOP|LAPTOP|PC|NB)[-_][A-Z0-9]{4,}$|^[A-Z]{3,}[0-9]{2,}$")
RE_THUMB = re.compile(r"^[0-9A-Fa-f]{40}$")
RE_LONGHEX = re.compile(r"^[0-9A-Za-z_-]{22,}={0,2}$")

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
         "warehouse-scanner", "training-room", "conf-observatory", "shipping-terminal",
         "showroom-display", "conf-annex", "breakroom-signage"]

BROWSERS = ["Edge 151", "Chrome 151", "Chrome 150", "Firefox 134", "Safari 18",
            "Internet Explorer 11", "Edge 18"]
EDITIONS = ["Pro", "Home"]
CITIES = ["Seattle, US", "Dublin, IE", "Singapore, SG", "Frankfurt, DE", "Toronto, CA",
          "Seoul, KR", "Sao Paulo, BR"]
MS_APPS = ["Microsoft Azure Portal", "Microsoft 365 Admin Center", "Microsoft Teams",
           "Office 365 Exchange Online", "Microsoft Intune Enrollment", "SharePoint Online",
           "Microsoft Intune Company Portal", "OfficeHome", "Microsoft Authentication Broker"]
CA_POLICY_TABLE = [
    {"name": "CA01 - Require MFA for all users", "state": "enabled",
     "controls": ["mfa"], "sessionControls": [], "users": "All users", "apps": "All apps"},
    {"name": "CA02 - Require MFA for admins", "state": "enabled",
     "controls": ["mfa"], "sessionControls": [], "users": "3 target(s)", "apps": "All apps"},
    {"name": "CA03 - Block legacy authentication", "state": "enabled",
     "controls": ["block"], "sessionControls": [], "users": "All users", "apps": "All apps"},
    {"name": "CA04 - Require compliant device", "state": "enabled",
     "controls": ["compliantDevice"], "sessionControls": [], "users": "2 target(s)",
     "apps": "All apps"},
    {"name": "CA05 - Approved device filter",
     "state": "enabledForReportingButNotEnforced",
     "controls": ["block"], "sessionControls": [], "users": "1 target(s)", "apps": "All apps"},
    {"name": "CA06 - Token protection (Windows)",
     "state": "enabledForReportingButNotEnforced",
     "controls": [], "sessionControls": ["secureSignInSession"], "users": "1 target(s)",
     "apps": "1 app(s)"},
    {"name": "CA07 - Sign-in frequency for privileged roles", "state": "enabled",
     "controls": [], "sessionControls": ["signInFrequency"], "users": "3 target(s)",
     "apps": "2 app(s)"},
    {"name": "CA08 - Block access from unapproved locations", "state": "enabled",
     "controls": ["block"], "sessionControls": [], "users": "All users", "apps": "All apps"},
    {"name": "CA09 - Require MFA for guest access", "state": "enabled",
     "controls": ["mfa"], "sessionControls": [], "users": "1 target(s)", "apps": "All apps"},
    {"name": "CA10 - Block unsupported device platforms", "state": "enabled",
     "controls": ["block"], "sessionControls": [], "users": "All users", "apps": "All apps"},
    {"name": "CA11 - Require app protection for mobile", "state": "enabled",
     "controls": ["compliantDevice"], "sessionControls": ["persistentBrowser"],
     "users": "2 target(s)", "apps": "2 app(s)"},
]
CA_POLICIES = [p["name"] for p in CA_POLICY_TABLE]
CA_EXCLUDED = [f"breakglass-01@{DOMAIN}", f"breakglass-02@{DOMAIN}",
               f"conf-atrium@{DOMAIN}", f"reception-kiosk@{DOMAIN}"]
ROLES = ["Global Administrator", "Global Reader", "Exchange Administrator",
         "Intune Administrator", "Security Administrator", "User Administrator",
         "Directory Readers", "Conditional Access Administrator"]
INCIDENTS = ["Suspicious inbox manipulation rule", "Multi-stage phishing campaign",
             "Impossible travel sign-in", "Malware delivered to mailbox",
             "Anonymous sharing link created on sensitive site", "Password spray attempt"]
SUBJECTS = ["Invoice 40218 overdue - action required", "Your mailbox storage is almost full",
            "Shared document: Q3 forecast.xlsx", "Payroll update - confirm your details",
            "Delivery failed: parcel 8842019", "Urgent: verify your account"]
GROUPS = ["Contoso-All-Employees", "Contoso-CA-Exclusions-BreakGlass", "Contoso-Pilot-Wave1",
          "Contoso-Room-Accounts", "Contoso-Managed-Devices"]
SITES = ["/sites/marketing", "/sites/projects", "/sites/hr-public", "/sites/vendor-exchange",
         "/personal/demo_user_contoso_com", "/sites/field-sales", "/sites/quality-records",
         "/sites/onboarding", "/sites/supplier-portal", "/sites/design-review"]

CA_CONTROLS = ["mfa", "compliantDevice", "block", "passwordChange", "AppTokenProtection",
               "SignInTokenProtection", "domainJoinedDevice"]
DEVICE_CLAIMS = ["Windows11 · compliant", "Windows11 · unmanaged", "Windows10 · compliant",
                 "(no device claim)", "iOS · compliant"]
SEVERITIES = ["high", "med", "low", "informational"]
OS_VERSIONS = ["10.0.26100.3194", "10.0.26200.8875", "10.0.22631.4460", "18.1.1"]
MODELS = ["ThinkPad E14 Gen 5", "Latitude 5450", "Pavilion 15-eh", "Galaxy Book4",
          "Surface Laptop 6", "OptiPlex 7010"]
ENROLL_TYPES = ["userEnrollment", "windowsAzureADJoin", "deviceEnrollmentManager",
                "windowsCoManagement"]
MAIL_LOCATIONS = ["Inbox", "Inbox/folder", "Junk Email", "Quarantine", "Deleted Items"]
SENDER_DOMAINS = ["mail-delivery.example", "invoice-portal.example", "shared-docs.example",
                  "secure-notice.example", "parcel-track.example"]
TRANSPORT_RULES = ["Inbound external banner", "Redirect failed authentication",
                   "Block executable attachments", "Bypass filtering for partner",
                   "Quarantine unauthenticated bulk mail", "Strip active content from archives",
                   "Flag lookalike display names", "Route finance approvals to review"]
SIMULATIONS = ["Credential harvest - company-wide awareness",
               "Phishing drill - finance team", "Link in attachment - quarterly test",
               "Malware attachment - onboarding cohort", "Drive-by URL - all staff",
               "OAuth consent lure - pilot group", "Payroll pretext - HR cohort",
               "Delivery notice lure - warehouse"]
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

OAUTH_SCOPES = ["User.Read", "openid", "profile", "email", "offline_access", "User.ReadBasic.All",
                "Group.Read.All", "Directory.Read.All", "Calendars.ReadWrite", "Mail.Read",
                "Files.ReadWrite.All", "Sites.Read.All", "Chat.Read", "Presence.Read.All",
                "Contacts.Read", "Tasks.ReadWrite"]
DATA_SCOPES = ["Files.ReadWrite.All", "Mail.Read", "Sites.Read.All", "Calendars.ReadWrite",
               "Chat.Read", "Mail.Send", "Contacts.Read"]
APP_ONLY_PERMS = ["Directory.Read.All", "User.Read.All", "Sites.Read.All", "Mail.Read",
                  "full_access_as_app", "Group.Read.All", "Files.Read.All"]
SAAS_APPS = ["Zoom", "Slack", "Jira", "Confluence", "Trello", "Salesforce", "DocuSign", "Canva",
             "Miro", "Figma", "Notion", "Asana", "Dropbox", "Zapier", "Smartsheet", "Grammarly",
             "Adobe Acrobat", "Lucidchart", "Mailchimp", "SurveyMonkey", "Calendly", "Loom",
             "Airtable", "Typeform", "Webex", "Box"]
PUBLISHERS = ["Zoom Video Communications", "Slack Technologies", "Atlassian", "Salesforce",
              "DocuSign Inc.", "Canva Pty Ltd", "Adobe Inc.", "Figma Inc.", "Dropbox Inc.",
              "(unverified)"]
SIGNIN_AUDIENCE = ["AzureADMyOrg", "AzureADMultipleOrgs", "AzureADandPersonalMicrosoftAccount"]
SITS = ["Credit Card Number", "U.S. Social Security Number (SSN)", "U.S. Bank Account Number",
        "ABA Routing Number", "U.S. / U.K. Passport Number", "U.S. Driver's License Number",
        "IP Address", "Azure Storage Account Key", "EU Passport Number",
        "U.S. Individual Taxpayer Identification Number (ITIN)"]
EXCEPTION_NOTES = [
    "break-glass account, reviewed and recorded as an intended exclusion",
    "unattended room device that cannot complete an interactive control",
    "time-boxed exception for an onboarding wave, expires with the wave",
]
DOC_ITEMS = ["Q3 forecast.xlsx", "Vendor NDA.pdf", "Site plan.pptx", "Payroll summary.xlsx",
             "Onboarding checklist.docx", "Supplier list.csv"]

FINDING_TEXT_KO = [
    "기기 조건을 요구하는 정상이 장치 클레임을 얻을 수 없는 플랫폼을 범위에 넣고 있습니다.",
    "상한가 여전히 익장 링킩를 허용하는 사이트에 익장 링킩가 남아 있습니다.",
    "파일랫 그룹 전원에게 확장 설치가 증명되지 않았습니다.",
    "테넌트 기본값이 익장 링킩를 허용하물로 새 사이트가 그대로 상속합니다.",
]
SIGNIN_ERRORS_KO = [
    "사용자 이름 또는 암호가 올바르지 않습니다",
    "MFA 가 필요하지만 완료되지 않았습니다",
    "MFA 인증이 실패하거나 시간이 초과되었습니다",
    "조건부 액세스 정책에 의해 차단되었습니다",
    "계정이 잠겼습니다",
]
REACH_WHY_KO = [
    "범위 포함: 전진 사용자 할당에 이 계정의 제외가 없습니다",
    "범위 포함: 포함된 그룹의 구성원이며 정책에 차단 컨트롤이 있습니다",
    "범위 제외: 레거시 클라이언트 유형에만 적용되는 정책입니다",
]

APP_ONLY_WRITES = ["Mail.Send", "User.ReadWrite.All", "Directory.ReadWrite.All",
                   "Sites.ReadWrite.All", "full_access_as_app"]
GRAPH_ENDPOINTS = ["/auditLogs/signIns", "/devices", "/deviceManagement/managedDevices",
                   "/security/alerts_v2", "/identity/conditionalAccess/policies",
                   "/servicePrincipals", "/sites"]
REQUEST_REASONS = [
    "needed for the quarterly supplier review",
    "team standardised on this tool last month",
    "replaces a personal account already in use",
    "requested by the project lead for a pilot",
]

AI_SUMMARY_KO = (
    "전반적인 보안 태세는 개선되고 있으나, 다음 조건부 액세스 변경 전에 두 가지를 정리해야 합니다. "
    "MFA 등록률이 기간 내 꾸준히 올랐고 보안 점수 추세도 상승이라 ID 기준선은 유지되고 있습니다. "
    "남은 위험은 다른 곳입니다. 기기 조건을 요구하는 정책이 아직 보고 전용인 상태에서 일부 Windows "
    "로그인이 장치 클레임 없이 도착하고 있고, 그 로그인들은 기기가 등록·준수 상태여도 시행 시 차단됩니다 "
    "- 실제 준수 실패가 아니라 브라우저 SSO 공백입니다. 익명 공유 링크는 상한이 아직 허용하는 두 사이트에 "
    "남아 있습니다. 우선순위는 누락된 장치 클레임을 해결하고, 시행 전에 보고 전용 영향 패널을 다시 읽는 "
    "것입니다. 보고 전용 차단 건수의 일부는 기기 기반 평가의 보고 특성에서 오는 과대 집계이므로 "
    "상한선으로 다루고 잠금 예측치로 읽지 마십시오."
)
DEFENDER_NOTE = (
    "Antivirus state is read from the Defender reporting surface, so a device that has not reported "
    "since its last policy change shows its previous state rather than no state at all."
)
DEFENDER_CAVEAT = (
    "A device counts as reporting only when Defender has posted within the freshness window; "
    "silence is treated as unknown rather than healthy, because the failure mode of the opposite "
    "choice is a fleet that looks clean while it is unmonitored."
)
APPS_NOTE = (
    "Consent-based discovery lists what somebody has granted, which is not the same as what is in "
    "use. An app with no sign-ins in the window is a candidate for removal, not proof of one."
)
SSO_NOTE = (
    "Applications configured for SSO do not appear in a consent inventory at all, so they are "
    "collected separately - otherwise the app estate looks smaller than it is."
)
EXPIRY_REASON = (
    "Nothing removes an exception automatically. A group membership added for a cutover stays until "
    "somebody takes it out, so each row carries its own review date."
)
REVOKE_COMMAND = (
    "Remove-MgGroupMemberByRef -GroupId <group> -DirectoryObjectId <user>"
)

MAM_GROUPS = ["Contoso-MAM-AllStaff", "Contoso-MAM-Pilot", "Contoso-MAM-Field",
              "Contoso-MAM-Contractors"]
DLP_POLICIES = ["Contoso-DLP-Simulation"]
GRAPH_PLATFORM_ENUMS = {"windows10", "windows81", "ios", "android", "androidforwork",
                        "androidenterprise", "macos"}
MAM_PLATFORMS = ["iOS · Android", "iOS", "Android"]
MAM_FINDINGS = [
    "Targeted users with no registration cannot be told apart from users who have not installed the "
    "app yet - a failed device check produces no row at all, only an absence.",
    "Registrations older than the staleness window are counted separately; a stale record is not "
    "evidence that the device is still enrolled.",
    "The group scope covers more people than the pilot did, so the unregistered list grew without "
    "anything failing.",
]
MAM_FINDINGS_KO = [
    "대상자인데 등록이 없는 사람은, 검증에 실패한 것인지 아직 앱을 설치하지 않은 것인지 구분되지 "
    "않습니다. 실패는 행이 아니라 행의 부재로 오기 때문입니다.",
    "만료 기준을 넘긴 등록은 따로 셉니다. 오래된 기록이 그 기기가 지금도 등록돼 있다는 증거는 "
    "아닙니다.",
    "그룹 범위가 파일럿보다 넓어지면서, 실패한 것 없이도 미등록 명단이 늘어났습니다.",
]
RISK_DETAIL_EN = [
    "Sign-in from an IP range not seen for this account before, on a client that carries no device "
    "claim.",
    "Several failures from one address across different accounts within a short window.",
    "Token issued to a client that has not presented this device before.",
    "Sign-in succeeded after a series of failures from the same address.",
]
RISK_DETAIL_KO = [
    "이 계정에서 이전에 보이지 않던 IP 대역에서의 로그인이며, 장치 클레임이 없는 클라이언트입니다.",
    "짧은 시간 안에 한 주소에서 여러 계정에 걸쳐 실패가 반복됐습니다.",
    "이 기기를 제시한 적 없는 클라이언트에 토큰이 발급됐습니다.",
    "같은 주소에서 연속 실패가 있은 뒤 로그인이 성공했습니다.",
]
ADDIN_APPS = ["Grammarly for Outlook", "Trello for Outlook", "Zoom for Outlook", "DocuSign for Outlook",
              "Boomerang", "Evernote", "Salesforce Inbox"]
ADDIN_PROVIDERS = ["Grammarly Inc.", "Atlassian", "Zoom Video Communications", "DocuSign Inc.",
                   "Baydin Inc.", "Bending Spoons", "Salesforce"]
ADDIN_REASONS = [
    "reads message bodies, which is the permission worth reviewing",
    "installed from the store by a user rather than deployed centrally",
    "requests mailbox read/write, the widest scope an add-in can hold",
]
ADDIN_DECISIONS = ["keep", "review", "remove"]
ADDIN_TRIGGERS = ["new add-in appeared since the last collection",
                  "permission scope widened", "publisher is unverified"]
ADDIN_ROLES = ["My Custom Apps", "My Marketplace Apps", "My ReadWriteMailbox Apps"]
FORWARD_REASONS = [
    "mailbox rule forwards to an address outside the organisation",
    "delivery to an external address with no copy kept in the mailbox",
]
CLICK_ACTIONS = ["UrlErrorPage", "ClickAllowed", "ClickBlocked"]
CLICK_URLS = ["https://invoice-portal.example/pay/40218",
              "https://shared-docs.example/d/q3-forecast",
              "https://secure-notice.example/verify",
              "https://parcel-track.example/8842019"]
DLP_NOTIFY = ["LastModifier", "SiteAdmin", "Owner"]
STALE_REASONS = ["record older than the refresh window", "site no longer returns a sharing setting"]
EOP_FINDINGS = [
    "An add-in that can read message bodies is installed for the whole organisation.",
    "Auto-forwarding to an external address is configured on a mailbox.",
]
EOP_FINDINGS_KO = [
    "메일 본문을 읽을 수 있는 추가 기능이 조직 전체에 설치돼 있습니다.",
    "외부 주소로의 자동 전달이 사서함에 설정돼 있습니다.",
]
UNCONSENTED_NOTE = (
    "Applications a user has signed into without a consent grant recorded. They are listed because "
    "the absence of a grant is itself the finding, not because the app is known to be a problem."
)
RESTART_CMD = "restart the dashboard web process"

MOBILE_MODELS = ["iPhone", "iPad", "Galaxy S24", "Galaxy S25", "Galaxy Z Flip",
                 "Galaxy A55", "Pixel 9", "Pixel 8a"]

OVERRIDES: dict[str, list] = {
    "browserClaims.byBrowser[].browser": BROWSERS,
    "browserClaims.users[].browsers[].browser": BROWSERS,
    "browserClaims.users[].editions[]": EDITIONS,
    "browserClaims.extensionName": ["Windows Accounts"],
    "browserClaims.pilotGroup": ["CA-Pilot-Users"],
    "browserClaims.scopePlatforms[]": ["windows", "macOS"],
    "browserClaims.scopePolicies[]": CA_POLICIES[3:6],
    "intuneDevices.byOs": None,
    "intuneDevices.devices[].os": ["Windows"],
    "intuneDevices.devices[].compliance": ["compliant", "compliant", "compliant", "noncompliant"],
    "intuneDevices.devices[].owner": ["Company", "Company", "Company", "Personal"],
    "intuneDevices.devices[].edition": EDITIONS,
    "deviceIdentity.tag": ["Approved-Device"],
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
    "adminAccounts.privileged[].role": ROLES,
    "adminAccounts.readPrivileged[].role": ROLES,
    "adminAccounts.otherRoles[].role": ROLES,
    "adminAccounts.servicePrincipalRoles[].role": ROLES,
    "adminAccounts.topAccounts[].roles[]": ROLES,
    "securityIncidents.incidents[].title": INCIDENTS,
    "securityAlerts.alerts[].title": INCIDENTS,
    "threatHunting.delivered[].subject": SUBJECTS,
    "threatHunting.riskyClicks[].subject": SUBJECTS,
    "threatHunting.urlClicks[].subject": SUBJECTS,
    "sharingLinks.sites[].path": SITES,
    "sharingLinks.links[].site": SITES,
    "sharepointSharing.newSites[].url": SITES,
    "sharingLinks.newSites[].url": SITES,
    "sharingLinks.newSites[].name": ["Marketing", "Projects", "HR Public", "Vendor Exchange",
                                    "Field Sales", "Quality Records", "Onboarding",
                                    "Supplier Portal", "Design Review"],

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

    "riskySignins.recentFailures[].error": SIGNIN_ERRORS,
    "riskySignins.caFailures[].error": SIGNIN_ERRORS,
    "riskySignins.nonInteractive.accounts[].recentApps[]": MS_APPS,

    "intuneDevices.devices[].osVersion": OS_VERSIONS,
    "intuneDevices.devices[].model": MODELS,
    "intuneDevices.devices[].manufacturer": ["Lenovo", "Dell Inc.", "HP", "Samsung", "Microsoft"],
    "deviceIdentity.devices[].enrollmentType": ENROLL_TYPES,
    "intuneDevices.devices[].enrollmentType": ENROLL_TYPES,
    "deviceIdentity.devices[].problems[]": DEVICE_PROBLEMS,
    "deviceIdentity.devices[].warnings[]": DEVICE_PROBLEMS,

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
    "threatHunting.byType[].type": ["Phish", "Spam", "Phish, Spam", "Malware"],
    "threatHunting.senders[].domain": SENDER_DOMAINS,
    "threatHunting.delivered[].senderDomain": SENDER_DOMAINS,

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

    "secureScoreActions.recommendations[].title": SECURE_SCORE_ACTIONS,
    "recentAudits.items[].activity": AUDIT_ACTIVITIES,
    "unattendedAccounts.findings[].name": ROOMS,
    "unattendedAccounts.accounts[].name": ROOMS,
    "unattendedAccounts.candidates[].name": ROOMS,
    "unattendedAccounts.findings[].policy": CA_POLICIES,
    "unattendedAccounts.policies[].policy": CA_POLICIES,

    "accountSummary.guestList[].state": ["Accepted", "PendingAcceptance"],
    "licenses.skus[].sku": ["SPB", "THREAT_INTELLIGENCE", "POWER_BI_STANDARD",
                            "Microsoft_365_Copilot", "EXCHANGESTANDARD", "AAD_PREMIUM",
                            "INTUNE_A", "FLOW_FREE", "TEAMS_EXPLORATORY"],
    "exchangeEop.allowlist.allowDomains[]": ["partner.example", "affiliate.example",
                                             "supplier.example", "logistics.example"],
    "exchangeEop.allowlist.ownDomains[]": [DOMAIN, TENANT],
    "exchangeEop.quarantine.byType[].type": ["Phish", "Spam", "Malware",
                                             "High Confidence Phish", "Bulk"],
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
                                                "Minimum OS version",
                                                "Secure Boot and code integrity",
                                                "Defender real-time protection"],
    "riskySignins.caFailByPolicy[].policy": CA_POLICIES,
    "deviceIdentity.devices[].signInTrustType": TRUST_TYPES,
    "deviceIdentity.devices[].intuneObjectTrustType": TRUST_TYPES,
    "deviceIdentity.multiAccountDevices[].device": None,
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
    "_health.graph.endpoints[].endpoint": GRAPH_ENDPOINTS,
    "_health.graph.slowest[].endpoint": GRAPH_ENDPOINTS,
    "_health.graph.worstEndpoint": GRAPH_ENDPOINTS,
    "browserClaims.findings[].text": FINDING_TEXT,
    "sharepointSharing.findings[].text": FINDING_TEXT,
    "sharingLinks.findings[].text": FINDING_TEXT,
    "enterpriseApps.apps[].name": SAAS_APPS,
    "enterpriseApps.apps[].publisher": PUBLISHERS,
    "enterpriseApps.apps[].scopes[]": OAUTH_SCOPES,
    "enterpriseApps.apps[].dataScopes[]": DATA_SCOPES,
    "enterpriseApps.apps[].appOnlyPermissions[]": APP_ONLY_PERMS,
    "enterpriseApps.apps[].signInAudience": SIGNIN_AUDIENCE,
    "enterpriseApps.ungated[].name": SAAS_APPS,
    "enterpriseApps.ungated[].publisher": PUBLISHERS,
    "enterpriseApps.ungated[].scopes[]": OAUTH_SCOPES,
    "enterpriseApps.ungated[].dataScopes[]": DATA_SCOPES,
    "enterpriseApps.ungated[].appOnlyPermissions[]": APP_ONLY_PERMS,
    "enterpriseApps.ungated[].signInAudience": SIGNIN_AUDIENCE,
    "enterpriseApps.unusedApps[].name": SAAS_APPS,
    "enterpriseApps.unusedApps[].publisher": PUBLISHERS,
    "enterpriseApps.unusedApps[].scopes[]": OAUTH_SCOPES,
    "enterpriseApps.unusedApps[].dataScopes[]": DATA_SCOPES,
    "enterpriseApps.unusedApps[].appOnlyPermissions[]": APP_ONLY_PERMS,
    "enterpriseApps.unusedApps[].signInAudience": SIGNIN_AUDIENCE,
    "enterpriseApps.appOnly[].name": SAAS_APPS,
    "enterpriseApps.appOnly[].publisher": PUBLISHERS,
    "enterpriseApps.appOnly[].scopes[]": OAUTH_SCOPES,
    "enterpriseApps.appOnly[].dataScopes[]": DATA_SCOPES,
    "enterpriseApps.appOnly[].appOnlyPermissions[]": APP_ONLY_PERMS,
    "enterpriseApps.appOnly[].signInAudience": SIGNIN_AUDIENCE,
    "enterpriseApps.gated[].name": SAAS_APPS,
    "enterpriseApps.gated[].publisher": PUBLISHERS,
    "enterpriseApps.gated[].scopes[]": OAUTH_SCOPES,
    "enterpriseApps.gated[].dataScopes[]": DATA_SCOPES,
    "enterpriseApps.gated[].appOnlyPermissions[]": APP_ONLY_PERMS,
    "enterpriseApps.gated[].signInAudience": SIGNIN_AUDIENCE,
    "enterpriseApps.consentQueue[].name": SAAS_APPS,
    "enterpriseApps.consentQueue[].publisher": PUBLISHERS,
    "enterpriseApps.consentQueue[].scopes[]": OAUTH_SCOPES,
    "enterpriseApps.consentQueue[].dataScopes[]": DATA_SCOPES,
    "enterpriseApps.consentQueue[].appOnlyPermissions[]": APP_ONLY_PERMS,
    "enterpriseApps.consentQueue[].signInAudience": SIGNIN_AUDIENCE,
    "enterpriseApps.findings[].text": FINDING_TEXT,
    "enterpriseApps.findings[].textEn": FINDING_TEXT,
    "enterpriseApps.findings[].textKo": FINDING_TEXT_KO,
    "dlpSimulation.policies[].name": DLP_POLICIES,
    "dlpSimulation.simulation.name": DLP_POLICIES,
    "dlpSimulation.findings[].text": FINDING_TEXT,
    "dlpSimulation.findings[].textEn": FINDING_TEXT,
    "dlpSimulation.findings[].textKo": FINDING_TEXT_KO,
    "dlpSimulation.policies[].rules[].sensitiveTypes[].name": SITS,
    "dlpSimulation.simulation.rules[].sensitiveTypes[].name": SITS,
    "dlpSimulation.simulation.sensitiveTypes[]": SITS,
    "dlpSimulation.simulation.exchangeDomains[].domain": [DOMAIN, "partner.example",
                                                          "affiliate.example"],
    "caExceptions.ok[].note": EXCEPTION_NOTES,
    "caExceptions.findings[].text": FINDING_TEXT,
    "caExceptions.findings[].textEn": FINDING_TEXT,
    "caExceptions.findings[].textKo": FINDING_TEXT_KO,
    "defenderPosture.findings[].text": FINDING_TEXT,
    "defenderPosture.findings[].textKo": FINDING_TEXT_KO,
    "riskySignins.recentFailures[].errorKo": SIGNIN_ERRORS_KO,
    "riskySignins.caFailures[].errorKo": SIGNIN_ERRORS_KO,
    "unattendedAccounts.policies[].reachWhyKo": REACH_WHY_KO,
    "unattendedAccounts.findings[].reachWhyKo": REACH_WHY_KO,
    "riskySignins.deviceCaBlocks[].apps[].name": MS_APPS,
    "sharepointSharing.perSite.openSites[].url": SITES,
    "sharingLinks.links[].item": DOC_ITEMS,
    "sharingLinks.links[].url": SITES,
    "enterpriseApps.ssoApps[].name": SAAS_APPS,
    "enterpriseApps.ssoApps[].publisher": PUBLISHERS,
    "enterpriseApps.ssoApps[].scopes[]": OAUTH_SCOPES,
    "enterpriseApps.ssoApps[].dataScopes[]": DATA_SCOPES,
    "enterpriseApps.ssoApps[].appOnlyPermissions[]": APP_ONLY_PERMS,
    "enterpriseApps.ssoApps[].signInAudience": SIGNIN_AUDIENCE,
    "enterpriseApps.pendingRequests[].name": SAAS_APPS,
    "enterpriseApps.pendingRequests[].publisher": PUBLISHERS,
    "enterpriseApps.pendingRequests[].scopes[]": OAUTH_SCOPES,
    "enterpriseApps.pendingRequests[].dataScopes[]": DATA_SCOPES,
    "enterpriseApps.pendingRequests[].appOnlyPermissions[]": APP_ONLY_PERMS,
    "enterpriseApps.pendingRequests[].signInAudience": SIGNIN_AUDIENCE,
    "enterpriseApps.apps[].appOnlyWrites[]": APP_ONLY_WRITES,
    "enterpriseApps.ungated[].appOnlyWrites[]": APP_ONLY_WRITES,
    "enterpriseApps.unusedApps[].appOnlyWrites[]": APP_ONLY_WRITES,
    "enterpriseApps.appOnly[].appOnlyWrites[]": APP_ONLY_WRITES,
    "enterpriseApps.gated[].appOnlyWrites[]": APP_ONLY_WRITES,
    "enterpriseApps.ssoApps[].appOnlyWrites[]": APP_ONLY_WRITES,
    "enterpriseApps.pendingRequests[].requesters[].status": ["pending", "approved", "denied"],
    "enterpriseApps.pendingRequests[].requesters[].reason": REQUEST_REASONS,
    "caExceptions.ok[].policy": CA_POLICIES,
    "caExceptions.policies[].policy": CA_POLICIES,
    "caExceptions.expiring[].policy": CA_POLICIES,
    "caExceptions.unrecorded[].policy": CA_POLICIES,
    "defenderPosture.devices[].osVersion": OS_VERSIONS,
    "defenderPosture.defenderPrimary[].osVersion": OS_VERSIONS,
    "defenderPosture.devices[].os": ["Windows"],
    "dlpSimulation.policies[].rules[].mode": ["simulation", "enable", "disable"],
    "dlpSimulation.simulation.topLocations.SharePoint[].key": SITES,
    "browserClaims.findings[].textEn": FINDING_TEXT,
    "browserClaims.findings[].textKo": FINDING_TEXT_KO,
    "sharingLinks.findings[].textEn": FINDING_TEXT,
    "sharingLinks.findings[].textKo": FINDING_TEXT_KO,
    "sharepointSharing.findings[].textEn": FINDING_TEXT,
    "sharepointSharing.findings[].textKo": FINDING_TEXT_KO,
    "unattendedAccounts.findings[].textKo": FINDING_TEXT_KO,
    "_health.graph.recentErrors[].endpoint": GRAPH_ENDPOINTS,
    "enterpriseApps.msExcludedActive[].name": SAAS_APPS,
    "enterpriseApps.msExcludedActive[].publisher": PUBLISHERS,
    "enterpriseApps.msExcludedActive[].scopes[]": OAUTH_SCOPES,
    "enterpriseApps.msExcludedActive[].dataScopes[]": DATA_SCOPES,
    "enterpriseApps.msExcludedActive[].appOnlyPermissions[]": APP_ONLY_PERMS,
    "enterpriseApps.msExcludedActive[].appOnlyWrites[]": APP_ONLY_WRITES,
    "enterpriseApps.msExcludedActive[].signInAudience": SIGNIN_AUDIENCE,
    "enterpriseApps.unconsented[].name": SAAS_APPS,
    "enterpriseApps.unconsented[].publisher": PUBLISHERS,
    "enterpriseApps.unconsented[].scopes[]": OAUTH_SCOPES,
    "enterpriseApps.unconsented[].dataScopes[]": DATA_SCOPES,
    "enterpriseApps.unconsented[].appOnlyPermissions[]": APP_ONLY_PERMS,
    "enterpriseApps.unconsented[].appOnlyWrites[]": APP_ONLY_WRITES,
    "enterpriseApps.unconsented[].signInAudience": SIGNIN_AUDIENCE,
    "enterpriseApps.unconsentedInert[].name": SAAS_APPS,
    "enterpriseApps.unconsentedInert[].publisher": PUBLISHERS,
    "enterpriseApps.unconsentedInert[].scopes[]": OAUTH_SCOPES,
    "enterpriseApps.unconsentedInert[].dataScopes[]": DATA_SCOPES,
    "enterpriseApps.unconsentedInert[].appOnlyPermissions[]": APP_ONLY_PERMS,
    "enterpriseApps.unconsentedInert[].appOnlyWrites[]": APP_ONLY_WRITES,
    "enterpriseApps.unconsentedInert[].signInAudience": SIGNIN_AUDIENCE,
    "enterpriseApps.unconsentedNote": [UNCONSENTED_NOTE],
    "mamRegistrations.groups[].group": MAM_GROUPS,
    "mamRegistrations.groups[].platform": MAM_PLATFORMS,
    "mamRegistrations.byPlatform[].platform": MOBILE_MODELS,
    "mamRegistrations.findings[].text": MAM_FINDINGS,
    "mamRegistrations.findings[].textEn": MAM_FINDINGS,
    "mamRegistrations.findings[].textKo": MAM_FINDINGS_KO,
    "riskySignins.riskSignals[].location": CITIES,
    "riskySignins.riskSignals[].detail": RISK_DETAIL_EN,
    "riskySignins.riskSignals[].detailEn": RISK_DETAIL_EN,
    "riskySignins.riskSignals[].detailKo": RISK_DETAIL_KO,
    "riskySignins.riskSignals[].app": MS_APPS,
    "riskySignins.egressIps[].location": CITIES,
    "riskySignins.riskSignals[].ip": ["203.0.113.24", "198.51.100.17",
                                     "203.0.113.24, 198.51.100.17"],
    "threatHunting.delivered[].threat": ["Phish", "Spam", "Phish, Spam", "Malware"],
    "threatHunting.clickedThreats[].threat": ["Phish", "Spam", "Malware"],
    "threatHunting.riskyClicks[].action": CLICK_ACTIONS,
    "threatHunting.urlClicks[].action": CLICK_ACTIONS,
    "threatHunting.clickedThreats[].action": CLICK_ACTIONS,
    "threatHunting.riskyClicks[].url": CLICK_URLS,
    "threatHunting.clickedThreats[].url": CLICK_URLS,
    "threatHunting.urlClicks[].url": CLICK_URLS,
    "threatHunting.clickedThreats[].subject": SUBJECTS,
    "exchangeEop.addins[].app": ADDIN_APPS,
    "exchangeEop.addins[].provider": ADDIN_PROVIDERS,
    "exchangeEop.addins[].reason": ADDIN_REASONS,
    "exchangeEop.addins[].openDecision": ADDIN_DECISIONS,
    "exchangeEop.addins[].reviewTrigger": ADDIN_TRIGGERS,
    "exchangeEop.outlookAddins[].app": ADDIN_APPS,
    "exchangeEop.outlookAddins[].provider": ADDIN_PROVIDERS,
    "exchangeEop.addinControls.addinRoles[]": ADDIN_ROLES,
    "exchangeEop.forwardingExternal[].to": ["archive@partner.example",
                                            "backup@mail.example"],
    "exchangeEop.forwardingExternal[].reason": FORWARD_REASONS,
    "exchangeEop.findings[].text": EOP_FINDINGS,
    "exchangeEop.findings[].textEn": EOP_FINDINGS,
    "exchangeEop.findings[].textKo": EOP_FINDINGS_KO,
    "dlpSimulation.policies[].rules[].notifyUser[]": DLP_NOTIFY,
    "dlpSimulation.simulation.rules[].notifyUser[]": DLP_NOTIFY,
    "dlpSimulation.simulation.simulationStatus": ["running", "completed", "notStarted"],
    "dlpSimulation.connectedAs": ["Custom Reporting App"],
    "defenderPosture.exposed[].osVersion": OS_VERSIONS,
    "defenderPosture.suspectUpdates[]": OS_VERSIONS,
    "sharepointSharing.perSite.staleRecords[].url": SITES,
    "sharepointSharing.perSite.staleRecords[].reason": STALE_REASONS,
    "_health.code.restartCmd": [RESTART_CMD],
    "_health.graph.worstEndpoint.endpoint": GRAPH_ENDPOINTS,
    "enterpriseApps.legacyProtocolApps[].name": SAAS_APPS,
    "enterpriseApps.legacyProtocolApps[].publisher": PUBLISHERS,
    "enterpriseApps.pendingRequests[].appDisplayName": SAAS_APPS,
    "riskySignins.deviceCaBlocks[].browsers[].name": BROWSERS,
    "dlpSimulation.policies[].simulationStatus": ["running", "completed", "notStarted"],
    "dlpSimulation.simulation.rules[].mode": ["simulation", "enable", "disable"],
    "_aiOverview.text": [AI_SUMMARY],
    "_aiOverview.textEn": [AI_SUMMARY],
    "_aiOverview.textKo": [AI_SUMMARY_KO],
    "defenderPosture.note": [DEFENDER_NOTE],
    "defenderPosture.caveat": [DEFENDER_CAVEAT],
    "defenderPosture.findings[].textEn": FINDING_TEXT,
    "enterpriseApps.note": [APPS_NOTE],
    "enterpriseApps.ssoNote": [SSO_NOTE],
    "caExceptions.autoExpiryReason": [EXPIRY_REASON],
    "caExceptions.revokeCommand": [REVOKE_COMMAND],
    "dlpSimulation.policies[].comment": ["created for the simulation review",
                                         "scoped to Exchange and SharePoint only"],
}

UNIQUE_PATHS = {
    "exchangeEop.transportRules[].name",
    "exchangeEop.transportRules[].description",
    "sharingLinks.newSites[].name",
    "sharingLinks.newSites[].url",
    "sharepointSharing.newSites[].url",
    "intuneDevices.compliancePolicies[].name",
    "riskySignins.caPolicyEval[].policy",
    "unattendedAccounts.policies[].policy",
    "unattendedAccounts.policies[].name",
    "unattendedAccounts.findings[].name",
    "unattendedAccounts.accounts[].name",
    "unattendedAccounts.candidates[].name",
    "enterpriseApps.apps[].name",
    "enterpriseApps.ungated[].name",
    "enterpriseApps.unusedApps[].name",
    "enterpriseApps.appOnly[].name",
    "enterpriseApps.gated[].name",
    "enterpriseApps.consentQueue[].name",
    "enterpriseApps.ssoApps[].name",
    "enterpriseApps.pendingRequests[].name",
    "enterpriseApps.legacyProtocolApps[].name",
    "enterpriseApps.msExcludedActive[].name",
    "enterpriseApps.unconsented[].name",
    "enterpriseApps.unconsentedInert[].name",
    "mamRegistrations.groups[].group",
    "exchangeEop.addins[].app",
    "exchangeEop.outlookAddins[].app",
    "licenses.skus[].sku",
    "attackSimulation.simulations[].displayName",
    "secureScoreActions.recommendations[].title",
    "entraAccess.caPolicies[].name",
    "sharingLinks.sites[].path",
    "sharingLinks.scannedSites[]",
    "sharingLinks.configuredPaths[]",
}

HOST_PATHS = {
    "intuneDevices.devices[].name",
    "deviceIdentity.devices[].device",
    "browserClaims.users[].browsers[].devices[]",
    "browserClaims.users[].devices[]",
    "deviceIdentity.enrolledNotTagged[]",
    "deviceIdentity.taggedNotEnrolled[]",
    "deviceIdentity.multiAccountDevices[].device",
    "defenderPosture.devices[].name",
    "defenderPosture.devices[].device",
    "defenderPosture.defenderPrimary[].name",
    "defenderPosture.exposed[].name",
    "mamRegistrations.notRegisteredUsers[].device",
}

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

KEY_POOLS: dict[str, list] = {
    "intuneDevices.byOs": ["Windows", "iOS", "Android"],
    "intuneDevices.byOwnership": ["company", "personal"],
    "browserClaims.byBrowser": BROWSERS,
    "riskySignins.caFailByPolicy": CA_POLICIES,
    "riskySignins.caFailByControl": ["mfa", "compliantDevice", "block", "passwordChange"],
    "riskySignins.caReportOnlyByControl": ["mfa", "compliantDevice", "block"],
    "riskySignins.legacyByClient": ["IMAP4", "POP3", "SMTP Auth", "Exchange ActiveSync"],
    "riskySignins.caStatusCounts": ["success", "failure", "notApplied"],
    "dlpSimulation.activityExplorer.byType": SITS,
    "mamRegistrations.byPlatform": MOBILE_MODELS,
    "dlpSimulation.byType": SITS,
    "exchangeEop.quarantineTrend": None,
}

LIST_SCALE = 1.62
LIST_CAP = 60

FIXED_LENGTH_PATHS = {
    "riskySignins.failedByDay",
    "riskySignins.nonInteractive.byDay",
    "exchangeEop.collectTimes",
    "exchangeEop.quarantineTrend",
    "browserClaims.scopePlatforms",
    "secureScore.trend",
    "_history",
}

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
        self.rng = random.Random(20260813)
        self.upns: dict[str, str] = {}
        self.ids: dict[str, str] = {}
        self.hosts: dict[str, str] = {}
        self.ips: dict[str, str] = {}
        self.fallbacks: dict[str, int] = {}
        self.passthrough: set[str] = set()
        self._n = 0
        self._nonce = 0
        self._pad = 0
        self._numid = 0
        self._drawn: dict[str, int] = {}

    def _key(self, real: str) -> str:
        return f"{real}\x00{self._nonce}"

    def draw(self, path: str, pool: list) -> str:
        """Sequential draw for a path whose value identifies its row, so it must not repeat. A pool
        shorter than the list gets suffixed rather than wrapping onto a name already used."""
        i = self._drawn.get(path, 0)
        self._drawn[path] = i + 1
        if i < len(pool):
            return pool[i]
        return f"{pool[i % len(pool)]} {i // len(pool) + 1}"

    def upn(self, real: str) -> str:
        real = self._key(real)
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
        real = self._key(real)
        if real not in self.ids:
            n = len(self.ids) + 1
            self.ids[real] = f"{n:08x}-1111-4222-8333-{n:012x}"
        return self.ids[real]

    def host(self, real: str) -> str:
        real = self._key(real)
        if real not in self.hosts:
            n = len(self.hosts) + 1
            self.hosts[real] = f"LAPTOP-DEMO{n:03d}"
        return self.hosts[real]

    def ip(self, real: str) -> str:
        real = self._key(real)
        if real not in self.ips:
            self.ips[real] = IP_POOL[len(self.ips) % len(IP_POOL)]
        return self.ips[real]

    def ip6(self, real: str) -> str:
        """RFC 3849 documentation prefix, so the value is recognisably not routable."""
        real = self._key(real)
        if real not in self.ips:
            n = len(self.ips) + 1
            self.ips[real] = f"2001:db8:{n:x}:{n * 7 % 65536:x}::{n:x}"
        return self.ips[real]

    def person(self, real: str) -> str:
        """A display name. Service principals stay service principals - decided from the shape of
        the original (an application name carries a platform word), never from its content."""
        real = self._key(real)
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
            if path in UNIQUE_PATHS:
                return self.draw(path, pool)
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
            self._numid += 1
            return str(1000 + self._numid * 7) if len(real) > 3 else real
        if RE_THUMB.match(real) or RE_LONGHEX.match(real):
            return self.gid(real).replace("-", "")[:len(real)]
        if real == "":
            return ""
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
            if n and path not in FIXED_LENGTH_PATHS and (isinstance(node[0], dict) or n >= 5):
                n = max(1, min(LIST_CAP, int(round(n * LIST_SCALE))))
            if not node:
                return []
            out = []
            for i in range(n):
                prev = self._nonce
                if i >= len(node):
                    self._pad += 1
                    self._nonce = self._pad
                out.append(self.walk(node[i % len(node)], f"{path}[]"))
                self._nonce = prev
            return out
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


HISTORY_ANCHORS = {
    "secureScorePct": lambda o: (round(o["secureScore"]["current"] / o["secureScore"]["max"] * 100, 1)
                                 if o.get("secureScore", {}).get("max") else None),
    "mfaPercent": lambda o: o.get("mfaStatus", {}).get("percent"),
    "activeAlerts": lambda o: o.get("securityAlerts", {}).get("count"),
    "activeIncidents": lambda o: o.get("securityIncidents", {}).get("activeCount"),
    "globalAdmins": lambda o: o.get("adminAccounts", {}).get("globalAdminCount"),
    "guestsPending": lambda o: o.get("accountSummary", {}).get("guestsPending"),
}

NEARLY_STATIC = {"globalAdmins"}

FIXED_NUMBERS = {
    "deviceIdentity.windowDays": 7,
    "browserClaims.windowDays": 7,
    "riskySignins.windowDays": 7,
    "accountSummary.dormantDays": 90,
}


def history_anchor(key: str, out: dict):
    fn = HISTORY_ANCHORS.get(key)
    if not fn:
        return None
    try:
        v = fn(out)
    except (KeyError, TypeError, ZeroDivisionError):
        return None
    return v if isinstance(v, (int, float)) and not isinstance(v, bool) else None


def history_series(key: str, end, n: int, rng: random.Random):
    """A series a reader would recognise: flat stretches, changing when something happened, ending
    exactly at the value the rest of the page reports."""
    if end is None or n < 2:
        return None

    if "Pct" in key or "Percent" in key:
        start = max(30.0, float(end) - rng.uniform(14, 24))
        cuts = sorted(rng.sample(range(1, n), min(11, n - 1)))
        step = (float(end) - start) / len(cuts)
        vals, cur, ci = [], start, 0
        for i in range(n):
            while ci < len(cuts) and cuts[ci] == i:
                cur += step
                ci += 1
            vals.append(round(cur + rng.uniform(-0.1, 0.1), 1))
        vals[-1] = end
        return vals

    target = int(end)
    vals, cur = [], max(0, target + (1 if key in NEARLY_STATIC else rng.randint(1, 4)))
    while len(vals) < n:
        dwell = rng.randint(30, 60) if key in NEARLY_STATIC else rng.randint(8, 26)
        vals.extend([cur] * dwell)
        delta = rng.choice([-1, 1]) if key in NEARLY_STATIC else rng.randint(-3, 3)
        cur = max(0, cur + delta)
    vals = vals[:n]
    for j in range(max(0, n - rng.randint(6, 16)), n):
        vals[j] = target
    return vals


def cohere(out: dict) -> list[str]:
    """Fix the things a per-value generator structurally cannot get right.

    A walker sees one leaf at a time, so it cannot know that a policy's control has to agree with
    that policy's name, or that a sender's domain has to agree with the sibling field classifying
    the mail as external. Those relationships are repaired here, after generation.
    """
    notes = []

    ea = out.get("entraAccess")
    if isinstance(ea, dict) and isinstance(ea.get("caPolicies"), list):
        rows = ea["caPolicies"][:len(CA_POLICY_TABLE)]
        for row, spec in zip(rows, CA_POLICY_TABLE):
            row.update({k: (list(v) if isinstance(v, list) else v) for k, v in spec.items()})
            for j, ex in enumerate(row.get("excluded") or []):
                ex["name"] = CA_EXCLUDED[j % len(CA_EXCLUDED)]
                ex["kind"] = "user"
                ex["acknowledged"] = False
            seen, uniq = set(), []
            for ex in row.get("excluded") or []:
                if ex.get("name") not in seen:
                    seen.add(ex.get("name"))
                    uniq.append(ex)
            row["excluded"] = uniq
            row["excludedCount"] = len(uniq)
            row["excludedUnacknowledged"] = sum(1 for e in uniq if not e.get("acknowledged"))
            row["excludedUnresolvable"] = 0
        ea["caPolicies"] = rows

        enabled = [r for r in rows if r["state"] == "enabled"]
        report = [r for r in rows if r["state"] == "enabledForReportingButNotEnforced"]
        ea["caPolicyCount"] = len(rows)
        ea["caEnabledCount"] = len(enabled)
        ea["caReportOnlyCount"] = len(report)
        ea["mfaEnforcedByCa"] = any("mfa" in r["controls"] for r in enabled)
        ea["securityDefaults"] = False
        all_ex = [e for r in rows for e in (r.get("excluded") or [])]
        ea["exclusionTotal"] = len(all_ex)
        ea["exclusionDistinct"] = len({e.get("name") for e in all_ex})
        ea["exclusionUnacknowledged"] = sum(1 for e in all_ex if not e.get("acknowledged"))
        ea["exclusionUnresolvable"] = 0
        notes.append(f"caPolicies={len(rows)} ({len(enabled)} on, {len(report)} report-only), "
                     f"exclusions={len(all_ex)}/{ea['exclusionDistinct']} distinct")

    di = out.get("deviceIdentity")
    if isinstance(di, dict) and isinstance(di.get("devices"), list):
        rows = di["devices"]
        n = len(rows)
        plan = (["coherent"] * round(n * 0.55) + ["untagged"] * round(n * 0.19)
                + ["split"] * round(n * 0.21))
        plan = (plan + ["stale"] * n)[:n]
        for r, state in zip(rows, plan):
            oid = r.get("intuneDeviceId") or r.get("signInDeviceId")
            r["problems"], r["warnings"] = [], []
            if state == "split":
                r.update({
                    "entraObjectCount": 2, "intuneTargetState": "liveStub",
                    "intuneObjectTrustType": None, "intuneObjectTagged": True,
                    "signInTrustType": "Workplace", "signInManaged": False,
                    "signInCompliant": False, "signInTagged": False, "signInObjectSound": False,
                    "signInExistsInEntra": True,
                })
                r["problems"] = [
                    "Intune points at a phantom object (no trustType - an MDM-only stub, which "
                    "carries no compliance state and can never satisfy a device policy)",
                    "2 Entra objects share this device name",
                    "the object it signs in with is NOT tagged - device-filter policies will block it",
                ]
            elif state == "stale":
                r.update({
                    "entraObjectCount": 1, "intuneTargetState": "deleted",
                    "intuneObjectTrustType": None, "intuneObjectTagged": None,
                    "signInTrustType": "Workplace", "signInManaged": True,
                    "signInCompliant": True, "signInTagged": True, "signInObjectSound": True,
                    "signInExistsInEntra": True,
                })
                r["warnings"] = ["Intune's azureADDeviceId still points at a deleted object - a "
                                 "stale field only; the object this device signs in with is sound"]
            else:
                tagged = state == "coherent"
                r.update({
                    "entraObjectCount": 1, "intuneTargetState": "liveReal",
                    "intuneObjectTrustType": "Workplace", "intuneObjectTagged": tagged,
                    "signInTrustType": "Workplace", "signInManaged": True,
                    "signInCompliant": True, "signInTagged": tagged, "signInObjectSound": True,
                    "signInExistsInEntra": True,
                    "intuneDeviceId": oid, "signInDeviceId": oid,
                })
                if not tagged:
                    r["problems"] = ["the object it signs in with is NOT tagged - device-filter "
                                     "policies will block it"]
            r["ok"] = not r["problems"]
            r.update({"presentedSource": "signin", "presentedDeviceId": r.get("signInDeviceId"),
                      "presentedTagged": r.get("signInTagged"),
                      "presentedManaged": r.get("signInManaged"),
                      "presentedSound": r.get("signInObjectSound"), "reregistered": False})

        di["duplicateObjectDevices"] = [
            {"device": r["device"], "objects": 2, "trustTypes": ["Workplace", "(none)"]}
            for r in rows if (r.get("entraObjectCount") or 0) > 1
        ]
        di["enrolledNotTagged"] = sorted(r["device"] for r in rows
                                        if r.get("signInTagged") is False)
        di["taggedNotEnrolled"] = []

        di.update({
            "enrolled": n,
            "healthy": sum(1 for r in rows if r["ok"]),
            "problem": sum(1 for r in rows if not r["ok"]),
            "warned": sum(1 for r in rows if r["ok"] and r["warnings"]),
            "duplicateObjectCount": sum(1 for r in rows if r["entraObjectCount"] > 1),
            "phantomLinkCount": sum(1 for r in rows if r["intuneTargetState"] == "liveStub"),
            "staleIntunePointerCount": sum(1 for r in rows
                                           if r["intuneTargetState"] in ("deleted", "missing")),
            "signInMismatchCount": sum(1 for r in rows if r["entraObjectCount"] > 1),
            "orphanSignInCount": 0,
            "untaggedSignInCount": sum(1 for r in rows if r.get("signInTagged") is False),
            "taggedObjectCount": sum(1 for r in rows if r.get("intuneObjectTagged") is True),
            "taggedStubCount": sum(1 for r in rows if r.get("intuneObjectTagged") is True
                                   and r["intuneTargetState"] == "liveStub"),
            "tagInertCount": sum(1 for r in rows if r.get("presentedTagged") is True
                                 and not r.get("presentedSound")),
            "tagInertFromFallback": 0,
        })
        notes.append(f"deviceIdentity: {di['healthy']} coherent + {di['problem']} mismatched "
                     f"+ {di['warned']} warned of {n}; {di['phantomLinkCount']} phantom, "
                     f"{di['duplicateObjectCount']} duplicate-object")

    for dotted, value in FIXED_NUMBERS.items():
        if set_path(out, dotted, value):
            notes.append(f"{dotted} pinned to the code constant {value}")

    th = out.get("threatHunting")
    if isinstance(th, dict):
        ext = [f"{f}.{l}@{d}" for d in SENDER_DOMAINS
               for f, l in ((FIRST[i], LAST[i]) for i in range(3))]
        allowed = [f"sales@{d}" for d in ("partner.example", "affiliate.example")] + \
                  [f"noreply@{d}" for d in ("partner.example", "affiliate.example")]
        fixed = 0
        for key in ("delivered", "riskyClicks", "urlClicks", "zap"):
            for i, row in enumerate(th.get(key) or []):
                if not isinstance(row, dict) or "sender" not in row:
                    continue
                cat = row.get("cat")
                if cat == "spoof":
                    continue
                pool = allowed if cat == "allow" else ext
                row["sender"] = pool[i % len(pool)]
                if "senderDomain" in row:
                    row["senderDomain"] = row["sender"].split("@")[1]
                fixed += 1
        if fixed:
            notes.append(f"senders re-domained to match their classification: {fixed}")
        for i, s in enumerate(th.get("senders") or []):
            if isinstance(s, dict) and "domain" in s:
                s["domain"] = (SENDER_DOMAINS + ["partner.example", DOMAIN])[
                    i % (len(SENDER_DOMAINS) + 2)]

    COUNTISH = re.compile(r"(Count|Total|count|total)$")

    def singular(s: str) -> str:
        for suf, rep in (("ies", "y"), ("ses", "s"), ("s", "")):
            if s.endswith(suf):
                return s[: -len(suf)] + rep
        return s

    def counted_list(nk: str, lists: dict):
        """Which list, if any, does this number claim to count?

        `*Count` and `*Total` are the obvious cases. The one that got away was `ips` beside
        `ipList` - a bare plural noun holding a number, which the UI renders as a "5 IPs" badge
        above a row listing ten of them. A name does not have to say "count" to be one.
        """
        no = nk.lower()
        for lk in lists:
            lo = lk.lower()
            if lo == singular(no) + "list" or lo == no + "list":
                return lk
            if singular(lo) == singular(no):
                return lk
        if COUNTISH.search(nk):
            stem = singular(COUNTISH.sub("", nk).strip("_").lower())
            if stem:
                for lk in lists:
                    ls = singular(lk.lower())
                    if stem in ls or ls in stem:
                        return lk
        return None

    fixed_counts = []

    def derive_counts(node, path=""):
        if isinstance(node, dict):
            lists = {k: v for k, v in node.items() if isinstance(v, list)}
            for nk, nv in list(node.items()):
                if not isinstance(nv, int) or isinstance(nv, bool):
                    continue
                lk = counted_list(nk, lists)
                if lk is not None and node[nk] != len(lists[lk]):
                    node[nk] = len(lists[lk])
                    fixed_counts.append(f"{path}.{nk}")
            for k, v in node.items():
                derive_counts(v, f"{path}.{k}" if path else k)
        elif isinstance(node, list):
            for v in node:
                derive_counts(v, f"{path}[]")

    derive_counts(out)
    if fixed_counts:
        notes.append(f"counts re-derived from their own lists: {len(fixed_counts)}")

    for src, list_key, hist_map in [
        ("intuneDevices", "devices", {"byOs": "os", "byEdition": "edition",
                                      "byJoinType": "joinType", "byOwner": "owner",
                                      "byCompliance": "compliance"}),
        ("browserClaims", "users", {"byStatus": "status"}),
    ]:
        body = out.get(src)
        if not isinstance(body, dict) or not isinstance(body.get(list_key), list):
            continue
        rows = body[list_key]
        for hk, field in hist_map.items():
            if not isinstance(body.get(hk), dict) or not all(field in r for r in rows):
                continue
            tally: dict = {}
            for r in rows:
                tally[str(r[field])] = tally.get(str(r[field]), 0) + 1
            body[hk] = tally
            notes.append(f"{src}.{hk} rebuilt from {len(rows)} rows")

    it = out.get("intuneDevices")
    if isinstance(it, dict) and isinstance(it.get("devices"), list):
        rows = it["devices"]
        comp = sum(1 for r in rows if r.get("compliance") == "compliant")
        it["total"] = len(rows)
        it["compliant"] = comp
        it["noncompliant"] = len(rows) - comp
        if "encrypted" in it:
            it["encrypted"] = sum(1 for r in rows if r.get("encrypted"))
        if "personal" in it:
            it["personal"] = sum(1 for r in rows if r.get("owner") == "Personal")
        notes.append(f"intuneDevices split: {comp} compliant + {len(rows) - comp} not = {len(rows)}")

    for src, rate_key, num_key, den_key in [
        ("riskySignins", "failRate", "failed", "logins"),
        ("mfaStatus", "percent", "registered", "total"),
        ("browserClaims", "provenPercent", "proven", "pilotMembers"),
        ("secureScore", "percent", "current", "max"),
    ]:
        body = out.get(src)
        if not isinstance(body, dict):
            continue
        num, den = body.get(num_key), body.get(den_key)
        if isinstance(num, (int, float)) and isinstance(den, (int, float)) and den:
            if num > den:
                body[num_key] = num = int(den * 0.62)
            if rate_key in body:
                body[rate_key] = round(num / den * 100, 1)
                notes.append(f"{src}.{rate_key} = {body[rate_key]} ({num}/{den})")

    PAIRS = [("firstBlock", "lastBlock"), ("firstSeen", "lastSeen"),
             ("firstClick", "lastClick"), ("firstSignIn", "lastSignIn"), ("invited", "lastActivity"),
             ("createdDateTime", "resolvedDateTime"), ("first", "last")]
    swapped = [0]

    def order_dates(node):
        if isinstance(node, dict):
            for a, b in PAIRS:
                x, y = node.get(a), node.get(b)
                if isinstance(x, str) and isinstance(y, str) and RE_ISO.match(x) \
                        and RE_ISO.match(y) and x > y:
                    node[a], node[b] = y, x
                    swapped[0] += 1
            for v in node.values():
                order_dates(v)
        elif isinstance(node, list):
            for v in node:
                order_dates(v)

    order_dates(out)
    if swapped[0]:
        notes.append(f"first/last timestamps put back in order: {swapped[0]}")

    deduped = [0]

    def dedupe(node):
        if isinstance(node, dict):
            for k, v in list(node.items()):
                if isinstance(v, list) and v and all(isinstance(x, str) for x in v):
                    seen, uniq = set(), []
                    for x in v:
                        if x not in seen:
                            seen.add(x)
                            uniq.append(x)
                    if len(uniq) != len(v):
                        deduped[0] += 1
                        node[k] = uniq
                else:
                    dedupe(v)
        elif isinstance(node, list):
            for v in node:
                dedupe(v)

    dedupe(out)
    if deduped[0]:
        notes.append(f"scalar lists deduplicated: {deduped[0]}")

    return notes


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
    vocab = source_vocabulary(root / "app") | GRAPH_PLATFORM_ENUMS
    print(f"source vocabulary: {len(vocab)} literals")

    base = datetime.now(timezone.utc).replace(microsecond=0)
    g = Gen(vocab, base)
    out = g.walk(real)
    out["_collectedAt"] = base.isoformat()

    def build_history():
        if not a.history:
            return
        hist_real = json.loads(pathlib.Path(a.history).read_text(encoding="utf-8"))
        keys = [k for k in (hist_real[0] if hist_real else {}) if k != "ts"]
        n = min(len(hist_real), 240)
        series = [{"ts": (base - timedelta(hours=(n - i) * 2)).isoformat()} for i in range(n)]
        anchored = []
        for k in keys:
            end = history_anchor(k, out)
            vals = history_series(k, end, n, g.rng)
            if vals is None:
                continue
            anchored.append(f"{k}={vals[-1]}")
            for i, row in enumerate(series):
                row[k] = vals[i]
        out["_history"] = series
        print(f"history: {n} points, {len(anchored)} series anchored to the snapshot "
              f"({', '.join(anchored)})")

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

    for note in cohere(out):
        print("cohere: " + note)

    fixed = []
    for num_path, list_path in DERIVED_TOTALS.items():
        lst = get_path(out, list_path)
        if isinstance(lst, list) and set_path(out, num_path, len(lst)):
            fixed.append(f"{num_path}={len(lst)}")
    if fixed:
        print("derived totals: " + ", ".join(fixed))

    build_history()

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
