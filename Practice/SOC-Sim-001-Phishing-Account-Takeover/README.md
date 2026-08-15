# SOC-Sim-001 — Phishing-Led Account Takeover & Mailbox Persistence

**Platform:** Custom SOC Practice Lab (self-built simulation)
**Alert ID:** SOC-Sim-001
**Severity:** High
**Category:** Phishing / Account Takeover / BEC (Business Email Compromise)

---

## 1. Alert Summary

A correlated set of SIEM alerts fired within a 40-minute window for user
**j.martinez@acmecorp.com**: six failed logins followed by a successful
login from a foreign IP, a suspicious PowerShell process spawned from
Outlook, a new external mail-forwarding rule routed through a Tor exit
node, and an "impossible travel" alert. A helpdesk ticket from the user
independently reported clicking a spoofed "DocuSign" link.

| Field | Value |
|---|---|
| Affected User | j.martinez@acmecorp.com |
| Affected Host | WKS-FIN-0231 |
| Attacker IP (login) | 41.203.78.114 |
| Forwarding Rule Source IP | 185.220.101.47 (Tor exit node) |
| Alert Time | 07:41 – 08:12 UTC |
| Alert Trigger Reason | Multiple failed logins + success, new mail rule, impossible travel |
| Auth Method Used | Legacy authentication (BAV2ROPC) — no MFA support |

---

## 2. Investigation Steps

### 2.1 Phishing Delivery
Mail gateway logs showed the initiating email failed SPF (softfail) and
had no DKIM record, but was delivered because the sender domain had been
allowlisted by the user the previous month.

```
FROM: docusign-notify@acmecorp-secure.com
SUBJECT: Contract Awaiting Your Signature - Action Required
LINK: hxxps://acme-verify-portal[.]com/auth/login
SPF: softfail | DKIM: none
```

**Finding:** The lookalike domain hosted a credential-harvesting page
mimicking a legitimate document-signing workflow.

### 2.2 Authentication Timeline
```
07:41–07:42 — 6 failed logins, then 1 success (legacy auth, no MFA)
08:03 — Suspicious encoded PowerShell spawned from Outlook
08:11 — Malicious inbox forwarding rule created (rule name blank: "..")
08:12 — Impossible travel: Chicago badge-in vs. Bucharest login
```

**Critical finding:** The successful login used the legacy authentication
client `BAV2ROPC`, which does not support MFA — this is the likely
MFA-bypass vector, not brute-force luck. The failed logins preceding it
were not automated brute-force; they occurred *after* the phishing email
was delivered, consistent with an attacker manually testing a harvested
credential.

### 2.3 Persistence Mechanism
A new inbox rule was created with a blank name (`..`), forwarding all
incoming mail to an external Proton Mail address and deleting the
original from the inbox — a classic BEC technique to hide the rule from
casual mailbox review while maintaining ongoing visibility into the
account.

---

## 3. MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1566 – Phishing |
| Initial Access | T1078 – Valid Accounts (post-compromise) |
| Execution | T1059.001 – PowerShell |
| Persistence | T1114.003 – Email Forwarding Rule |
| Defense Evasion | T1556 – Modify Authentication Process (legacy auth / MFA bypass) |

---

## 4. Verdict

> **True Positive — Confirmed phishing-led account takeover with active mailbox persistence.**

**Reasoning:**
- Phishing email preceded the failed/successful login sequence, ruling out standalone brute-force.
- Legacy auth protocol bypassed MFA entirely.
- Forwarding rule to an external address via Tor confirms an active, ongoing data-collection mechanism, not a one-time login event.
- Impossible travel independently corroborates the account was under attacker control from a second geography.

---

## 5. Indicators of Compromise (IOC)

1. Phishing domain `acme-verify-portal[.]com` — credential-harvesting page.
2. Attacker login IP `41.203.78.114`.
3. Forwarding-rule source IP `185.220.101.47` (Tor exit node).
4. Legacy auth client `BAV2ROPC` used for the successful login.
5. Malicious mail rule with blank name (`..`), forwarding to `r.kowalski92@protonmail.com`.

---

## 6. Containment & Recommendations

- [ ] Disable the account and force a password reset.
- [ ] Revoke all active sessions and OAuth tokens (a password reset alone does not invalidate already-issued tokens).
- [ ] Remove the malicious inbox forwarding rule.
- [ ] Isolate host WKS-FIN-0231 via EDR.
- [ ] Block the phishing domain and the Tor exit IP at the perimeter.
- [ ] Disable legacy authentication protocols organization-wide if not already enforced.
- [ ] Check for other newly created forwarding rules across the tenant.
- [ ] Warn other users of the same phishing campaign/sender infrastructure.

---

## 7. Closure

**Analyst Submission:** Malicious Activity Detected
**Alert Playbook Followed:** Yes
**Escalated:** Yes — active mailbox persistence and legacy-auth MFA bypass require Tier 2 review and org-wide legacy auth policy check.

**Closure Note:**
> User j.martinez@acmecorp.com fell victim to a spoofed DocuSign phishing
> email, entering credentials on a lookalike domain. Attacker logged in
> using legacy authentication (bypassing MFA), created a hidden mail
> forwarding rule routed through a Tor exit node, and triggered an
> impossible-travel event confirming active control of the account.
> Verdict: True Positive. Recommend token revocation, rule removal,
> legacy auth disablement, and org-wide phishing campaign check.

---

## Key Takeaways (Lessons for Future Investigations)

- Always build the full timeline before naming an attack type — a
  failed/successful login pattern isn't automatically brute-force if a
  phishing email preceded it.
- Legacy authentication protocols are a common, often-overlooked MFA
  bypass vector — always check the auth client/protocol field on a
  successful login, not just source IP and timestamp.
- Password resets alone do not kill active sessions or OAuth tokens —
  token revocation is a separate, frequently-forgotten containment step.
- A mail rule with a blank or obfuscated name is itself a red flag for
  BEC persistence and should be searched for proactively during mailbox
  compromise investigations.
