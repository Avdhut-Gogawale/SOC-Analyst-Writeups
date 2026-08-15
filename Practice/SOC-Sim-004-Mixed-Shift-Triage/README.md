# SOC-Sim-004 — Mixed Shift: Adware/Smishing, Verified Admin Activity, and an Unresolved JA3 Match

**Platform:** Custom SOC Practice Lab (self-built simulation)
**Alert ID:** SOC-Sim-004
**Severity:** Mixed (Low – Medium across three unrelated alert threads)
**Category:** Mixed Triage / Adware & Smishing / False-Positive Verification / Unresolved Threat Intel Match

---

## 1. Alert Summary

Three unrelated alert threads fired in the same shift window: (1) a
marketing user reported a slow laptop, self-opening browser tabs, and a
suspicious "IT Security" text message; (2) a new local admin account and
backup command sequence on the production database server; (3) a
firewall/JA3 fingerprint match to a known Cobalt Strike default profile
on an unrelated finance workstation.

| Alert | Host | Verdict |
|---|---|---|
| Adware + smishing | WKS-MKT-0147 | True Positive |
| New admin account + RDP login | SRV-DB-02 | False Positive (verified) |
| JA3 Cobalt Strike fingerprint match | WKS-FIN-0091 | Open / Escalated |

---

## 2. Investigation Steps

### 2.1 WKS-MKT-0147 — Adware & Smishing
Proxy logs showed a browser tab opened without user interaction,
repeating beacon-like requests every ~180 seconds to a domain registered
11 months prior, and a blocked attempt to reach a newly-registered
lookalike portal — correlating with the user-reported "IT Security"
verification text message.

### 2.2 SRV-DB-02 — Verified False Positive
RDP login by the SQL service account, followed by local admin account
creation and a backup command, matched a **pre-approved, CISO-signed
change ticket** and an independent, same-time Slack confirmation from
the technician performing the work. Closed with full evidentiary
support.

### 2.3 WKS-FIN-0091 — JA3 Match (Corrected Triage)
A single 45-second TLS connection matched a JA3 fingerprint associated
with a known Cobalt Strike default profile, per a threat intel feed
pushed hours earlier. EDR showed no process anomalies.

**Initial (incorrect) triage:** closed as false positive, reasoning that
the user was in a Zoom call at the same time and the connection was
short with minimal data exchanged.

**Correction on review:** this closure was invalid for two reasons —
(1) short duration/low data volume is *consistent* with a single C2
check-in beacon, not evidence of innocence; (2) the Zoom-call
explanation doesn't actually account for *this specific* connection —
Zoom uses its own dedicated infrastructure, so coincidental timing to an
unrelated IP is not causation. **A high-confidence threat intel match
requires a direct, verifiable explanation to close — not a plausible
nearby event.** Status changed to Open/Escalated.

---

## 3. MITRE ATT&CK Mapping

| Tactic | Technique | Host |
|---|---|---|
| Initial Access | T1660 – Phishing via SMS (Smishing) | WKS-MKT-0147 |
| Command and Control | T1071 – Application Layer Protocol (unconfirmed) | WKS-FIN-0091 |

---

## 4. Verdict

> **Mixed: 1 True Positive (WKS-MKT-0147), 1 Confirmed False Positive (SRV-DB-02), 1 Open/Escalated (WKS-FIN-0091).**

**Reasoning:**
- WKS-MKT-0147: independently corroborated by user report, proxy beacon pattern, and silent tab-opening behavior.
- SRV-DB-02: fully corroborated by a pre-approved change ticket and independent Slack confirmation — genuine false positive.
- WKS-FIN-0091: high-confidence threat intel signal with no verified causal explanation — held open pending Tier 2 review rather than closed on coincidental timing.

---

## 5. Indicators of Compromise (IOC)

**Confirmed (WKS-MKT-0147):**
1. Smishing text impersonating internal IT Security.
2. Chrome tab opened without user click.
3. Repeating beacon pattern (~180 sec interval) to an unverified domain.

**False Positive (SRV-DB-02) — with evidence:**
- New local admin account `backup_admin` and RDP login from IT help desk technician's machine — matched Change Ticket #55098 (CISO-approved) and same-time Slack confirmation.

**Open (WKS-FIN-0091):**
- JA3 fingerprint match to known Cobalt Strike default profile on a single 45-second TLS connection — pending Tier 2/threat intel review.

---

## 6. Containment & Recommendations

- [ ] Isolate WKS-MKT-0147, block the tracking/ad domains.
- [ ] Warn the organization about the smishing campaign impersonating IT Security.
- [ ] Confirm no credentials were entered before the lookalike domain was blocked.
- [ ] Escalate WKS-FIN-0091 to Tier 2/threat intel for deeper packet-level review — do not close.
- [ ] Place WKS-FIN-0091 under closer monitoring or preventive isolation pending confirmation.
- [ ] Close SRV-DB-02 with documentation attached; no action needed.

---

## 7. Closure

**Analyst Submission:** Mixed — 1 Malicious Activity Detected, 1 False Positive (documented), 1 Escalated/Unresolved
**Alert Playbook Followed:** Yes
**Escalated:** Yes, for WKS-FIN-0091 only.

**Closure Note:**
> Three unrelated alerts triaged in one shift. WKS-MKT-0147 confirmed as
> a true positive (adware + smishing). SRV-DB-02 confirmed false
> positive via a pre-approved change ticket and independent
> confirmation. WKS-FIN-0091's JA3-Cobalt-Strike match was initially
> closed based on coincidental Zoom-call timing; on review this was
> corrected and escalated, since a high-confidence threat intel match
> requires verified causal evidence to close, not proximity to unrelated
> activity.

---

## Key Takeaways (Lessons for Future Investigations)

- Every alert on the board needs to be explicitly addressed — as
  confirmed, false positive with evidence, or open — silence on an
  alert reads the same as missing it.
- The bar for closing a high-confidence threat intel match (named
  malware family, JA3 fingerprint, known-bad hash) is much higher than
  "there's a plausible nearby explanation." Coincidental timing is not
  the same as a verified causal explanation.
- Not all "explained" alerts carry equal evidentiary weight — a
  pre-approved, signed-off change ticket is much stronger evidence than
  an after-the-fact assumption about unrelated user activity.
