# SOC-Sim-003 — Insider Threat: Data Theft Prior to Resignation

**Platform:** Custom SOC Practice Lab (self-built simulation)
**Alert ID:** SOC-Sim-003
**Severity:** Medium
**Category:** Insider Threat / Data Exfiltration

---

## 1. Alert Summary

DLP blocked an attempt by a resigning sales employee to upload a 14.2MB
customer contracts file to a personal Google Drive. This coincided with
after-hours bulk file access, a USB mass-storage device copying 212
files, printing of pricing/contract documents, and creation of a
password-protected archive.

| Field | Value |
|---|---|
| Affected User | r.chen@acmecorp.com |
| Affected Host | WKS-SALES-0089 |
| Trigger Event | Blocked upload to personal Google Drive (DLP) |
| Alert Time | 13/05 23:41 – 14/05 11:05 |
| HR Context | Resignation submitted 13/05, moving to a named competitor |
| USB Device | SanDisk Ultra 64GB, serial logged by endpoint agent |

---

## 2. Investigation Steps

### 2.1 HR Context (Received Independently)
A manager's email forwarded to the SOC confirmed the employee had
resigned and was joining a competitor — this context shaped the
investigation from the outset toward an insider-threat hypothesis rather
than external compromise, and was corroborated by badge/VPN logs
confirming she was physically on-site throughout (ruling out remote
account compromise).

### 2.2 Timeline Reconstruction
```
13/05        — Resignation submitted (last day 24/05)
13/05 23:41  — After-hours bulk access: 47 files from Contracts share
14/05 08:15  — USB connected; 212 files copied (Contracts + Pricing)
14/05 09:10  — Password-protected zip archive created ("contracts_backup.zip")
14/05 09:30–09:45 — 8 sensitive documents printed
14/05 10:52  — Attempted Google Drive upload — BLOCKED by DLP
14/05 11:05  — Calendar invite sent to 3 teammates, unrelated subject line
```

**Finding:** The archive's innocuous name ("contracts_backup.zip") is a
soft IOC — a naming pattern intended to blend in with routine backup
activity.

### 2.3 Control Effectiveness Note
The DLP block on the Google Drive upload succeeded — this is evidence
the cloud-upload control worked as intended. However, the same data was
later moved successfully via USB, indicating a **control gap in
removable media DLP** rather than a failure of the email/cloud DLP
policy. This distinction matters for the post-incident recommendation.

### 2.4 Noise Ruled Out
A scheduled `admin_svc` mailbox export (quarterly legal-hold archive)
fired in the same window — confirmed as routine, pre-scheduled, and
unrelated to this user.

---

## 3. MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Collection | T1005 – Data from Local System |
| Exfiltration | T1052.001 – Exfiltration over USB |
| Exfiltration | T1567 – Exfiltration to Cloud Storage (attempted, blocked) |

---

## 4. Verdict

> **True Positive — Confirmed insider data collection ahead of departure to a competitor.**

**Reasoning:**
- Clear behavioral escalation across multiple channels (bulk file access → USB copy → archive creation → printing → cloud upload attempt) within a 12-hour window immediately following resignation.
- Timing directly follows the resignation submission, not a routine work pattern.
- DLP block confirms attempted exfiltration via cloud, successfully bypassed via USB.

---

## 5. Indicators of Compromise (IOC)

1. After-hours bulk file access (47 files, Contracts share).
2. USB device connection with 212 files copied (Contracts + Pricing folders).
3. Password-protected archive `contracts_backup.zip`.
4. Blocked upload attempt to personal Google Drive.
5. Bulk printing of contract/pricing documents.
6. Vague "quick sync" calendar invite to 3 teammates — unresolved, flagged for further review.

---

## 6. Containment & Recommendations

- [ ] **Notify HR and Legal before any employee-facing action** — insider cases involving a departing employee carry legal/employment implications beyond unilateral SOC action.
- [ ] Forensically image the USB device (preserve chain of custody) rather than simply retrieving it.
- [ ] Reduce/monitor account access for the remainder of the notice period, per HR/Legal guidance.
- [ ] Review the content and recipients of the "quick sync" calendar invite for possible collusion.
- [ ] Cross-reference the 212 USB files against the 47 file-share files and 8 printed documents to build a definitive "what was taken" list.
- [ ] Recommend a policy review: reduce sensitive-data access starting day 1 of a resignation notice period, not on the final day.

---

## 7. Closure

**Analyst Submission:** Malicious Activity Detected (Insider Threat)
**Alert Playbook Followed:** Yes, with HR/Legal escalation branch
**Escalated:** Yes — escalated to HR and Legal prior to any employee-facing containment action.

**Closure Note:**
> Resigning sales employee r.chen accessed and collected sensitive
> contract and pricing data across multiple channels (bulk file share
> access, USB copy, password-protected archive, printing, and an
> attempted cloud upload blocked by DLP) in the hours following her
> resignation, ahead of a move to a named competitor. Verdict: True
> Positive. Recommend HR/Legal-coordinated response, forensic
> preservation of the USB device, and access reduction for the
> remainder of her notice period.

---

## Key Takeaways (Lessons for Future Investigations)

- Insider threat cases require HR/Legal coordination **before** any
  employee-facing containment action — unlike malware/external-attacker
  cases, the SOC cannot act unilaterally here without legal risk.
- When a DLP control blocks an exfiltration attempt, explicitly note it
  as a "control success" in the report — and separately flag if the
  same data left via an uncontrolled channel (e.g., USB), since this
  identifies a specific control gap for remediation.
- Chain of custody matters when a case may lead to legal action —
  "retrieve the device" is not the same as "forensically image the
  device with documented custody."
- A vague, unrelated-subject calendar invite sent to colleagues right
  before a departure is a soft indicator worth flagging for follow-up,
  even without immediate proof of collusion.
