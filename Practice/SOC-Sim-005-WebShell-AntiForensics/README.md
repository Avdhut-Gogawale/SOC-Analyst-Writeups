# SOC-Sim-005 — Web Shell Intrusion with Attacker Anti-Forensic Cleanup

**Platform:** Custom SOC Practice Lab (self-built simulation)
**Alert ID:** SOC-Sim-005
**Severity:** Critical
**Category:** Web Attack / Malware / Command and Control (Lemon_Duck-associated infrastructure)

---

## 1. Alert Summary

An overnight shift handover flagged an unchased CPU spike on
`SRV-APP-07`. Investigation revealed a WAF that blocked two attack
attempts (XSS, path traversal) but allowed a third, obfuscated
PowerShell payload through, leading to malware download, C2 beaconing,
and attacker self-cleanup of evidence. A separate account-lockout alert
from an internal IT admin workstation was kept open pending further
verification.

| Field | Value |
|---|---|
| Affected Host | SRV-APP-07 (internal reporting application) |
| Attacker IP | 203.0.113.212 |
| C2 / Payload IP | 185.220.101.204 (Lemon_Duck-associated, per threat intel) |
| Alert Time | 02:57 – 03:42 UTC |
| WAF Result | 2 payloads blocked, 1 encoded PowerShell payload NOT blocked (no matching rule) |

---

## 2. Investigation Steps

### 2.1 WAF Log Review
```
02:57:40 - XSS payload — BLOCKED
02:57:41 - Path traversal payload — BLOCKED
02:57:55 - powershell -enc [payload] — NOT BLOCKED (no matching WAF rule) — 200
```

**Finding:** The WAF successfully blocked two known attack patterns but
had no rule covering obfuscated/encoded PowerShell — the actual root
cause enabling this intrusion.

### 2.2 Execution & C2 Timeline
```
02:58:10 — w3wp.exe spawns powershell.exe; CPU spikes to 91%
02:58:12 — update.ps1 downloaded from 185.220.101.204
02:58:15–03:40 — Repeating outbound POST /gate (6 total, ~5 min interval)
03:41:50 — cleanup.ps1 downloaded
03:41:55 — PowerShell process terminated; CPU returns to baseline
03:42:05 — update.ps1 deleted from disk (attacker self-cleanup)
03:42:10 — Scheduled task check runs — finds nothing (file already gone 5 sec earlier)
```

**Finding:** The attacker deleted their own payload file roughly 5
seconds before the automated scheduled-task check ran — deliberate
anti-forensic timing, not coincidence.

### 2.3 Threat Intel Correlation
IP `185.220.101.204` was added to the threat intel blocklist at 04:00,
associated with **Lemon_Duck** cryptomining botnet infrastructure (high
confidence). Note: this confirmation arrived *after* the attack occurred
at 02:58 — this was not a missed-intel failure, the indicator simply
wasn't available yet at attack time.

### 2.4 Related Alert — Kept Open (Not Closed)
A separate account-lockout alert from an IT admin workstation was
explained by a self-filed ticket ("bulk password reset script bug"),
submitted *after* the fact by the same admin whose machine triggered the
alert, with no prior approval trail. Kept open pending independent
verification rather than accepted at face value.

### 2.5 Noise Ruled Out
A marketing traffic spike on a separate web server was corroborated by
the overnight handover note and an independent marketing ticket for a
scheduled A/B test — ruled out as unrelated.

---

## 3. MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1190 – Exploit Public-Facing Application |
| Execution | T1059.001 – PowerShell |
| Command and Control | T1071 – Application Layer Protocol |
| Command and Control | T1105 – Ingress Tool Transfer |
| Defense Evasion | T1070.004 – File Deletion (anti-forensics) |

---

## 4. Verdict

> **True Positive — Confirmed RCE, C2 communication, and deliberate evidence destruction.**

**Reasoning:**
- WAF logs confirm the exact bypass mechanism (encoded PowerShell, no matching rule).
- EDR confirms process lineage from the web server process to PowerShell.
- Outbound firewall logs confirm both payload download and repeating C2 check-ins to Lemon_Duck-associated infrastructure.
- Self-deletion of the payload file within seconds of the scheduled forensic check confirms attacker awareness of detection timing.

---

## 5. Indicators of Compromise (IOC)

1. Attacker source IP `203.0.113.212`.
2. C2/payload IP `185.220.101.204` (Lemon_Duck-associated infrastructure).
3. Encoded PowerShell command executed via `w3wp.exe` → `powershell.exe`.
4. Repeating outbound POST beacon pattern to `/gate` (6 occurrences, ~5 min interval).
5. Self-deleted payload file `update.ps1`, removed ~5 seconds before scheduled forensic check.

**Kept Open — insufficient evidence to close:**
- Account lockout alert on IT admin workstation — self-reported explanation only, no independent corroboration.

---

## 6. Containment & Recommendations

- [ ] Isolate SRV-APP-07.
- [ ] **Forensically image the host before any remediation** — the attacker has already shown anti-forensic behavior, and remaining evidence is fragile.
- [ ] Block `185.220.101.204` at the perimeter.
- [ ] Close the WAF rule gap for encoded/obfuscated PowerShell patterns.
- [ ] Audit whether the reporting application exposed or could have exfiltrated sensitive business data via this RCE.
- [ ] Continue monitoring the IT admin workstation for independent evidence on the lockout case.
- [ ] Check other internet-facing applications for the same WAF rule gap.

---

## 7. Closure

**Analyst Submission:** Malicious Activity Detected
**Alert Playbook Followed:** Yes
**Escalated:** Yes — confirmed C2 activity and anti-forensic behavior warrant Tier 2 forensic review; account lockout alert escalated separately pending independent verification.

**Closure Note:**
> Attacker exploited an obfuscated-PowerShell gap in the WAF ruleset on
> SRV-APP-07 to achieve remote code execution, downloaded and executed a
> payload from Lemon_Duck-associated infrastructure, established
> repeating C2 beacon activity, and deleted their own payload file
> seconds before the environment's automated forensic check ran. Verdict:
> True Positive. A related account-lockout alert, explained only by a
> self-filed after-the-fact ticket, was kept open rather than closed at
> face value.

---

## Key Takeaways (Lessons for Future Investigations)

- Evidence quality matters as much as evidence existence — a
  self-reported explanation filed *after* an incident, by the same
  account implicated in it, carries less weight than a pre-approved
  change ticket and should be treated with more scrutiny before
  closure.
- When an attacker is observed cleaning up after themselves, assume
  further evidence is fragile — forensic imaging should happen *before*
  remediation, not after.
- Threat intel timing matters in reporting — note explicitly when an IOC
  becomes "known" relative to when the attack occurred, since this
  distinguishes a detection gap from a genuine missed-intel failure.
- Small, repeating outbound transfer sizes should not be assumed to be
  "just beaconing" — low-and-slow exfiltration can look identical
  without payload inspection.
