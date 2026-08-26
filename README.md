# SOC Analyst Investigation Portfolio

A portfolio of hands-on security alert investigations practiced on the [LetsDefend](https://letsdefend.io) platform. This repository documents my approach to SIEM monitoring, log correlation, and incident response in a simulated Security Operations Center (SOC) environment, as I work toward a career as a SOC Analyst.

Each case below is a real investigation I worked through myself, using LetsDefend's SIEM, EDR, email security, and log management tools. I used AI-assisted research and review (Claude) as a learning aid throughout — to help me understand attacker techniques and malware families I hadn't encountered before, catch gaps or imprecise reasoning in my analysis, and structure the final writeups — but the underlying investigation (reading the logs, pulling and correlating evidence, reaching a verdict) is my own work.

---

## About Me

I'm Avdhut Gogawale, a recent Electronics and Telecommunication Engineering graduate transitioning into a SOC Analyst role, based in Pune, Maharashtra. I'm building this portfolio through self-directed, hands-on practice — investigating simulated alerts, researching the techniques and malware families behind them, and documenting each case the way I would for a real ticket.

**Practice platforms:** LetsDefend (alert investigation) · TryHackMe (100+ rooms completed across various security domains)

---

## What This Portfolio Demonstrates

- **Incident Triage** — assessing alerts to determine severity, scope, and validity (True Positive vs. False Positive)
- **Log Analysis** — correlating data across SIEM, EDR, firewall, web proxy, and email/Exchange logs to reconstruct full attack chains
- **Threat Intelligence Correlation** — using VirusTotal and AbuseIPDB to enrich indicators and confirm malicious infrastructure
- **MITRE ATT&CK Mapping** — identifying the specific tactics and techniques behind each attack
- **Clear, Evidence-Based Reporting** — distinguishing what the evidence actually confirms from what remains an open question, rather than overstating findings

---

## Investigation Index

| Alert ID | Title | Category | Severity | Key Technique |
|---|---|---|---|---|
| [SOC176](Brute-Force/SOC176-RDP-Brute-Force-Full.md/) | RDP Brute Force Detected | Brute Force | Medium | T1110 – Brute Force, weak username matching hostname |
| [SOC246](Brute-Force/SOC246-Forced-Authentication.md/) | Forced Authentication Detected | Brute Force | Medium | T1110 – Web login brute force, plaintext HTTP credential exposure |
| [SOC282](Phishing/SOC282-Phishing-AsyncRAT.md/) | Phishing Alert – Deceptive Mail Detected | Phishing | Medium → Critical | AsyncRAT delivery, confirmed C2 callback |
| [SOC275](Phishing/SOC275-Application-Token-Steal-Attempt.md/) | Application Token Steal Attempt Detected | Phishing | Medium | Discord-themed credential/token phishing |
| [SOC251](Phishing/SOC251-Quishing-QR-Phishing.md/) | Quishing Detected (QR Code Phishing) | Phishing | Medium | T1566.002 – QR-code phishing, IPFS-hosted payload |
| [SOC326](Phishing/SOC326-Impersonating-Domain-MX-Change.md/) | Impersonating Domain MX Record Change Detected | Phishing | Medium | Typosquat domain, CTI-driven detection |
| [SOC336](Malware/SOC336-CVE-2025-21298-Zero-Click-RCE.md/) | Windows OLE Zero-Click RCE Detected (CVE-2025-21298) | Malware | Critical | Zero-click RCE, regsvr32 "Squiblydoo", Sliver C2 |
| [SOC338](Malware/SOC338-Lumma-Stealer-ClickFix.md/) | Lumma Stealer – DLL Side-Loading via Click Fix Phishing | Data Leakage | Critical | ClickFix technique, Emmenhtal loader, disguised payload |
| [SOC335](Malware/SOC335-CVE-2024-49138-Privilege-Escalation.md/) | CVE-2024-49138 Exploitation Detected | Malware | Medium → Critical | RDP brute force → CLFS privilege escalation to SYSTEM |
| [SOC250](Data-Leakage/SOC250-APT35-HyperScrape.md/) | APT35 HyperScrape Data Exfiltration Tool Detected | Data Leakage | Medium → Critical | Nation-state actor (Charming Kitten), confirmed mailbox exfiltration |

*Portfolio in progress — more cases (SQL injection, PowerShell abuse, and further CVE-based exploitation) being added as I work through them.*

---

## Investigation Methodology

Every case in this repository follows the same structure:

1. **Alert Summary** — what triggered the alert and initial context
2. **Investigation Timeline** — reconstructed chronology of the attack
3. **Investigation Steps** — log analysis across SIEM, EDR, firewall, proxy, and email sources, with evidence screenshots
4. **Threat Intelligence Enrichment** — IOC lookups via VirusTotal and AbuseIPDB, with crowdsourced threat context where available
5. **MITRE ATT&CK Mapping** — tactics and techniques identified
6. **Verdict** — True/False Positive determination with explicit reasoning, distinguishing *confirmed* findings from *unconfirmed/open* items
7. **Containment & Recommendations** — prioritized response actions
8. **Closure Note** — concise summary suitable for ticket closure
9. **Key Takeaways** — lessons I applied to subsequent investigations

## Tools Used

- **SIEM / Log Management:** LetsDefend platform (Exchange, Proxy, Firewall, OS/Windows Event logs, EDR process telemetry)
- **Threat Intelligence:** VirusTotal, AbuseIPDB
- **Frameworks:** MITRE ATT&CK
- **Research/Review Aid:** Claude (Anthropic) — used to research unfamiliar attacker techniques and malware families, and to review my draft findings for gaps, imprecise claims, or missed evidence before finalizing each writeup

## Repository Structure

```
SOC-Analyst-Writeups/
├── Investigations/
│   ├── Brute-Force/
│   ├── Phishing/
│   ├── Malware/
│   ├── Web-Attacks/
│   └── Data-Leakage/
└── Practice-Labs/
```

Each investigation folder contains a full markdown writeup and a `screenshots/` subfolder with the supporting evidence referenced inline in the report.

---

## Connect

- LinkedIn: [linkedin.com/in/avdhut-gogawale](https://www.linkedin.com/in/avdhut-gogawale/)
- Email: avdhutgogawale@gmail.com
