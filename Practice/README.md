# Practice — SOC Simulation Scenarios

Custom AI-generated investigation scenarios
for SOC analyst methodology practice.

Each scenario provides realistic SIEM alerts,
raw log snippets, Sysmon events, and user
context with signal and noise mixed in —
mirroring real SOC shift conditions.

---

## Scenario Index

| Case | Attack Chain | IOCs | Status |
|------|-------------|------|--------|
| [SOC-Sim-001](./SOC-Sim-001-Phishing-Account-Takeover/) | Phishing → Account Takeover | Simulated | Complete |
| [SOC-Sim-002](./SOC-Sim-002-SQLi-to-RCE-Persistence/) | SQLi → RCE → Persistence | Simulated | Complete |
| [SOC-Sim-003](./SOC-Sim-003-Insider-Threat-Data-Exfil/) | Insider Threat → Data Exfil | Simulated | Complete |
| [SOC-Sim-004](./SOC-Sim-004-Mixed-Shift-Triage/) | Mixed Shift Triage | Simulated | Complete |
| [SOC-Sim-005](./SOC-Sim-005-WebShell-AntiForensics/) | WebShell → AntiForensics | Simulated | Complete |
| [SOC-Sim-006](./SOC-Sim-006-Phishing-AsyncRAT/) | Phishing → AsyncRAT C2 | Real IOCs ✅ | Complete |

---

## IOC Note

**SOC-Sim-001 to 005:** Fictional IOCs used
for investigation methodology practice.
Enrichment workflow documented but IPs/domains
are not publicly known threat indicators.

**SOC-Sim-006:** Real IOCs verified on
VirusTotal and AbuseIPDB. Screenshots of
enrichment results in screenshots/ folder.

---

## Methodology Per Case

1. Alert context and hypothesis
2. Log analysis (Auth → Network → Endpoint)
3. IOC enrichment
4. Attack timeline reconstruction
5. TP/FP verdict with justification
6. Containment recommendation
7. MITRE ATT&CK mapping
