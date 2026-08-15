# SOC-Sim-002 — SQL Injection → Reverse Shell → Root Persistence

**Platform:** Custom SOC Practice Lab (self-built simulation)
**Alert ID:** SOC-Sim-002
**Severity:** Critical
**Category:** Web Attack / SQL Injection / Remote Code Execution

---

## 1. Alert Summary

Production web server `web-prod-03` showed a 340% spike in HTTP 500
errors. Access logs revealed a single source IP progressing through
classic SQL injection discovery, followed by successful data extraction,
a reverse shell, and creation of an unauthorized root-privileged local
account.

| Field | Value |
|---|---|
| Affected Host | web-prod-03 (nginx) |
| Attacker IP | 198.51.100.77 |
| C2 / Payload Host IP | 45.142.212.61 |
| C2 Port | 4444 (default Metasploit Meterpreter port) |
| Alert Time | 02:09 – 02:24 UTC |
| Alert Trigger Reason | HTTP 500 error spike, SQLi pattern in WAF log |
| WAF Action | Logged only — rule was in "monitor mode" |

---

## 2. Investigation Steps

### 2.1 SQL Injection Discovery
Nginx access logs showed the attacker methodically testing payloads over
~90 seconds:

```
GET /api/v1/products?id=15' HTTP/1.1                                    500
GET /api/v1/products?id=15' OR '1'='1 HTTP/1.1                          200 48302
GET /api/v1/products?id=15' UNION SELECT username,password,1,1 FROM users-- 200 8811
GET /api/v1/products?id=15' AND SLEEP(5)-- HTTP/1.1                     200
```

MySQL slow query log independently confirmed the UNION query executed
successfully against the `users` table.

### 2.2 WAF Gap Identified
The WAF's generic SQLi rule fired and logged the UNION SELECT pattern —
but the rule was in **monitor mode only** since a recent migration,
meaning it detected but did not block the attack. This is the root
cause enabling the rest of the chain.

### 2.3 Remote Code Execution & Persistence
```
02:22 — Web shell executes curl | bash, downloads payload from 45.142.212.61
02:22–02:36 — Reverse shell connection on port 4444 (14 min duration)
02:24 — Root-privileged local account "sysupdate" created by www-data
```

**Finding:** Port 4444 is the default Metasploit Meterpreter listener
port — strong evidence of known offensive tooling rather than custom
malware.

### 2.4 Noise Ruled Out
A separate request from `203.0.113.44` returned a normal HTTP 200 with
typical payload size — consistent with a legitimate user browsing the
product page. Ruled out as unrelated.

---

## 3. MITRE ATT&CK Mapping

| Tactic | Technique |
|---|---|
| Initial Access | T1190 – Exploit Public-Facing Application |
| Initial Access | T1505 – SQL Injection |
| Execution | T1059.004 – Unix Shell |
| Persistence | T1136 – Create Account |
| Command and Control | T1071 – Application Layer Protocol (C2 over port 4444) |

---

## 4. Verdict

> **True Positive — Confirmed RCE with privilege escalation and active reverse shell.**

**Reasoning:**
- SQLi payload progression and successful UNION SELECT independently confirmed in both web and database logs.
- Reverse shell to a known offensive-tooling port (4444) confirmed via firewall logs.
- Unauthorized root account creation confirms persistence, not just a data-exposure event.
- WAF logged but did not block — a control-effectiveness gap, not a missing control.

---

## 5. Indicators of Compromise (IOC)

1. Attacker IP `198.51.100.77`.
2. Payload/C2 IP `45.142.212.61:4444`.
3. SQLi payloads targeting `/api/v1/products?id=`.
4. Unauthorized root account `sysupdate`, created by `www-data`.

---

## 6. Containment & Recommendations

- [ ] Remove the unauthorized `sysupdate` root account.
- [ ] Kill the active reverse shell process/connection.
- [ ] Forensically image the host before any reimaging.
- [ ] Switch the WAF SQLi rule from monitor to blocking mode.
- [ ] Patch the vulnerable endpoint (parameterized queries).
- [ ] Block both attacker IPs at the firewall.
- [ ] Force password resets for all accounts in the exposed `users` table.
- [ ] Check for additional persistence (cron jobs, SSH keys, other new accounts).
- [ ] Check other web servers for the same vulnerable endpoint pattern or shared backend database.

---

## 7. Closure

**Analyst Submission:** Malicious Activity Detected
**Alert Playbook Followed:** Yes
**Escalated:** Yes — confirmed RCE, privilege escalation, and potential credential-database exposure require Tier 2 and possible breach-notification review.

**Closure Note:**
> Attacker exploited an unvalidated input parameter on the products API
> to perform SQL injection, extracting data from the `users` table. A
> WAF rule detected the pattern but was misconfigured in monitor-only
> mode and did not block it. The attacker escalated to a reverse shell
> using a Metasploit-default port and created an unauthorized root
> account for persistence. Verdict: True Positive. Recommend immediate
> account removal, WAF reconfiguration, and password resets for exposed
> accounts.

---

## Key Takeaways (Lessons for Future Investigations)

- Whenever an alert shows "new account created" or "permissions
  changed," account removal must be an explicit containment step — one
  of the most commonly missed steps by junior analysts.
- Always ask *why* a control didn't stop an attack — a WAF rule that
  fires but doesn't block is a distinct, reportable finding from "no
  rule existed at all."
- A known offensive-tooling default port (e.g., 4444 for Meterpreter)
  is a strong standalone IOC — always cross-reference unusual ports
  against known tooling defaults.
- Not every request from an unfamiliar IP is malicious — validate
  response codes and payload sizes before including something in your
  IOC list.
