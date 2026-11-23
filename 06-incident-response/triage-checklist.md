# Alert Triage Checklist

A repeatable process for handling an alert from start to finish.

---

## 1. Understand the alert

- [ ] What rule fired, and what is it designed to detect?
- [ ] Which MITRE ATT&CK technique does it map to?
- [ ] What is the default severity?
- [ ] Has this rule produced false positives before? (check previous tickets)

## 2. Collect the basics — the 5 W's

- [ ] **Who** — user account(s) involved
- [ ] **What** — process, command line, file, hash
- [ ] **When** — first seen, last seen, timezone
- [ ] **Where** — hostname, IP, network segment
- [ ] **How** — parent process, logon type, source of the connection

## 3. Enrich

- [ ] **IP / domain reputation** — VirusTotal, AbuseIPDB, URLhaus, Cisco Talos
- [ ] **File hash** — VirusTotal, MalwareBazaar
- [ ] **Asset context** — is the host critical (DC, server, executive laptop)?
- [ ] **User context** — role, privileges, normal working hours, department
- [ ] **Geo / ASN** of external IPs — is the location expected for this user?

## 4. Context — is this normal?

- [ ] Has this user / host done this before? (look back 7–30 days)
- [ ] Do other hosts show the same behavior? (single host vs. widespread)
- [ ] Is there a change ticket, maintenance window, or known admin activity?
- [ ] What happened on the host **before and after** the alert? (build a short timeline)

## 5. Decide

| Verdict | Meaning | Action |
|---|---|---|
| **True Positive** | Malicious activity confirmed | Escalate / start incident response |
| **Benign True Positive** | Rule worked correctly, but the activity is authorized (e.g. pentest, admin task) | Document, close, consider tuning |
| **False Positive** | Rule fired on activity it shouldn't match | Document, close, **tune the rule** |
| **Needs more info** | Not enough evidence yet | Escalate to Tier 2 / contact the user or asset owner |

## 6. If it's a True Positive — first containment steps

- [ ] Escalate according to the escalation matrix
- [ ] Isolate the host (EDR network containment) if spreading or data theft is possible
- [ ] Disable / reset compromised accounts
- [ ] Block malicious IPs, domains, hashes
- [ ] Preserve evidence before making changes (memory, logs, disk if required)
- [ ] Scope: search for the same IOCs across the whole environment

## 7. Document

Every ticket should let another analyst understand the case without asking you:

- [ ] Summary of what happened (2–3 sentences)
- [ ] Timeline of key events
- [ ] IOCs (IPs, domains, hashes, accounts, hosts)
- [ ] Evidence (queries used, screenshots, log excerpts)
- [ ] Verdict and reasoning
- [ ] Actions taken and recommendations (including rule tuning)
