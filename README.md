# SOC Detection Notes

**Attack → Detection notes for SOC analysts.**

I come from an offensive-security background (CRTP). This repo flips that knowledge around: for each technique I know how to perform, I document what it looks like from the defender's side — the logs it leaves behind, how to detect it, what can cause false positives, and how to respond.

> **Status:** Work in progress. Detections are written from documentation and training labs. A full home lab (Active Directory + Sysmon + Splunk) to validate every query is in progress — see the [Roadmap](#roadmap).

---

## Contents

| Folder | What's inside |
|---|---|
| [01-windows-event-logs](01-windows-event-logs/) | Key Windows Security Event IDs, logon types, and failure codes |
| [02-sysmon](02-sysmon/) | Important Sysmon events and suspicious process patterns |
| [03-ad-attacks-detection](03-ad-attacks-detection/) | Active Directory attacks and how to detect each one |
| [04-splunk-queries](04-splunk-queries/) | Ready-to-adapt Splunk detection queries |
| [05-network-analysis](05-network-analysis/) | Wireshark filters and C2 beaconing indicators |
| [06-incident-response](06-incident-response/) | Alert triage checklist and response playbooks |

### Active Directory attacks covered

| Attack | MITRE ATT&CK | Key evidence |
|---|---|---|
| [Kerberoasting](03-ad-attacks-detection/kerberoasting.md) | T1558.003 | 4769 with RC4 (0x17) encryption |
| [AS-REP Roasting](03-ad-attacks-detection/as-rep-roasting.md) | T1558.004 | 4768 with Pre-Auth Type 0 |
| [DCSync](03-ad-attacks-detection/dcsync.md) | T1003.006 | 4662 with replication GUIDs from a non-DC account |
| [Pass-the-Hash](03-ad-attacks-detection/pass-the-hash.md) | T1550.002 | 4624 Logon Type 9 (seclogo) / NTLM Type 3 logons |
| [LSASS Dumping](03-ad-attacks-detection/lsass-dumping.md) | T1003.001 | Sysmon Event 10 targeting lsass.exe |

---

## Note template

Every attack note follows the same structure:

1. **Overview** — what the attack does, in short
2. **MITRE ATT&CK** — technique ID
3. **Log Sources & Event IDs** — what evidence it leaves
4. **Detection** — Splunk query and logic
5. **False Positives** — legitimate activity that looks similar
6. **Response** — what an analyst should do when the alert fires
7. **Prevention** — how to reduce the risk

---

## Roadmap

- [x] Windows Event IDs cheat sheet
- [x] Sysmon key events
- [x] Detection notes for 5 AD attacks
- [x] Splunk query collection
- [x] Network analysis notes (Wireshark, C2 beaconing)
- [x] Triage checklist and brute-force playbook
- [ ] Home lab: AD + Sysmon + Splunk
- [ ] Validate every query in the lab and add screenshots of real results
- [ ] Convert detections to Sigma rules
- [ ] Detect my own custom C2 framework (network + host artifacts)
- [ ] More playbooks: phishing, malware execution, suspicious PowerShell

---

## Notes on the queries

- **Field names vary.** They depend on how logs are ingested (Splunk Add-on for Microsoft Windows, `WinEventLog` vs `XmlWinEventLog`, Sysmon add-on). Adjust `index`, `sourcetype`, and field names to your environment.
- **Thresholds are starting points.** Tune them against your own baseline before using them in production.
- **Audit policy matters.** Many events (4688 command line, 4662, 4104) are not logged by default. Each note mentions what needs to be enabled.

---

## References

- [MITRE ATT&CK](https://attack.mitre.org/)
- [Ultimate Windows Security — Event ID Encyclopedia](https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/)
- [Microsoft — Advanced security audit policy](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/advanced-security-auditing)
- [Sysinternals Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config)
- [Olaf Hartong sysmon-modular](https://github.com/olafhartong/sysmon-modular)
- [JPCERT/CC — Detecting Lateral Movement through Tracking Event Logs](https://www.jpcert.or.jp/english/pub/sr/ir_research.html)
- [SigmaHQ rules](https://github.com/SigmaHQ/sigma)

---

## Author

**Yazeed Alsalahat** — Network Engineering and Security graduate, CRTP
[LinkedIn](https://www.linkedin.com/in/yazeed-salahat-235a36244/) · [GitHub](https://github.com/YazeedS3)
