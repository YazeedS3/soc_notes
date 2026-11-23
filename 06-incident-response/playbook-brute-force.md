# Playbook: Brute Force / Password Spraying

**MITRE ATT&CK:** T1110.001 (Password Guessing), T1110.003 (Password Spraying)

---

## Attack patterns

| Pattern | Looks like |
|---|---|
| **Brute force** | One account, many passwords → many 4625 for the same user, often ending in lockout (4740) |
| **Password spraying** | Many accounts, one or two common passwords → few failures per user, many users, from one source. Designed to avoid lockout |
| **Credential stuffing** | Leaked username/password pairs → mix of failures and some successes, often against external services (VPN, OWA, M365) |

---

## Triggers

- Many **4625** events from one source in a short time
- Many **4771** (Kerberos pre-auth failed, code `0x18`) — spraying via Kerberos to avoid 4625
- Many **4776** with error `0xC000006A` on the DC — NTLM-based attempts
- **4740** account lockouts, especially several accounts at once
- Failed logins on VPN / OWA / cloud identity provider from one IP

---

## Investigation steps

### 1. Identify the source

- [ ] Source IP / hostname (`Source_Network_Address`, `Workstation_Name`)
- [ ] Internal or external?
- [ ] If external: reputation (AbuseIPDB, VirusTotal), geo-location, ASN (VPS / hosting provider = more suspicious)
- [ ] If internal: which host and user? An internal source suggests a **compromised host**

### 2. Understand the pattern

- [ ] Count failures per account and number of distinct accounts
- [ ] Check failure codes (`0xC0000064` = user doesn't exist → attacker using a guessed username list)
- [ ] Is the timing automated (regular intervals, high speed)?

```spl
index=wineventlog EventCode=4625 Source_Network_Address="<IP>"
| stats count values(Sub_Status) AS codes BY Account_Name
| sort - count
```

### 3. The key question: did any attempt succeed?

```spl
index=wineventlog EventCode=4624 Source_Network_Address="<IP>"
| table _time host Account_Name Logon_Type
```

- [ ] Any **4624** from the same source after the failures?
- [ ] Any successful logon for a targeted account from **another** unusual source?

### 4. If a logon succeeded — check post-logon activity

- [ ] Which hosts did the account access afterwards?
- [ ] Process creation, new services, scheduled tasks on those hosts
- [ ] Group membership changes, new accounts created
- [ ] Mailbox rules / data access (for cloud accounts)

---

## Response

### No successful logon

1. Block the source IP (firewall / WAF / conditional access)
2. Notify the owners of targeted accounts if appropriate
3. Confirm targeted accounts have MFA
4. Close as True Positive — attack attempted, not successful

### Successful logon

1. **Escalate** — this is now a compromised account incident
2. Disable the account or force a password reset, and **revoke active sessions / tokens**
3. Investigate everything the account did after the successful logon
4. If the source was internal: isolate the source host and investigate it

---

## Prevention

- MFA on all external-facing services
- Account lockout policy (balanced to avoid enabling lockout-based DoS)
- Block legacy authentication protocols (no MFA support)
- Banned / weak password lists
- Don't expose RDP directly to the internet
