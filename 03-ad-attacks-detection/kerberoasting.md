# Kerberoasting

## Overview

Any authenticated domain user can request a Kerberos service ticket (TGS) for any account that has a **Service Principal Name (SPN)**. Part of that ticket is encrypted with the service account's password hash. The attacker requests tickets, takes them offline, and cracks them to recover the service account password.

Service accounts often have weak, never-rotated passwords and high privileges — which makes this a common path to domain compromise.

**Common tools:** Rubeus (`kerberoast`), Impacket `GetUserSPNs.py`, PowerView `Invoke-Kerberoast`

## MITRE ATT&CK

**T1558.003** — Steal or Forge Kerberos Tickets: Kerberoasting

## Log Sources & Event IDs

| Source | Event | What to look for |
|---|---|---|
| DC Security log | **4769** (TGS requested) | `Ticket Encryption Type = 0x17` (RC4) |
| DC Security log | 4769 | One account requesting tickets for **many different SPNs** in a short time |
| DC Security log | 4769 | `Service Name` not ending in `$` (user-based service accounts, not computers) and not `krbtgt` |
| Endpoint | Sysmon 1 / 4688 | `Rubeus.exe`, `GetUserSPNs`, suspicious command lines |
| Endpoint | PowerShell 4104 | `Invoke-Kerberoast`, `KerberosRequestorSecurityToken` |
| Network | Kerberos traffic | TGS-REP (`kerberos.msg_type == 13`) with `kerberos.etype == 23` |

> **Why RC4?** Attackers request RC4 tickets because they are much faster to crack than AES. In a modern domain where AES is the norm, RC4 service tickets stand out.

## Detection

**Many RC4 service tickets requested by one account:**

```spl
index=wineventlog EventCode=4769 Ticket_Encryption_Type=0x17
    Service_Name!="*$" Service_Name!="krbtgt"
| stats count dc(Service_Name) AS unique_spns values(Service_Name) AS spns
        BY Account_Name Client_Address
| where unique_spns >= 3
| sort - unique_spns
```

**Logic:** Normal users request tickets for a few services they actually use. An account requesting RC4 tickets for many different service accounts in a short window is suspicious.

**High-confidence option — honeypot SPN:** Create a fake service account with an SPN that no real application uses. Any 4769 for that account is almost certainly an attacker enumerating SPNs.

```spl
index=wineventlog EventCode=4769 Service_Name="svc_honeypot"
```

## False Positives

- Legacy applications or old systems that only support RC4
- Vulnerability scanners and some monitoring tools
- Service accounts explicitly configured for RC4 (`msDS-SupportedEncryptionTypes`)

Baseline which services legitimately use RC4 and exclude them.

## Response

1. Identify the requesting account and the source host (`Client_Address`).
2. Check the source host for attack tooling: Sysmon 1 / 4688 process creation, PowerShell 4104.
3. Determine whether the requesting user is compromised (unusual logon times, locations, hosts).
4. **Reset the passwords of all targeted service accounts** — assume the tickets are being cracked.
5. Isolate the source host if malicious activity is confirmed.

## Prevention

- Long, random service account passwords (25+ characters)
- Use **Group Managed Service Accounts (gMSA)** — passwords are rotated automatically
- Disable RC4 for Kerberos where possible
- Review which accounts have SPNs and remove unnecessary ones
- Avoid giving service accounts Domain Admin rights
