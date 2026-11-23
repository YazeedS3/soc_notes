# AS-REP Roasting

## Overview

Normally, a user must prove they know their password (**Kerberos pre-authentication**) before the DC returns a TGT. If an account has **"Do not require Kerberos preauthentication"** enabled, anyone can request an AS-REP for it — and part of that response is encrypted with the user's password hash. The attacker cracks it offline.

Unlike Kerberoasting, the attacker may not even need valid domain credentials if they already have a list of usernames.

**Common tools:** Rubeus (`asreproast`), Impacket `GetNPUsers.py`

## MITRE ATT&CK

**T1558.004** — Steal or Forge Kerberos Tickets: AS-REP Roasting

## Log Sources & Event IDs

| Source | Event | What to look for |
|---|---|---|
| DC Security log | **4768** (TGT requested) | `Pre-Authentication Type = 0` (no pre-auth) |
| DC Security log | 4768 | `Ticket Encryption Type = 0x17` (RC4) |
| DC Security log | **4738** (user account changed) | UAC change: `'Don't Require Preauth' - Enabled` — an attacker may set this flag to make an account roastable |
| Endpoint | Sysmon 1 / 4688 | `Rubeus.exe asreproast`, `GetNPUsers` |
| Network | Kerberos traffic | AS-REP (`kerberos.msg_type == 11`) with `kerberos.etype == 23` |

## Detection

**TGT requests without pre-authentication:**

```spl
index=wineventlog EventCode=4768 Pre_Authentication_Type=0
| stats count values(Client_Address) AS sources values(Ticket_Encryption_Type) AS enc_types
        BY Account_Name
| sort - count
```

**Someone disabled pre-authentication on an account:**

```spl
index=wineventlog EventCode=4738 "Don't Require Preauth' - Enabled"
| table _time host Account_Name Target_Account_Name
```

## Proactive Hunting

Find every account that is currently AS-REP roastable:

```powershell
Get-ADUser -Filter 'DoesNotRequirePreAuth -eq $true' -Properties DoesNotRequirePreAuth |
    Select-Object SamAccountName, Enabled
```

Every account in this list should have a documented business reason.

## False Positives

- Legacy applications or Kerberos clients that genuinely need pre-auth disabled (rare)
- Some Linux / non-Windows Kerberos integrations

If an account legitimately has pre-auth disabled, its TGT requests will appear regularly from the same known source — baseline it.

## Response

1. Identify the source IP and whether it belongs to a known system.
2. Check if the targeted accounts actually need pre-auth disabled — re-enable it if not.
3. **Reset passwords** for targeted accounts.
4. If a 4738 shows the flag was recently enabled, investigate **who** changed it — that account is likely compromised.

## Prevention

- Keep Kerberos pre-authentication enabled for every account (the default)
- Strong passwords on any account that must have it disabled
- Alert on any change that disables pre-authentication (4738)
