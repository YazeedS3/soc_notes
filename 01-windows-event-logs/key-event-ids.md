# Key Windows Event IDs

The Security log events every SOC analyst should recognize on sight. Unless noted, these are in the **Security** log.

---

## Authentication

| Event ID | Meaning | Why it matters |
|---|---|---|
| 4624 | Successful logon | Check **Logon Type** and source IP — the baseline for almost every investigation |
| 4625 | Failed logon | Brute force, password spraying (check Status / Sub Status) |
| 4634 / 4647 | Logoff / user-initiated logoff | Session duration, timeline building |
| 4648 | Logon with explicit credentials | `runas`, lateral movement with alternate credentials |
| 4672 | Special privileges assigned to new logon | Admin-level logon — watch for unexpected accounts |
| 4740 | Account locked out | Brute force result; logged on the DC |

### Logon Types (4624 / 4625)

| Type | Name | Typical source |
|---|---|---|
| 2 | Interactive | Keyboard logon at the machine |
| 3 | Network | SMB share access, PsExec, WMI, many lateral-movement tools |
| 4 | Batch | Scheduled tasks |
| 5 | Service | Service starting under an account |
| 7 | Unlock | Workstation unlock |
| 8 | NetworkCleartext | Credentials sent in clear text (e.g. IIS basic auth) |
| 9 | NewCredentials | `runas /netonly`, **Mimikatz `sekurlsa::pth`** |
| 10 | RemoteInteractive | RDP |
| 11 | CachedInteractive | Logon with cached domain credentials (DC unreachable) |

### 4625 Status / Sub Status codes

| Code | Meaning | What it suggests |
|---|---|---|
| 0xC0000064 | User name does not exist | Username enumeration / spraying with a bad list |
| 0xC000006A | Correct user, wrong password | Password guessing |
| 0xC0000234 | Account locked out | Brute force continued after lockout |
| 0xC0000072 | Account disabled | Attempt to use an old/disabled account |
| 0xC000006F | Logon outside allowed hours | Possible misuse of valid credentials |
| 0xC0000071 | Password expired | Usually benign |
| 0xC0000193 | Account expired | Old account being used |

---

## Kerberos & NTLM (Domain Controller)

| Event ID | Meaning | Why it matters |
|---|---|---|
| 4768 | Kerberos TGT requested (AS-REQ) | **AS-REP Roasting** when Pre-Auth Type = 0 |
| 4769 | Kerberos service ticket requested (TGS-REQ) | **Kerberoasting** when Encryption Type = 0x17 (RC4) |
| 4771 | Kerberos pre-authentication failed | Kerberos-based brute force / spraying |
| 4776 | DC validated NTLM credentials | NTLM usage, Pass-the-Hash, NTLM brute force |

### Kerberos failure codes (4768 / 4771)

| Code | Meaning |
|---|---|
| 0x6 | Username does not exist |
| 0x12 | Account disabled, expired, or locked out |
| 0x17 | Password expired |
| 0x18 | Wrong password (pre-auth failed) |
| 0x25 | Clock skew too large |

### Kerberos encryption types

| Value | Algorithm | Note |
|---|---|---|
| 0x11 | AES128 | Normal in modern domains |
| 0x12 | AES256 | Normal in modern domains |
| 0x17 | RC4-HMAC | Weak — the classic Kerberoasting / AS-REP Roasting signal |

---

## Account & group management

| Event ID | Meaning |
|---|---|
| 4720 | User account created |
| 4722 | User account enabled |
| 4724 | Password reset attempt |
| 4726 | User account deleted |
| 4738 | User account changed (watch UAC flag changes, e.g. "Don't Require Preauth") |
| 4728 | Member added to a **global** security group (e.g. Domain Admins) |
| 4732 | Member added to a **local** security group (e.g. Administrators) |
| 4756 | Member added to a **universal** security group (e.g. Enterprise Admins) |

---

## Execution & persistence

| Event ID | Log | Meaning |
|---|---|---|
| 4688 | Security | Process created (enable "Include command line in process creation events") |
| 4697 | Security | Service installed |
| 7045 | System | New service installed — PsExec, Impacket, Cobalt Strike-style lateral movement |
| 4698 | Security | Scheduled task created |
| 4702 | Security | Scheduled task updated |
| 4657 | Security | Registry value modified (needs SACL) |

---

## PowerShell

Log: `Microsoft-Windows-PowerShell/Operational`

| Event ID | Meaning |
|---|---|
| 4103 | Module logging (pipeline execution details) |
| 4104 | **Script block logging** — the de-obfuscated script content; the most valuable PowerShell event |

---

## Directory service & object access

| Event ID | Meaning | Why it matters |
|---|---|---|
| 4662 | Operation performed on an AD object | **DCSync** detection (replication GUIDs) |
| 4663 | Attempt to access an object | File / registry access auditing |
| 5140 | Network share accessed | Access to `ADMIN$`, `C$`, `IPC$` during lateral movement |
| 5145 | Detailed file share access | Which file was accessed over SMB |

---

## Defense evasion

| Event ID | Log | Meaning |
|---|---|---|
| 1102 | Security | Security audit log cleared — **always investigate** |
| 104 | System | System log cleared |
| 4719 | Security | System audit policy changed |

---

## Audit policy reminders

Several of these events are **not logged by default**:

- **4688 command line** → GPO: *Administrative Templates > System > Audit Process Creation > Include command line in process creation events*
- **4662** → *Audit Directory Service Access* + a SACL on the domain object
- **4104** → *Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging*
- **5140 / 5145** → *Audit File Share* / *Audit Detailed File Share*
