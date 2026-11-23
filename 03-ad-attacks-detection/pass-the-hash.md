# Pass-the-Hash (PtH)

## Overview

NTLM authentication never requires the plaintext password — only the **NTLM hash**. An attacker who steals a hash (e.g. from LSASS) can authenticate as that user to other machines without ever cracking it. It is one of the most common lateral movement techniques.

**Common tools:** Mimikatz `sekurlsa::pth`, Impacket (`psexec.py`, `wmiexec.py`, `smbexec.py` with `-hashes`), CrackMapExec / NetExec, Evil-WinRM

## MITRE ATT&CK

**T1550.002** — Use Alternate Authentication Material: Pass the Hash

## Log Sources & Event IDs

### On the attacker's source host (e.g. Mimikatz `sekurlsa::pth`)

| Event | What to look for |
|---|---|
| **4624** | `Logon Type = 9` (NewCredentials) + `Logon Process = seclogo` |
| 4648 | Logon with explicit credentials |
| Sysmon 10 | Process accessing `lsass.exe` (Mimikatz writes the hash into a new logon session) |

### On the target host

| Event | What to look for |
|---|---|
| **4624** | `Logon Type = 3` + `Authentication Package = NTLM` — especially workstation-to-workstation, where Kerberos would normally be used |
| 4672 | Admin privileges assigned to that logon |
| 5140 | Access to `ADMIN$`, `C$`, `IPC$` shares |
| **7045** | New service installed — PsExec (`PSEXESVC`) or Impacket psexec (random service name) |
| Sysmon 1 | `wmiprvse.exe` spawning `cmd.exe /Q /c ... 1> \\127.0.0.1\ADMIN$\__<number> 2>&1` — a well-known Impacket `wmiexec` pattern |

### On the Domain Controller

| Event | What to look for |
|---|---|
| 4776 | NTLM credential validation for the account from unusual workstations |

## Detection

**Mimikatz-style PtH on the source host:**

```spl
index=wineventlog EventCode=4624 Logon_Type=9 Logon_Process=seclogo
| table _time host Account_Name Process_Name
```

**One account making NTLM network logons to many hosts:**

```spl
index=wineventlog EventCode=4624 Logon_Type=3 Authentication_Package=NTLM
    Account_Name!="ANONYMOUS LOGON" Account_Name!="*$"
| stats dc(host) AS target_count values(host) AS targets
        BY Account_Name Source_Network_Address
| where target_count > 3
```

**Impacket wmiexec pattern:**

```spl
index=sysmon EventCode=1 ParentImage="*\\wmiprvse.exe" Image="*\\cmd.exe"
    CommandLine="*\\\\127.0.0.1\\ADMIN$\\__*"
```

## False Positives

- `runas /netonly` also produces Logon Type 9 with `seclogo` — legitimate admin use exists
- Environments still relying heavily on NTLM (legacy apps, IP-based access instead of hostnames)
- Admin tools and IT management software that connect to many hosts

## Response

1. Identify the compromised account and every host it authenticated to.
2. Check the **source** host for credential dumping (see [LSASS Dumping](lsass-dumping.md)) — that is where the hash was stolen.
3. Reset the account's password (this changes the NTLM hash).
4. Isolate affected hosts and look for persistence (new services, scheduled tasks, new accounts).

## Prevention

- **LAPS** — unique local admin passwords per machine, so one hash doesn't unlock every host
- Restrict NTLM usage where possible; prefer Kerberos
- Add privileged accounts to the **Protected Users** group (no NTLM authentication)
- Credential Guard to protect hashes in memory
- Tiered admin model — don't log on to workstations with Domain Admin accounts
