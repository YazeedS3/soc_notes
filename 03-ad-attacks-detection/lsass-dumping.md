# LSASS Credential Dumping

## Overview

`lsass.exe` (Local Security Authority Subsystem Service) holds credential material in memory for logged-on users: NTLM hashes, Kerberos tickets, and sometimes plaintext passwords. Attackers read or dump its memory to steal credentials — usually the step **before** Pass-the-Hash, Pass-the-Ticket, or lateral movement.

**Common methods:**
- Mimikatz `sekurlsa::logonpasswords` (reads memory directly)
- `procdump.exe -ma lsass.exe lsass.dmp` (Sysinternals, signed by Microsoft)
- `rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump <PID> lsass.dmp full` (built-in LOLBin)
- Task Manager → right-click lsass → "Create dump file"
- Then parse the dump offline with Mimikatz or pypykatz

## MITRE ATT&CK

**T1003.001** — OS Credential Dumping: LSASS Memory

## Log Sources & Event IDs

| Source | Event | What to look for |
|---|---|---|
| Sysmon | **10** (Process access) | `TargetImage` = `lsass.exe` with suspicious `GrantedAccess` |
| Sysmon | 10 | `CallTrace` containing `dbghelp.dll` / `dbgcore.dll` (`MiniDumpWriteDump`) or `UNKNOWN` (injected / unbacked code) |
| Sysmon | 1 / Security 4688 | `procdump` with `lsass`, `rundll32` with `comsvcs` + `MiniDump` |
| Sysmon | 11 (File created) | `.dmp` files, especially with `lsass` in the name |
| PowerShell | 4104 | `Invoke-Mimikatz`, `sekurlsa`, `MiniDumpWriteDump` |

### Common suspicious GrantedAccess values

| Value | Typical source |
|---|---|
| `0x1010` | Mimikatz `sekurlsa` (PROCESS_VM_READ + QUERY_LIMITED_INFORMATION) |
| `0x1410` | Memory read with query information |
| `0x1438` / `0x143a` | Dumping tools |
| `0x1fffff` | PROCESS_ALL_ACCESS — full access |

## Detection

**Suspicious access to LSASS:**

```spl
index=sysmon EventCode=10 TargetImage="*\\lsass.exe"
    GrantedAccess IN ("0x1010", "0x1410", "0x1438", "0x143a", "0x1fffff")
    NOT SourceImage IN ("*\\MsMpEng.exe", "*\\csrss.exe", "*\\wininit.exe", "*\\wmiprvse.exe")
| stats count BY host SourceImage GrantedAccess CallTrace
```

**Dumping with comsvcs.dll:**

```spl
index=sysmon EventCode=1 Image="*\\rundll32.exe"
    CommandLine="*comsvcs*" CommandLine="*MiniDump*"
| table _time host User ParentImage CommandLine
```

**Dumping with ProcDump:**

```spl
index=sysmon EventCode=1 (Image="*\\procdump*.exe" OR OriginalFileName="procdump")
    CommandLine="*lsass*"
| table _time host User CommandLine
```

> Matching `OriginalFileName` catches a renamed `procdump.exe`.

**Dump file written to disk:**

```spl
index=sysmon EventCode=11 TargetFilename="*lsass*.dmp"
| table _time host Image TargetFilename
```

## False Positives

- Antivirus / EDR products (Defender `MsMpEng.exe`, third-party agents)
- Windows components (`csrss.exe`, `wininit.exe`, `svchost.exe` in some cases)
- IT admins troubleshooting with ProcDump (should be rare and documented)

Build the exclusion list from your own environment's baseline — **exclude by full path, not just name**, since attackers can name their tools `MsMpEng.exe`.

## Response

1. Treat every credential on that host as compromised — check which accounts were logged on (4624 events on the host).
2. Isolate the host.
3. Reset passwords of all exposed accounts, prioritizing privileged ones.
4. Hunt for use of the stolen credentials across the network (see [Pass-the-Hash](pass-the-hash.md)).
5. Find the initial access — how the attacker got local admin on that host.

## Prevention

- **Credential Guard** (virtualization-based protection of secrets)
- **LSA protection** (`RunAsPPL`) — LSASS runs as a protected process
- ASR rule: *Block credential stealing from the Windows local security authority subsystem*
- Limit local admin rights — dumping LSASS requires admin / SeDebugPrivilege
- Disable WDigest (prevents plaintext passwords in memory on older systems)
