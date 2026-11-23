# Sysmon Key Events

Sysmon (System Monitor, Sysinternals) adds detailed process, network, and file telemetry that the default Windows logs don't provide.

**Log location:** `Applications and Services Logs > Microsoft > Windows > Sysmon > Operational`

---

## Installation

```powershell
# Install with a community config
sysmon64.exe -accepteula -i sysmonconfig.xml

# Update the config later
sysmon64.exe -c sysmonconfig.xml
```

Recommended starting configs:
- [SwiftOnSecurity/sysmon-config](https://github.com/SwiftOnSecurity/sysmon-config) — well-commented, good baseline
- [olafhartong/sysmon-modular](https://github.com/olafhartong/sysmon-modular) — modular, mapped to MITRE ATT&CK

---

## Event IDs

| ID | Event | Detection use |
|---|---|---|
| **1** | Process creation | Command lines, parent-child relationships, hashes — the most used event |
| 2 | File creation time changed | Timestomping (T1070.006) |
| **3** | Network connection | Which **process** made the connection — C2, beaconing, lateral movement |
| 5 | Process terminated | Timeline building |
| 6 | Driver loaded | Malicious / vulnerable drivers (BYOVD) |
| 7 | Image (DLL) loaded | DLL side-loading, suspicious DLLs (noisy — filter carefully) |
| **8** | CreateRemoteThread | Process injection |
| **10** | Process access | **LSASS credential dumping** (`TargetImage = lsass.exe`) |
| **11** | File created | Dropped payloads, dump files (`.dmp`), files in startup folders |
| 12 / 13 / 14 | Registry create/delete, value set, rename | Run keys and other registry persistence |
| 15 | File stream created | Alternate Data Streams, Mark-of-the-Web (downloaded files) |
| 17 / 18 | Named pipe created / connected | C2 frameworks often use named pipes (e.g. SMB beacons, PsExec) |
| **22** | DNS query | Which process resolved which domain — C2 domains, DNS tunneling |
| 23 / 26 | File delete (archived / logged) | Attacker cleanup |
| 25 | Process tampering | Process hollowing / herpaderping |

> **Tip:** `ProcessGuid` is unique per process and survives PID reuse. Use it to correlate events 1, 3, 10, 11, and 22 belonging to the same process.

---

## Suspicious parent → child relationships (Event 1)

| Parent | Child | Possible meaning |
|---|---|---|
| `winword.exe`, `excel.exe`, `outlook.exe` | `cmd.exe`, `powershell.exe`, `mshta.exe`, `wscript.exe` | Malicious macro / phishing document |
| `w3wp.exe`, `httpd.exe`, `tomcat*.exe` | `cmd.exe`, `powershell.exe`, `whoami.exe` | Web shell |
| `wmiprvse.exe` | `cmd.exe`, `powershell.exe` | Remote execution over WMI (e.g. Impacket `wmiexec`) |
| `services.exe` | `cmd.exe` with random service name | PsExec-style lateral movement |
| `explorer.exe` | `rundll32.exe` with no arguments | Often injected / suspicious |
| `lsass.exe` | anything | Almost never legitimate |

---

## Suspicious command lines (LOLBins)

Living-off-the-land binaries abused by attackers:

| Command pattern | Abuse |
|---|---|
| `certutil -urlcache -split -f http...` | Download a file |
| `certutil -decode` | Decode a Base64 payload |
| `mshta http...` / `mshta vbscript:` | Run a remote HTA / script |
| `regsvr32 /s /n /u /i:http... scrobj.dll` | "Squiblydoo" — remote scriptlet execution |
| `rundll32 ... comsvcs.dll, MiniDump` | LSASS memory dump |
| `bitsadmin /transfer` | Download a file |
| `powershell -enc` / `-EncodedCommand` | Obfuscated PowerShell |
| `powershell ... IEX (New-Object Net.WebClient).DownloadString(...)` | Download-and-execute |
| `vssadmin delete shadows /all /quiet` | Ransomware removing backups |
| `wevtutil cl Security` | Clearing logs |

---

## Suspicious execution paths

Executables running from these locations deserve a closer look:

- `C:\Users\<user>\AppData\Local\Temp\`
- `C:\Users\<user>\AppData\Roaming\`
- `C:\Users\Public\`
- `C:\ProgramData\`
- `C:\Windows\Temp\`
- `C:\PerfLogs\`

Also watch for **system binary names in the wrong path** (e.g. `svchost.exe` outside `C:\Windows\System32\`).
