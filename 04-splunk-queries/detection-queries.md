# Splunk Detection Queries

A collection of detection queries to adapt. Queries for specific AD attacks live in their own notes:

| Attack | Note |
|---|---|
| Kerberoasting | [kerberoasting.md](../03-ad-attacks-detection/kerberoasting.md) |
| AS-REP Roasting | [as-rep-roasting.md](../03-ad-attacks-detection/as-rep-roasting.md) |
| DCSync | [dcsync.md](../03-ad-attacks-detection/dcsync.md) |
| Pass-the-Hash | [pass-the-hash.md](../03-ad-attacks-detection/pass-the-hash.md) |
| LSASS Dumping | [lsass-dumping.md](../03-ad-attacks-detection/lsass-dumping.md) |

> **Before using:** replace `index=wineventlog`, `index=sysmon`, and `index=powershell` with your own indexes, and check field names against your add-ons (they differ between `WinEventLog` and `XmlWinEventLog`).

---

## Authentication

### Brute force — many failures from one source

```spl
index=wineventlog EventCode=4625
| bin _time span=5m
| stats count dc(Account_Name) AS users BY _time Source_Network_Address
| where count > 20
```

### Password spraying — many users, few attempts each

```spl
index=wineventlog EventCode=4625
| bin _time span=30m
| stats count dc(Account_Name) AS users BY _time Source_Network_Address
| where users > 10 AND count / users < 3
```

### Successful logon after many failures (possible successful brute force)

```spl
index=wineventlog (EventCode=4625 OR EventCode=4624) Account_Name!="*$"
| stats count(eval(EventCode=4625)) AS failures count(eval(EventCode=4624)) AS successes
        BY Account_Name Source_Network_Address
| where failures > 10 AND successes > 0
```

### RDP logons from external IPs

```spl
index=wineventlog EventCode=4624 Logon_Type=10
| where NOT (cidrmatch("10.0.0.0/8", Source_Network_Address)
          OR cidrmatch("172.16.0.0/12", Source_Network_Address)
          OR cidrmatch("192.168.0.0/16", Source_Network_Address))
| table _time host Account_Name Source_Network_Address
```

---

## Privilege & account changes

### User added to a privileged group

```spl
index=wineventlog EventCode IN (4728, 4732, 4756)
    Group_Name IN ("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
| table _time host Account_Name Member_Name Group_Name
```

### New user account created

```spl
index=wineventlog EventCode=4720
| table _time host Account_Name New_Account_Name
```

---

## Execution

### Office application spawning a shell (phishing / macro)

```spl
index=sysmon EventCode=1
    ParentImage IN ("*\\winword.exe", "*\\excel.exe", "*\\powerpnt.exe", "*\\outlook.exe")
    Image IN ("*\\cmd.exe", "*\\powershell.exe", "*\\wscript.exe", "*\\cscript.exe",
              "*\\mshta.exe", "*\\rundll32.exe", "*\\regsvr32.exe")
| table _time host User ParentImage Image CommandLine
```

### Encoded PowerShell

```spl
index=sysmon EventCode=1 Image="*\\powershell.exe"
    (CommandLine="* -enc *" OR CommandLine="* -e *" OR CommandLine="*-EncodedCommand*")
| table _time host User ParentImage CommandLine
```

### Suspicious PowerShell script blocks

```spl
index=powershell EventCode=4104
    (ScriptBlockText="*Invoke-Mimikatz*" OR ScriptBlockText="*DownloadString*"
     OR ScriptBlockText="*FromBase64String*" OR ScriptBlockText="*Net.WebClient*"
     OR ScriptBlockText="*AmsiUtils*" OR ScriptBlockText="*Invoke-Kerberoast*")
| table _time host ScriptBlockText
```

### LOLBin downloads

```spl
index=sysmon EventCode=1
    ((Image="*\\certutil.exe" CommandLine="*urlcache*")
     OR (Image="*\\bitsadmin.exe" CommandLine="*transfer*")
     OR (Image="*\\mshta.exe" CommandLine="*http*")
     OR (Image="*\\regsvr32.exe" CommandLine="*/i:http*"))
| table _time host User Image CommandLine
```

---

## Persistence

### New service installed

```spl
index=wineventlog EventCode=7045
| table _time host Service_Name Service_File_Name Service_Account
```

### Scheduled task created

```spl
index=wineventlog EventCode=4698
| table _time host Account_Name Task_Name
```

### Run key modification

```spl
index=sysmon EventCode=13
    TargetObject IN ("*\\CurrentVersion\\Run\\*", "*\\CurrentVersion\\RunOnce\\*")
| table _time host Image TargetObject Details
```

---

## Defense evasion

### Audit log cleared

```spl
index=wineventlog (EventCode=1102 OR (EventCode=104 source="WinEventLog:System"))
| table _time host Account_Name EventCode
```

### Shadow copies deleted (ransomware)

```spl
index=sysmon EventCode=1
    ((Image="*\\vssadmin.exe" CommandLine="*delete*shadows*")
     OR (Image="*\\wmic.exe" CommandLine="*shadowcopy*delete*"))
| table _time host User CommandLine
```

---

## Network / C2

### Beaconing — regular connection intervals

```spl
index=sysmon EventCode=3
| where NOT (cidrmatch("10.0.0.0/8", DestinationIp)
          OR cidrmatch("172.16.0.0/12", DestinationIp)
          OR cidrmatch("192.168.0.0/16", DestinationIp))
| sort 0 _time
| streamstats current=f last(_time) AS prev_time BY host Image DestinationIp
| eval delta = _time - prev_time
| stats count avg(delta) AS avg_interval stdev(delta) AS jitter
        BY host Image DestinationIp DestinationPort
| where count > 20 AND jitter < 5
| sort jitter
```

**Logic:** Humans browse irregularly; implants check in on a timer. Low standard deviation between connections = machine-like behavior. See [c2-beaconing-indicators.md](../05-network-analysis/c2-beaconing-indicators.md).

### Rare processes making network connections

```spl
index=sysmon EventCode=3
| stats dc(host) AS host_count count BY Image
| where host_count < 3
| sort host_count
```
