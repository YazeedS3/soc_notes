# DCSync

## Overview

Domain Controllers replicate AD data to each other using the **Directory Replication Service (DRS) Remote Protocol**. With DCSync, an attacker who holds replication rights *pretends to be a Domain Controller* and asks a real DC to replicate password data — including the **krbtgt** hash (enabling Golden Tickets) and every user's NTLM hash.

No code runs on the DC; it is a legitimate replication request coming from the wrong place.

**Required rights:** `DS-Replication-Get-Changes` + `DS-Replication-Get-Changes-All` (held by default by Domain Admins, Enterprise Admins, Administrators, and DC computer accounts).

**Common tools:** Mimikatz `lsadump::dcsync`, Impacket `secretsdump.py`

## MITRE ATT&CK

**T1003.006** — OS Credential Dumping: DCSync

## Log Sources & Event IDs

| Source | Event | What to look for |
|---|---|---|
| DC Security log | **4662** (operation on an AD object) | `Properties` containing a replication GUID **and** the account is **not** a DC computer account (doesn't end in `$`) |
| DC Security log | 4624 | Network logon (Type 3) from the source host just before the replication |
| Network | RPC / DRSUAPI | `DRSGetNCChanges` requests from an IP that is **not** a Domain Controller |

### Replication GUIDs

| GUID | Right |
|---|---|
| `1131f6aa-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes |
| `1131f6ad-9c07-11d1-f79f-00c04fc2dcd2` | DS-Replication-Get-Changes-All |
| `89e95b76-444d-4c62-991a-0facbeda640c` | DS-Replication-Get-Changes-In-Filtered-Set |

**Requirement:** *Audit Directory Service Access* must be enabled, with a SACL on the domain object, for 4662 to be logged.

## Detection

**Replication requests from accounts that are not Domain Controllers:**

```spl
index=wineventlog EventCode=4662 Access_Mask=0x100
    (Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*"
     OR Properties="*1131f6ad-9c07-11d1-f79f-00c04fc2dcd2*"
     OR Properties="*89e95b76-444d-4c62-991a-0facbeda640c*")
    Account_Name!="*$"
| table _time host Account_Name Account_Domain Properties
```

**Logic:** Real replication is done by DC computer accounts (`DC01$`). A *user* account performing replication is a strong DCSync indicator.

**Network-based (Zeek `dce_rpc.log` or IDS):** `DRSGetNCChanges` operations where the source IP is not in the list of known Domain Controllers. In Wireshark: `drsuapi.opnum == 3`.

## False Positives

- **Azure AD Connect / Entra Connect** sync account (often named `MSOL_...`) legitimately uses replication rights
- Some identity management or AD backup / auditing tools

Allow-list these specific accounts **and** their specific source hosts — not just the account name.

## Response

DCSync means the attacker likely already has high privileges. Treat it as **critical**.

1. Identify the account and the source host.
2. Assume all domain hashes are compromised, including **krbtgt**.
3. Disable / reset the account used.
4. **Reset the krbtgt password twice** (with replication time between resets) to invalidate Golden Tickets.
5. Investigate how the attacker obtained replication rights — trace back the full attack chain.

## Prevention

- Regularly audit who has replication rights on the domain object. **BloodHound** shows these as `GetChanges` / `GetChangesAll` / `DCSync` edges — the same tool attackers use can be used to find and remove dangerous paths.
- Minimize the number of Domain Admin accounts
- Monitor and protect accounts with replication rights (e.g. the Entra Connect account)
