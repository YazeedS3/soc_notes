# C2 Beaconing Indicators

## What is beaconing?

After compromise, an implant regularly "checks in" with its Command & Control (C2) server to ask for new tasks. Even when the traffic is encrypted, the **pattern** of those check-ins often gives it away.

**MITRE ATT&CK:** T1071 (Application Layer Protocol), T1573 (Encrypted Channel), T1071.004 (DNS)

---

## Indicators

### Timing

| Indicator | Why it's suspicious |
|---|---|
| Connections at a **fixed interval** (e.g. every 60s) | Humans don't browse on a timer |
| Low **jitter** (small variation between intervals) | Even with built-in jitter, the average interval stays consistent over time |
| Activity continuing at night / weekends | No user is active, but the "user" keeps connecting |

### Size

| Indicator | Why it's suspicious |
|---|---|
| Many requests with **nearly identical sizes** | Empty check-ins ("any tasks?") look the same every time |
| Small requests, occasional large responses | Tasking or tool downloads |
| Large outbound uploads to a rare destination | Possible exfiltration |

### Destination

| Indicator | Why it's suspicious |
|---|---|
| Domain contacted by **only one or two hosts** in the whole network | Legitimate services are usually used by many hosts |
| Newly registered domains | Attackers register infrastructure shortly before use |
| Direct connections to an IP with no DNS lookup | Hard-coded C2 address |
| Self-signed or unusual TLS certificates | Default / quickly-made C2 infrastructure |

### Protocol & host

| Indicator | Why it's suspicious |
|---|---|
| HTTPS from a process that **isn't a browser** (Sysmon 3: `Image`) | e.g. `rundll32.exe` or an unknown binary in `AppData` making web requests |
| Unusual User-Agent, or one that doesn't match the process | Implant with a hard-coded User-Agent |
| Long, random-looking subdomains | DNS tunneling (data encoded in subdomains) |
| Many TXT / NULL DNS queries | DNS-based C2 |
| Uncommon TLS client fingerprint (JA3 / JA4) | Non-browser TLS libraries have different fingerprints |
| Named pipes between hosts (Sysmon 17/18) | SMB-based peer-to-peer C2 |

---

## Detection approaches

- **Splunk:** interval and jitter analysis — see the beaconing query in [detection-queries.md](../04-splunk-queries/detection-queries.md)
- **Zeek** `conn.log` + **RITA** (Real Intelligence Threat Analytics) — automated beacon scoring
- **JA3 / JA4** TLS fingerprinting via Zeek or Suricata
- **Wireshark:** Statistics > I/O Graphs with a filter on the suspicious destination — regular spikes are easy to see
- **Rarity analysis:** domains or processes seen on very few hosts

---

## Applying this to my own C2 framework

I built a custom C2 framework (C++ agent, Python FastAPI server, mTLS, AES-GCM encrypted protocol over HTTPS, persistent WinHTTP sessions). These are the artifacts I expect a defender could use to detect it — **to be validated in my home lab**:

| Artifact | Where a defender would see it | Status |
|---|---|---|
| Regular check-in interval | Proxy / firewall logs, Sysmon 3, Zeek `conn.log` | ⏳ To test |
| Consistent request sizes (fixed protocol framing) | NetFlow, Zeek `conn.log` | ⏳ To test |
| HTTPS from a non-browser process | Sysmon 3 (`Image` field) | ⏳ To test |
| Client certificate in the TLS handshake (mTLS — uncommon for normal web traffic) | Wireshark / Zeek `ssl.log` (visible in TLS 1.2, encrypted in TLS 1.3) | ⏳ To test |
| Non-browser TLS fingerprint (WinHTTP) | JA3 / JA4 via Zeek or Suricata | ⏳ To test |
| Long-lived / reused connections | Zeek `conn.log` duration | ⏳ To test |

The goal: write detections for my own tool, then see which ones survive changes to the implant's behavior (jitter, sleep time, TLS version).
