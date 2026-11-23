# Wireshark Filters & PCAP Analysis

## First steps with a new PCAP

Before filtering, get the big picture:

1. **Statistics > Capture File Properties** — time range, packet count
2. **Statistics > Protocol Hierarchy** — which protocols are present (unexpected ones stand out)
3. **Statistics > Conversations** — who talked to whom, how much data, how long
4. **Statistics > Endpoints** — all hosts involved
5. **File > Export Objects > HTTP / SMB** — extract transferred files
6. **Follow > TCP / HTTP Stream** — read a full conversation
7. **Statistics > I/O Graphs** — spot regular spikes (beaconing)

---

## General

| Filter | Purpose |
|---|---|
| `ip.addr == 10.0.0.5` | All traffic to/from a host |
| `ip.src == 10.0.0.5 && ip.dst == 8.8.8.8` | Traffic in one direction |
| `tcp.port == 4444` | A specific port (4444 = Metasploit default) |
| `!(arp or dns or icmp)` | Remove noise |
| `tcp.analysis.flags` | Retransmissions, resets, other TCP problems |
| `frame.time >= "2026-01-01 10:00:00"` | Time-based filtering |

## Scanning

| Filter | Purpose |
|---|---|
| `tcp.flags.syn == 1 && tcp.flags.ack == 0` | SYN packets — many to different ports from one source = port scan |
| `tcp.flags.reset == 1` | RST responses — closed ports during a scan |
| `icmp.type == 8` | Ping sweep |

## HTTP

| Filter | Purpose |
|---|---|
| `http.request` | All HTTP requests |
| `http.request.method == "POST"` | Uploads, form submissions, possible exfiltration or C2 check-ins |
| `http.response.code >= 400` | Errors (directory brute forcing produces many 404s) |
| `http.user_agent contains "python"` | Scripted traffic (also try `curl`, `Go-http-client`, `PowerShell`) |
| `http.request.uri contains ".exe"` | Executable downloads |

## DNS

| Filter | Purpose |
|---|---|
| `dns.flags.response == 0` | DNS queries only |
| `dns.qry.name contains "example"` | Queries for a specific domain |
| `dns.qry.name.len > 50` | Very long names — possible DNS tunneling / exfiltration |
| `dns.qry.type == 16` | TXT queries — sometimes used for C2 |
| `dns.flags.rcode == 3` | NXDOMAIN — many of these can indicate DGA malware |

## TLS

| Filter | Purpose |
|---|---|
| `tls.handshake.type == 1` | Client Hello |
| `tls.handshake.extensions_server_name` | SNI — the domain the client asked for (visible even with encryption) |
| `tls.handshake.type == 11` | Certificate messages (in TLS 1.2 these are visible; in TLS 1.3 they are encrypted) |

## Windows / Active Directory

| Filter | Purpose |
|---|---|
| `smb2` | SMB traffic |
| `smb2.filename contains "PSEXESVC"` | PsExec service binary being copied |
| `smb2.tree contains "ADMIN$"` | Access to admin share (lateral movement) |
| `kerberos.msg_type == 11` | AS-REP |
| `kerberos.msg_type == 13` | TGS-REP |
| `kerberos.etype == 23` | RC4 encryption — **Kerberoasting / AS-REP Roasting** signal |
| `ntlmssp.messagetype == 0x00000003` | NTLM authentication messages (shows user and domain) |
| `drsuapi.opnum == 3` | `DRSGetNCChanges` — **DCSync** if source is not a DC |
| `ldap` | LDAP queries — large volumes can indicate BloodHound / SharpHound enumeration |

---

## tshark one-liners

```bash
# Top queried domains
tshark -r capture.pcap -Y "dns.flags.response == 0" -T fields -e dns.qry.name \
  | sort | uniq -c | sort -nr | head -20

# All HTTP requests with host and URI
tshark -r capture.pcap -Y "http.request" -T fields -e ip.src -e http.host -e http.request.uri

# All TLS SNI values
tshark -r capture.pcap -Y "tls.handshake.type == 1" -T fields \
  -e ip.src -e tls.handshake.extensions_server_name | sort -u

# Conversations summary
tshark -r capture.pcap -q -z conv,tcp
```
