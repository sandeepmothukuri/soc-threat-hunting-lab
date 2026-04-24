# Module 02 — Arkime (Full Packet Capture)
## Network Forensics at Scale

---

## What Arkime Does

Arkime captures and indexes every packet on your network, making it searchable like a database. Unlike Zeek (which only generates metadata logs), Arkime stores the **actual packet data** so you can reconstruct any session, extract files, and replay traffic.

Think of it as Wireshark + Google combined — you can search billions of packets in seconds.

---

## Step 1 — Install Arkime

```bash
# On Arkime VM (192.168.50.20) — needs 200GB+ disk
sudo CAPTURE_IFACE=eth1 PCAP_DIR=/data/pcap ./install-arkime.sh
```

**Access the Web UI:**
```
URL:   http://192.168.50.20:8005
Login: admin / (shown at end of install)
```

---

## Step 2 — Key Arkime Features

### Session Search
In Arkime UI → Sessions tab, use queries:

```
# All HTTP traffic today
http.method == GET && startTime >= -1d

# Large data transfers (possible exfiltration)
packets > 1000 && bytes > 1000000

# Connections to known bad IPs (from MISP)
ip == 185.220.101.47

# Specific user agent (malware C2)
http.user-agent == "python-requests/2.28.0"

# DNS queries for suspicious TLDs
dns.host == /\.(xyz|tk|ml|ga|cf)$/

# SSL with self-signed cert
ssl.issuerCN == ssl.subjectCN && protocols == tls
```

### Extract Files from PCAP

```bash
# From UI: Sessions → click a session → "Download PCAP"
# From CLI: extract a file transfer
tshark -r /data/pcap/20240101-session.pcap \
    -Y "http.request.method == POST" \
    -T fields -e http.file_data | xxd | head -20
```

---

## Step 3 — Hands-On Hunting Exercises

### Exercise 1 — Find Malware Download

```
# In Arkime UI search:
http.response-content-type == application/x-dosexec

# Or via tshark on saved PCAP:
tshark -r /data/pcap/capture.pcap \
    -Y 'http.content_type contains "application/x-dosexec"' \
    -T fields -e ip.src -e ip.dst -e http.request.uri
```

### Exercise 2 — Reconstruct Attacker Session

1. In Arkime UI → find attacker IP session
2. Click **Sessions** → select the session
3. Click **Packet Data** to see raw request/response
4. Or download PCAP and open in Wireshark

### Exercise 3 — Data Exfiltration Detection

```
# Large outbound transfers (bytes from internal to external)
node == 192.168.30.* && bytes.dst > 10000000

# DNS exfiltration (many unique subdomains)
protocols == dns && dns.query-type == A && dns.host == /.{40,}/
```

### Exercise 4 — TLS Traffic Analysis

```
# All TLS handshakes
protocols == tls

# Expired certificates
ssl.notAfter < now

# Self-signed (issuer == subject)
ssl.issuerCN == ssl.subjectCN
```

---

## Arkime Query Language Reference

| Query | Meaning |
|---|---|
| `ip == 192.168.30.10` | Sessions involving this IP |
| `port == 4444` | Meterpreter default port |
| `bytes > 1000000` | Large transfers |
| `protocols == smb` | All SMB traffic |
| `country == RU` | Traffic to/from Russia |
| `asn == AS12345` | Specific AS number |
| `tags == soc-lab` | All captured traffic |
| `startTime >= -1h` | Last hour |
| `http.method == POST && bytes.dst > 10000` | Large POSTs (exfil) |

---

## Arkime + MISP Integration

```python
# scripts/import-misp-blocklist.py — see 08-integrations
# Imports MISP IOCs as Arkime wise tags
# Highlights sessions matching known-bad IPs/domains in red
```
