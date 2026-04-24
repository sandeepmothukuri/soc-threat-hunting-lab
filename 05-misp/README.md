# Module 05 — MISP Threat Intelligence Platform

## Share, Correlate, and Act on Threat Intelligence

MISP (Malware Information Sharing Platform) is the gold standard for threat intelligence sharing. It aggregates IOCs (Indicators of Compromise) from global feeds and lets you share intelligence with partners, automatically enriching your SIEM, EDR, and SOAR detections.

---

## Architecture

```
  External Threat Feeds              Internal Intelligence
  ┌─────────────────┐               ┌──────────────────────┐
  │ abuse.ch        │               │ SOC Analyst adds     │
  │ CIRCL OSINT     │──► MISP ◄────│ custom IOCs          │
  │ MalwareBazaar   │   (192.168    │ incident artifacts   │
  │ URLhaus         │   .60.10)     │ threat actor TTPs    │
  │ ThreatFox       │               └──────────────────────┘
  │ Feodo Tracker   │
  └─────────────────┘
           │
           │  ioc-sync.py (every 6h)
           ▼
  ┌──────────────────────────────────────────────┐
  │              IOC Distribution                │
  │                                              │
  │  Wazuh CDB Lists    OSQuery Packs    TheHive │
  │  (IP/domain rules)  (misp-iocs.conf) (alerts)│
  └──────────────────────────────────────────────┘
```

---

## Installation

```bash
export MISP_IP=192.168.60.10
export MISP_ADMIN_EMAIL=admin@soc-lab.local
sudo -E ./install-misp.sh
```

Access: `https://192.168.60.10`

---

## Step 1 — Enable Threat Feeds

In MISP UI → Sync Actions → Feeds:

| Feed | Type | Update |
|------|------|--------|
| CIRCL OSINT | MISP | Every 6h |
| abuse.ch MalwareBazaar | MISP | Every 6h |
| URLhaus | MISP | Every 6h |
| ThreatFox | MISP | Every 6h |
| Feodo Tracker C2 IPs | MISP | Every 6h |
| PhishTank | CSV | Daily |

```bash
# Enable all feeds via CLI
php /var/www/MISP/app/Console/cake Server enable_feeds
php /var/www/MISP/app/Console/cake Server fetch_feeds
```

---

## Step 2 — Configure API Access

```bash
# Get your API key
# MISP UI → top-right user menu → My Profile → Auth Key → Reset

# Test API
curl -k -s -H "Authorization: YOUR_API_KEY" \
     -H "Accept: application/json" \
     https://192.168.60.10/attributes/restSearch \
     -d '{"returnFormat":"json","type":"ip-dst","limit":5}' | jq '.response.Attribute[].value'
```

---

## Step 3 — Sync IOCs to Other Tools

```bash
# Set environment variables
export MISP_URL=https://192.168.60.10
export MISP_KEY=your-api-key-here
export THEHIVE_URL=http://192.168.60.20:9000
export THEHIVE_KEY=your-thehive-key

# Full sync: MISP → Wazuh + OSQuery + TheHive
python3 scripts/ioc-sync.py --mode sync

# Export just malicious IPs
python3 scripts/ioc-sync.py --mode export-ips > /tmp/bad-ips.txt

# Push high-severity events to TheHive
python3 scripts/ioc-sync.py --mode thehive

# Continuous watch mode (every 30 min)
python3 scripts/ioc-sync.py --mode watch --interval 1800
```

---

## Threat Hunting with MISP IOCs

### Search Events by Threat Actor
```
MISP UI → Events → Search: threat_actor_name
         → View Event → Attributes tab
         → Download as CSV for offline analysis
```

### MITRE ATT&CK Mapping
```
MISP UI → Galaxies → MITRE ATT&CK
         → Browse techniques linked to IOCs
```

### Correlate with Zeek Logs
```bash
# Extract MISP C2 IPs and search Zeek conn logs
python3 scripts/ioc-sync.py --mode export-ips > /tmp/misp-ips.txt

# Search Zeek logs for connections to MISP IPs
grep -Ff /tmp/misp-ips.txt /opt/zeek/logs/current/conn.log | \
    zeek-cut ts id.orig_h id.resp_h id.resp_p duration | head -20
```

---

## MISP API Cheat Sheet

```bash
BASE="https://192.168.60.10"
KEY="YOUR_API_KEY"

# Search for events by tag
curl -k -s -H "Authorization: $KEY" -H "Accept: application/json" \
     "$BASE/events/restSearch" \
     -d '{"returnFormat":"json","tags":["tlp:red"],"limit":10}' | jq '.response[].Event.info'

# Get attributes of type IP
curl -k -s -H "Authorization: $KEY" -H "Accept: application/json" \
     "$BASE/attributes/restSearch" \
     -d '{"returnFormat":"json","type":"ip-dst","to_ids":1,"limit":100}' | \
     jq '.response.Attribute[].value'

# Add a new IOC
curl -k -s -X POST -H "Authorization: $KEY" -H "Content-Type: application/json" \
     "$BASE/attributes/add/1" \
     -d '{"type":"ip-dst","value":"192.168.99.99","comment":"C2 server from incident 2024-001","to_ids":1}'
```

---

## Hands-on Exercise: Full Intel Cycle

```
1. Create Event in MISP
   → Add Event → Threat Level: High
   → Add attributes: C2 IP, malware hash, domain

2. Tag with MITRE ATT&CK
   → Galaxies → MITRE ATT&CK Pattern
   → Select T1071.001 (C2 over HTTP)

3. Sync to detection stack
   → python3 scripts/ioc-sync.py --mode sync

4. Verify Wazuh sees the IOC
   → grep the malicious IP in /var/ossec/etc/lists/misp-malicious-ips

5. Simulate C2 connection
   → curl http://MISP_IP_YOU_ADDED/
   → Wazuh should fire alert within 60s

6. Check TheHive alert was auto-created
   → TheHive UI → Alerts → filter source:misp
```
