# Module 06 — TheHive 5 Case Management + Cortex

## Your SOC's Command Center

TheHive is where everything comes together. When Zeek detects beaconing, OSQuery finds a backdoor, or MISP flags a known C2 — alerts flow into TheHive and become tracked cases with tasks, timelines, and analyst assignments.

---

## Architecture

```
Alert Sources                Case Management            Response
──────────────               ───────────────            ────────
Zeek/RITA ──────────────►┐
Arkime ──────────────────►│
Velociraptor ────────────►│  TheHive 5          ──►  Shuffle SOAR
OSQuery ─────────────────►├  (192.168.60.20:9000)     (auto-block, isolate)
MISP ────────────────────►│
ioc-sync.py ─────────────►┘
                               │
                               ▼
                          Cortex (port 9001)
                          ├── VirusTotal Analyzer
                          ├── MISP Analyzer
                          ├── Shodan Analyzer
                          └── abuse.ch Analyzer
```

---

## Installation

```bash
export HIVE_IP=192.168.60.20
sudo -E ./install-thehive.sh
```

Access: `http://192.168.60.20:9000`  
Default: `admin@thehive.local` / `secret` (change immediately!)

---

## Step 1 — Initial Setup

```
1. Open http://192.168.60.20:9000
2. Login → Admin → Platform Management
3. Create Organisation: "SOC-Lab"
4. Create Users:
   - analyst1@soc-lab.local  (role: analyst)
   - responder1@soc-lab.local (role: responder)
5. Connect MISP:
   Admin → Platform → MISP
   → Add: https://192.168.60.10 (paste MISP API key)
6. Connect Cortex:
   Admin → Platform → Cortex
   → Add: http://192.168.60.20:9001 (Cortex API key)
```

---

## Step 2 — Create Case Templates

Import the SOC Lab case templates:

```bash
# Via TheHive API
curl -s -X POST http://192.168.60.20:9000/api/case/template \
     -H "Authorization: Bearer $THEHIVE_KEY" \
     -H "Content-Type: application/json" \
     -d @templates/alert-templates.json
```

Templates included:
- **SOC-Incident-Response** — Full IR workflow (6 tasks: Detect → Contain → Investigate → Eradicate → Recover → Lessons)
- **SOC-Threat-Hunt** — Proactive hunting workflow (3 tasks)

---

## Step 3 — Wire Up Alert Sources

### Connect Wazuh → TheHive

```bash
# On Wazuh manager, install integration
pip3 install thehive4py --break-system-packages

# Add to /var/ossec/etc/ossec.conf:
<integration>
  <name>custom-thehive</name>
  <hook_url>http://192.168.60.20:9000/api/v1/alert</hook_url>
  <api_key>YOUR_THEHIVE_KEY</api_key>
  <level>10</level>
  <alert_format>json</alert_format>
</integration>
```

### Connect RITA → TheHive

```bash
# RITA beaconing alerts → TheHive (via 08-integrations/scripts/rita-to-thehive.py)
python3 ../08-integrations/scripts/rita-to-thehive.py --watch
```

---

## Step 4 — Investigate a Case

### Scenario: OSQuery detected a backdoor

```
1. TheHive → Alerts → New Alert "proc_net_activity: nc listening on 4444"

2. Click "Create Case" → Select template "SOC-Incident-Response"

3. Task 1: Triage
   - Observables: add IP 192.168.30.10 (type: ip)
   - Observables: add "nc" (type: filename)
   - Analyze with Cortex: right-click IP → Run Analyzers → Shodan

4. Task 2: Containment
   - Velociraptor: quarantine the host
     SELECT quarantine(message="Backdoor detected - SOC isolating") FROM scope()
   - Block attacker IP in firewall

5. Task 3: Forensics
   - Velociraptor: collect full IR bundle
   - OSQuery: run incident-response pack
   - Arkime: search for all sessions from that host

6. Add TTPs: click MITRE ATT&CK tab → add T1059 (Command Shell)

7. Close case → generate PDF report
```

---

## Cortex Analyzers (IOC Enrichment)

Cortex auto-enriches any observable you add to a case:

| Analyzer | What It Checks | Needs |
|----------|---------------|-------|
| VirusTotal | File hash reputation | Free API key |
| MISP | IOC in your MISP instance | Your MISP key |
| Shodan | IP open ports, location | Free API key |
| abuse.ch | IP/hash in abuse.ch DB | Free |
| URLhaus | URL malware check | Free |
| MaxMind | IP geolocation | Free |

```bash
# Configure analyzers in Cortex UI
http://192.168.60.20:9001
→ Organizations → SOC-Lab → Analyzers
→ Enable: VirusTotal_GetReport, MISP_2_1, Shodan_Host
```

---

## TheHive API Cheat Sheet

```bash
BASE="http://192.168.60.20:9000"
KEY="your-api-key"

# Create an alert
curl -s -X POST "$BASE/api/v1/alert" \
     -H "Authorization: Bearer $KEY" \
     -H "Content-Type: application/json" \
     -d '{"title":"Test Alert","type":"External","source":"Manual","sourceRef":"test-001","severity":2,"status":"New"}'

# List open cases
curl -s "$BASE/api/v1/query" \
     -H "Authorization: Bearer $KEY" \
     -d '{"query":[{"_name":"listCase"},{"_name":"filter","_field":"status","_value":"Open"}]}' | jq '.[].title'

# Add observable to case
curl -s -X POST "$BASE/api/v1/case/CASE_ID/observable" \
     -H "Authorization: Bearer $KEY" \
     -d '{"dataType":"ip","data":"1.2.3.4","tags":["c2","misp"]}'
```
