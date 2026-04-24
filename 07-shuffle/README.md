# Module 07 — Shuffle SOAR

## Automate Your Incident Response

Shuffle is an open-source SOAR platform that connects all your security tools and automates response actions visually — no coding required. When TheHive gets an alert, Shuffle automatically blocks IPs, isolates hosts, queries MISP, and notifies your team.

---

## Architecture

```
Alert Sources              Shuffle Workflow Engine         Response Actions
─────────────              ──────────────────────          ────────────────
TheHive Webhook ──────►┐
RITA Beacon Alert ─────►│  Shuffle            ──────►  Block IP (Firewall)
MISP New Event ────────►│  (192.168.60.30)    ──────►  Isolate Host (Velociraptor)
Scheduled Checks ──────►│                    ──────►  Add IOC to MISP
                        └►  Visual Drag-Drop  ──────►  Create TheHive Case
                            Workflow Builder  ──────►  Send Email/Slack
```

---

## Installation

```bash
export SHUFFLE_IP=192.168.60.30
sudo -E ./install-shuffle.sh
```

Access: `http://192.168.60.30:3001`

---

## Step 1 — Connect Your Tools

In Shuffle UI → Apps → Configure:

```
1. TheHive
   URL: http://192.168.60.20:9000
   API Key: [from TheHive → Admin → API]

2. MISP
   URL: https://192.168.60.10
   API Key: [from MISP → My Profile → Auth Key]

3. Velociraptor
   URL: https://192.168.50.30:8000
   API Key: [velociraptor --config server.config.yaml config show]

4. Email (for notifications)
   SMTP: your mail server settings
```

---

## Step 2 — Import Workflows

```
Shuffle UI → Workflows → Import Workflow

Import these files (in order):
1. workflows/soc-incident-response.json   ← Main IR workflow
2. workflows/misp-to-thehive.json         ← Intel sync workflow
3. workflows/beaconing-response.json      ← RITA beacon handler
```

---

## Step 3 — Set Up TheHive Webhook

```bash
# In TheHive: Admin → Webhooks → Add Webhook
Name: Shuffle-SOAR
URL: http://192.168.60.30:3001/api/v1/hooks/YOUR_WORKFLOW_TRIGGER_ID
Verify SSL: No (lab environment)

# Test the webhook
curl -s -X POST http://192.168.60.30:3001/api/v1/hooks/YOUR_ID \
     -H "Content-Type: application/json" \
     -d '{"title":"Test","severity":3,"type":"External","source":"Manual"}'
```

---

## Included Workflows

### 1. `soc-incident-response.json`
**Trigger:** TheHive new alert (severity >= High)  
**Actions:**
- Parse alert data (IP, severity, source)
- VirusTotal reputation check on extracted IP
- Promote alert → TheHive case with IR template
- Email SOC team notification
- Add confirmed IOC to MISP

### 2. `misp-to-thehive.json`
**Trigger:** Schedule — every 30 minutes  
**Actions:**
- Poll MISP for new high-severity events
- Filter: threat_level = High or Critical
- Auto-create TheHive alerts for each new event

### 3. `beaconing-response.json`
**Trigger:** RITA beacon webhook (score > 0.7)  
**Actions:**
- Parse source IP, destination IP, beacon score
- Cross-check destination IP against MISP
- Query source host via Velociraptor (what process is beaconing?)
- Create TheHive case with all context pre-filled

---

## Hands-On: Build Your Own Workflow

```
1. Shuffle UI → Workflows → New Workflow
2. Name: "OSQuery Backdoor Response"

3. Add Trigger: Webhook
   Copy the webhook URL — you'll use it in OSQuery alerting

4. Add Action: Shuffle Tools → "Parse Value"
   Extract: hostname, backdoor_port, process_name

5. Add Action: Velociraptor → "Run Query"
   Query: SELECT * FROM netstat() WHERE Pid = {{process_pid}}

6. Add Action: TheHive → "Create Case"
   Title: "Backdoor on {{hostname}} port {{backdoor_port}}"
   Severity: Critical
   Template: SOC-Incident-Response

7. Add Action: Email → "Send Email"
   To: soc@company.com
   Body: Backdoor detected on {{hostname}}!

8. Save → Activate → Test with curl:
   curl -X POST YOUR_WEBHOOK_URL \
     -d '{"hostname":"ubuntu-target","backdoor_port":"4444","process_name":"nc"}'
```

---

## Apps Available in Shuffle

| Category | Apps |
|----------|------|
| Case Management | TheHive, JIRA, ServiceNow |
| Threat Intel | MISP, VirusTotal, Shodan, abuse.ch |
| Communication | Email (SMTP), Slack, Teams, PagerDuty |
| EDR | Velociraptor, CrowdStrike, Carbon Black |
| SIEM | Wazuh, Splunk, Elastic SIEM |
| Firewall | pfSense, Cisco ASA, Palo Alto |
| Utilities | HTTP (custom APIs), Python scripts, Bash |
