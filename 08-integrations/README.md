# Module 08 — Cross-Tool Integrations

## The Glue That Makes It a Real SOC

Individual tools are powerful, but a real SOC requires them to talk to each other. This module connects all 7 tools into a unified detection and response pipeline.

---

## Integration Map

```
  Zeek/RITA ──► zeek-to-thehive.py ──────────────────────► TheHive
  RITA      ──► rita-to-thehive.py ──────────────────────► TheHive
  MISP      ──► ioc-sync.py ────────► Wazuh + OSQuery     ► TheHive
  OSQuery   ──► (via Wazuh agent) ──────────────────────► TheHive
  TheHive   ──► (webhooks) ─────────────────────────────► Shuffle
  Shuffle   ──► Velociraptor + Firewall + Email
```

---

## Start All Integrations

```bash
# Set environment variables (add to /etc/environment or ~/.bashrc)
export THEHIVE_URL=http://192.168.60.20:9000
export THEHIVE_KEY=YOUR_THEHIVE_API_KEY
export MISP_URL=https://192.168.60.10
export MISP_KEY=YOUR_MISP_API_KEY

# Start all integration watchers (run on Detection VM)
# Each runs as a background service

# 1. RITA → TheHive (check every 5 min for new beacons)
nohup python3 scripts/rita-to-thehive.py --watch --interval 300 &

# 2. Zeek → TheHive (real-time notice forwarding)
nohup python3 scripts/zeek-to-thehive.py --watch &

# 3. MISP IOC Sync (every 30 min)
nohup python3 ../05-misp/scripts/ioc-sync.py --mode watch --interval 1800 &

# Or install as systemd services:
sudo cp systemd/*.service /etc/systemd/system/
sudo systemctl enable --now soc-rita-forwarder soc-zeek-forwarder soc-misp-sync
```

---

## Scripts Reference

| Script | From | To | Purpose |
|--------|------|----|---------|
| `rita-to-thehive.py` | RITA | TheHive | Forward beacon detections as alerts |
| `zeek-to-thehive.py` | Zeek | TheHive | Forward network notices in real-time |
| `../05-misp/scripts/ioc-sync.py` | MISP | Wazuh + OSQuery + TheHive | Distribute IOCs to detection stack |

---

## Sigma Rules

Portable detection rules that can be converted to any SIEM format:

| Rule | Detects | MITRE |
|------|---------|-------|
| `c2-beaconing.yml` | Regular interval C2 callbacks | T1071 |
| `reverse-shell.yml` | Shell spawned by web server | T1505.003 |
| `dns-tunneling.yml` | Long subdomain queries | T1071.004 |
| `cron-persistence.yml` | Malicious cron job added | T1053.003 |

```bash
# Convert Sigma rules to Wazuh format
pip3 install sigma-cli --break-system-packages
sigma convert -t wazuh sigma-rules/reverse-shell.yml

# Convert to Elastic/OpenSearch format
sigma convert -t elasticsearch sigma-rules/dns-tunneling.yml

# Convert to Splunk SPL
sigma convert -t splunk sigma-rules/c2-beaconing.yml
```

---

## Playbooks

Step-by-step response procedures for each attack scenario:

- **Playbook 1** — C2 Beaconing (RITA triggers)
- **Playbook 2** — Webshell/RCE (OSQuery triggers)
- **Playbook 3** — DNS Tunneling (Zeek triggers)
- **Playbook 4** — Lateral Movement (cross-tool)
- **Hunt 1** — Find All C2 Infrastructure
- **Hunt 2** — Credential Harvesting

See: [incident-response-playbooks.md](playbooks/incident-response-playbooks.md)
