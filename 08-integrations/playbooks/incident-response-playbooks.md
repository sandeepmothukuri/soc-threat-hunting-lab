# 🚨 Incident Response Playbooks

> **How to use:** When an alert fires, find the matching playbook below. Follow each step in order. Log every action in TheHive with timestamps.

---

## Playbook 1 — C2 Beaconing (RITA Detection)

**Trigger:** RITA beacon score > 0.7 on any internal host  
**MITRE:** T1071 (C2 over App Layer), T1571 (Non-Standard Port)  
**Tools:** RITA, Arkime, Velociraptor, TheHive, Shuffle

### Phase 1: Confirm (< 5 min)

```bash
# Step 1.1 — Check RITA beacon details
rita show-beacons soc-hunt | grep SOURCE_IP

# Step 1.2 — View connections in Arkime
# Browser: http://192.168.50.20:8005
# Search: ip.src == SOURCE_IP AND ip.dst == DEST_IP

# Step 1.3 — Check if destination is known malicious
curl -k -s -H "Authorization: $MISP_KEY" \
     https://192.168.60.10/attributes/restSearch \
     -d '{"returnFormat":"json","type":"ip-dst","value":"DEST_IP"}' | jq '.response.Attribute | length'
# If result > 0 → CONFIRMED C2, escalate immediately
```

### Phase 2: Investigate (< 15 min)

```sql
-- Velociraptor: What process is making these connections?
-- Hunt Manager → New Hunt → All Clients
SELECT Pid, Name, CommandLine, Exe, Username,
       {SELECT Raddr.IP, Raddr.Port FROM netstat() WHERE Pid = Pid} AS Connections
FROM pslist()
WHERE {SELECT count(*) FROM netstat() WHERE Pid = Pid AND Raddr.IP = 'DEST_IP'} > 0
```

```bash
# Check OSQuery on affected host
osqueryi "SELECT p.name, p.cmdline, n.remote_address, n.remote_port
          FROM process_open_sockets n JOIN processes p ON n.pid = p.pid
          WHERE n.remote_address = 'DEST_IP';"
```

### Phase 3: Contain (< 30 min)

```bash
# Option A: Isolate via Velociraptor (keeps forensic channel)
# Velociraptor UI → right-click client → Quarantine
# Or VQL: SELECT quarantine(message="C2 Beaconing - SOC isolating") FROM scope()

# Option B: Block C2 IP at firewall
# pfSense: Firewall → Rules → WAN → Add rule to block DEST_IP

# Add C2 IP to MISP for team sharing
python3 05-misp/scripts/ioc-sync.py  # After manually adding IOC
```

### Phase 4: Eradicate & Close

```bash
# Kill the malicious process
# Velociraptor VQL:
SELECT kill(pid=MALICIOUS_PID) FROM scope()

# Check for persistence
# Velociraptor: run SOCLab.HuntPersistence artifact

# Remove any dropped files
SELECT rm(filename="/tmp/malware.sh") FROM scope()

# Document in TheHive:
# - Timeline of events
# - Process name, PID, path
# - C2 IP and port
# - Any files dropped
# - Actions taken
```

---

## Playbook 2 — Webshell / RCE (OSQuery Detection)

**Trigger:** OSQuery `shell_from_webserver` query — shell spawned by web process  
**MITRE:** T1505.003 (Web Shell), T1059 (Command Shell)  
**Tools:** OSQuery, Velociraptor, Arkime, TheHive

### Phase 1: Confirm

```bash
# Check OSQuery log for the alert
grep "shell_from_webserver" /var/log/osquery/osqueryd.results.log | tail -5 | python3 -m json.tool

# Find the webshell file in Arkime
# http://192.168.50.20:8005
# Search: http.uri == *.php* AND http.method == POST AND dst == WEBSERVER_IP
# Look for: unusual POST requests to .php files, base64 in POST body

# Verify web server logs
grep "POST" /var/log/apache2/access.log | grep -E "\.(php|jsp|aspx)" | tail -20
```

### Phase 2: Find the Webshell

```bash
# Search for webshell files (common patterns)
find /var/www -name "*.php" -newer /var/www/html/index.php -type f 2>/dev/null
find /var/www -type f -name "*.php" | xargs grep -l "eval\|base64_decode\|system\|passthru\|exec" 2>/dev/null

# Velociraptor: scan web directory for PHP shells
# VQL:
SELECT FullPath, Mtime, hash(path=FullPath) AS Hash,
       read_file(filename=FullPath, length=200) AS Preview
FROM glob(globs=["/var/www/**/*.php"])
WHERE read_file(filename=FullPath, length=500) =~ "(eval|base64_decode|passthru|system|shell_exec)"
ORDER BY Mtime DESC
```

### Phase 3: Contain & Eradicate

```bash
# Remove webshell
rm -f /var/www/html/WEBSHELL.php

# Block attacker IP
# Get attacker IP from Apache logs
grep "WEBSHELL.php" /var/log/apache2/access.log | awk '{print $1}' | sort | uniq -c | sort -rn

# Restore from backup if web app is compromised
# Or redeploy web server from clean snapshot

# Check for backdoor accounts created
osqueryi "SELECT username, uid, shell, directory FROM users WHERE uid >= 1000;"
grep "useradd\|adduser" /var/log/auth.log | tail -20
```

---

## Playbook 3 — DNS Tunneling (Zeek Detection)

**Trigger:** Zeek notice `SOC::DNS_Tunnel` — long subdomain queries  
**MITRE:** T1071.004 (DNS), T1048.003 (Exfil over DNS)  
**Tools:** Zeek, Arkime, MISP, TheHive

### Phase 1: Confirm

```bash
# View suspicious DNS queries in Zeek
zeek-cut ts id.orig_h query qtype_name answers \
    < /opt/zeek/logs/current/dns.log | \
    awk 'length($3) > 50 {print}' | head -20

# Count queries to same domain (tunneling = many queries)
zeek-cut query < /opt/zeek/logs/current/dns.log | \
    rev | cut -d'.' -f1,2 | rev | sort | uniq -c | sort -rn | head -20
# If one domain has 100s of queries → likely tunneling

# Decode a sample query (iodine, dnscat2 use base32/base64 encoding)
echo "QUERY_LABEL" | base32 -d 2>/dev/null || echo "QUERY_LABEL" | base64 -d 2>/dev/null
```

### Phase 2: Identify Exfiltrated Data

```bash
# Extract all subdomains to a domain (potential data)
zeek-cut query < /opt/zeek/logs/current/dns.log | \
    grep "SUSPICIOUS_DOMAIN" | \
    sed 's/\..*//' | \
    tr -d '\n' > /tmp/extracted-data.b32

# Attempt decode
cat /tmp/extracted-data.b32 | base32 -d 2>/dev/null | strings | head -20
cat /tmp/extracted-data.b32 | base64 -d 2>/dev/null | strings | head -20
```

### Phase 3: Block and Mitigate

```bash
# Block domain at DNS level
# Add to /etc/hosts on affected hosts:
echo "0.0.0.0 SUSPICIOUS_DOMAIN" >> /etc/hosts

# Block domain in pfSense DNS resolver
# Or configure dnsmasq: address=/SUSPICIOUS_DOMAIN/0.0.0.0

# Add domain to MISP
curl -k -X POST -H "Authorization: $MISP_KEY" \
     https://192.168.60.10/attributes/add/1 \
     -d '{"type":"domain","value":"SUSPICIOUS_DOMAIN","to_ids":1,"comment":"DNS tunnel C2 domain"}'

# Kill the process performing tunneling
# Zeek → identify source IP → Velociraptor hunt on that host
```

---

## Playbook 4 — Lateral Movement (Zeek/Velociraptor)

**Trigger:** Zeek `SOC::Lateral_Move` or Velociraptor SSH detection  
**MITRE:** T1021 (Remote Services), T1021.002 (SMB)  
**Tools:** Zeek, Velociraptor, OSQuery, TheHive

### Phase 1: Map the Movement

```bash
# Identify all hosts the attacker touched
# Zeek: find all SMB connections from initial victim
zeek-cut ts id.orig_h id.resp_h id.resp_p < /opt/zeek/logs/current/conn.log | \
    awk '$3 == 445 {print $2, "→", $3}' | sort -u

# Find SSH lateral movement
zeek-cut ts id.orig_h id.resp_h id.resp_p < /opt/zeek/logs/current/conn.log | \
    awk '$3 == 22' | sort -u

# Build attack graph — run Velociraptor hunt on ALL endpoints
# VQL: show processes + network connections
SELECT Pid, Name, CommandLine,
       {SELECT Raddr.IP FROM netstat() WHERE Pid=Pid AND Raddr.Port IN (22,445,3389)} AS LateralConns
FROM pslist()
WHERE {SELECT count(*) FROM netstat() WHERE Pid=Pid AND Raddr.Port IN (22,445,3389)} > 0
```

### Phase 2: Contain All Affected Hosts

```bash
# List all hosts to isolate
# Velociraptor → Hunt Manager → New Hunt
# Artifact: SOCLab.HuntPersistence (run on all clients)
# Check results for: new accounts, new SSH keys, new cron jobs

# Isolate each compromised host (do this simultaneously to prevent escape)
# Velociraptor: bulk quarantine
# Firewall: block lateral movement ports (445, 22) between VLANs

# Reset ALL credentials on affected systems
# Rotate SSH keys, service account passwords
```

---

## Threat Hunting Playbooks

### Hunt 1: Find All C2 Infrastructure

```bash
# 1. RITA: Show all beacons
rita show-beacons soc-hunt --limit 50

# 2. Zeek: Extract all unique external connections with high byte counts
zeek-cut id.orig_h id.resp_h id.resp_p orig_bytes resp_bytes \
    < /opt/zeek/logs/current/conn.log | \
    awk '$5 > 100000' | sort -k5 -rn | head -20

# 3. Arkime: JA3 fingerprints matching known malware
# Browser → Sessions → ja3 == KNOWN_MALWARE_JA3_HASH

# 4. MISP: Export all C2 IPs and cross-reference Zeek
python3 05-misp/scripts/ioc-sync.py --mode export-ips > /tmp/c2-ips.txt
grep -Ff /tmp/c2-ips.txt /opt/zeek/logs/current/conn.log | zeek-cut ts id.orig_h id.resp_h
```

### Hunt 2: Credential Harvesting

```bash
# OSQuery: processes accessing /etc/shadow or /etc/passwd
osqueryi "SELECT p.name, p.pid, p.cmdline, p.uid
          FROM process_open_files pof
          JOIN processes p ON pof.pid = p.pid
          WHERE pof.path IN ('/etc/shadow', '/etc/passwd', '/etc/gshadow')
          AND p.name NOT IN ('login','sudo','su','sshd','passwd');"

# Check for LSASS-equivalent dumps
osqueryi "SELECT path, mtime, size FROM file
          WHERE (path LIKE '/tmp/%.dmp' OR path LIKE '/tmp/%.dump'
          OR path LIKE '/dev/shm/%.dump');"

# Velociraptor: who accessed SSH private keys?
SELECT Name, Pid, CommandLine
FROM pslist()
WHERE {SELECT path FROM handles(pid=Pid) WHERE path =~ "id_rsa|id_ed25519|\\.ssh"} != ""
```
