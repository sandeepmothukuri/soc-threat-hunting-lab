# Module 03 — Velociraptor EDR + DFIR
## Live Endpoint Forensics & Threat Hunting

---

## What Velociraptor Does

Velociraptor is a next-generation EDR and DFIR platform. Unlike Wazuh (event-based), Velociraptor lets you **query any endpoint on-demand** in real-time using VQL (Velociraptor Query Language) — like SQL for your endpoints.

Key capabilities:
- Hunt across all endpoints simultaneously in seconds
- Collect memory, processes, network connections, files, registry
- Deploy custom detection artifacts (YARA, hashes, behavior)
- Timeline reconstruction for DFIR investigations
- Respond: isolate host, kill process, quarantine file

---

## Step 1 — Deploy Server

```bash
sudo SERVER_IP=192.168.50.30 ./install-velociraptor.sh
```

Access: `https://192.168.50.30:8889`

---

## Step 2 — Enroll Endpoints

### Linux Agent
```bash
# Generate client config on Velociraptor server
velociraptor --config /etc/velociraptor/server.config.yaml \
    config client > /tmp/client.config.yaml

# Transfer client.config.yaml to target, then:
# On Ubuntu Target (192.168.30.10):
curl -o /usr/local/bin/velociraptor \
    https://github.com/Velocidex/velociraptor/releases/download/v0.72.3/velociraptor-v0.72.3-linux-amd64
chmod +x /usr/local/bin/velociraptor
velociraptor --config client.config.yaml service install
systemctl start velociraptor_client
```

### Windows Agent (PowerShell)
```powershell
# On Windows Target (192.168.30.20)
Invoke-WebRequest -Uri "https://192.168.50.30:8889/public/velociraptor.exe" `
    -OutFile velociraptor.exe -SkipCertificateCheck

.\velociraptor.exe --config client.config.yaml service install
Start-Service VelociraptorFrontend
```

---

## Step 3 — Deploy Custom Hunt Artifacts

```bash
# Upload SOC Lab persistence hunt artifact to server
velociraptor --config /etc/velociraptor/server.config.yaml \
    artifacts upload artifacts/SOCLab.HuntPersistence.yaml
```

In UI: Artifacts → Search for `SOCLab` → Run on all clients

---

## Step 4 — Run a Live Investigation

### Scenario: Suspicious process found on Ubuntu Target

```sql
-- Step 1: Identify the process
SELECT Pid, Ppid, Name, CommandLine, Exe, Username, CreateTime
FROM pslist()
WHERE Name =~ "(nc|python|perl|ruby|bash)"
ORDER BY CreateTime DESC

-- Step 2: Check what files it has open
SELECT * FROM handles(pid=SUSPICIOUS_PID)
WHERE Type = "File"

-- Step 3: Check its network connections
SELECT * FROM netstat()
WHERE Pid = SUSPICIOUS_PID

-- Step 4: Dump process memory for analysis
SELECT * FROM proc_dump(pid=SUSPICIOUS_PID)

-- Step 5: Find its parent and siblings
SELECT Pid, Ppid, Name, CommandLine
FROM pslist()
WHERE Ppid = PARENT_PID
```

---

## Step 5 — DFIR Collection (Full Evidence Grab)

For a compromised host, collect everything at once:

```
Velociraptor UI → Collected Artifacts → New Collection:
  - Linux.Collection.LiveResponse
  - Generic.Forensic.LocalHashes
  - Linux.Memory.Dump (if RAM forensics needed)
  - Linux.Sys.BashHistory
  - Linux.Sys.Crontab
  - Linux.Sys.Users
  - Generic.Network.Netstat
  - SOCLab.HuntPersistence
```

Download as ZIP → analyze with Autopsy or log2timeline

---

## Velociraptor Response Actions

```
# In UI → right-click on client → Quarantine
# Or via VQL:
SELECT quarantine(message="Suspected compromise - isolated by SOC") FROM scope()

# Kill a process
SELECT kill(pid=1234) FROM scope()

# Delete a malicious file
SELECT rm(filename="/tmp/malware.sh") FROM scope()

# Run a remediation script
SELECT execve(argv=["/bin/bash", "-c", "rm -rf /tmp/evil; pkill evil"]) FROM scope()
```
