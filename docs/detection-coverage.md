# 🛡️ Detection Coverage — MITRE ATT&CK Matrix

This table shows which tools detect which MITRE ATT&CK techniques in the lab.

---

## Coverage Matrix

| ATT&CK Technique | Zeek | RITA | Arkime | Velociraptor | OSQuery | MISP | Sigma Rules |
|-----------------|:----:|:----:|:------:|:------------:|:-------:|:----:|:-----------:|
| **RECONNAISSANCE** | | | | | | | |
| T1046 — Network Scan | ✅ | ❌ | ✅ | ❌ | ✅ | ❌ | ✅ |
| T1595 — Active Scanning | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ |
| **INITIAL ACCESS** | | | | | | | |
| T1190 — Exploit Public App | ✅ | ❌ | ✅ | ❌ | ✅ | ✅ | ❌ |
| T1566 — Phishing | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ | ❌ |
| **EXECUTION** | | | | | | | |
| T1059 — Command Shell | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ✅ |
| T1059.004 — Unix Shell | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ✅ |
| T1203 — Exploit Client | ❌ | ❌ | ✅ | ✅ | ❌ | ✅ | ❌ |
| **PERSISTENCE** | | | | | | | |
| T1053.003 — Cron | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ✅ |
| T1543 — System Service | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| T1098.004 — SSH Key | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| T1505.003 — Web Shell | ✅ | ❌ | ✅ | ✅ | ✅ | ❌ | ✅ |
| T1546 — Shell Startup | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| **PRIVILEGE ESCALATION** | | | | | | | |
| T1548 — Abuse Elevation | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| T1548.001 — SUID/GUID | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| T1068 — Exploit Vulnerability | ❌ | ❌ | ❌ | ✅ | ✅ | ✅ | ❌ |
| **DEFENSE EVASION** | | | | | | | |
| T1055 — Process Injection | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| T1574.006 — LD_PRELOAD | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| T1564.001 — Hidden Files | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| T1036 — Masquerading | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| **CREDENTIAL ACCESS** | | | | | | | |
| T1003 — Credential Dump | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| T1110 — Brute Force | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ❌ |
| **DISCOVERY** | | | | | | | |
| T1049 — Network Connections | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| T1082 — System Info | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| T1057 — Process Discovery | ❌ | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ |
| **LATERAL MOVEMENT** | | | | | | | |
| T1021 — Remote Services | ✅ | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| T1021.002 — SMB | ✅ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ |
| T1021.004 — SSH | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| **COLLECTION** | | | | | | | |
| T1560 — Archive/Compress | ❌ | ❌ | ✅ | ✅ | ❌ | ❌ | ❌ |
| T1074 — Data Staged | ❌ | ❌ | ✅ | ✅ | ✅ | ❌ | ❌ |
| **COMMAND & CONTROL** | | | | | | | |
| T1071 — App Layer C2 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1071.004 — DNS C2 | ✅ | ❌ | ✅ | ❌ | ✅ | ✅ | ✅ |
| T1572 — Protocol Tunnel | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ |
| T1571 — Non-Standard Port | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **EXFILTRATION** | | | | | | | |
| T1041 — Exfil over C2 | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| T1048 — Exfil Alternative | ✅ | ❌ | ✅ | ❌ | ❌ | ❌ | ✅ |

**Coverage: ~35 MITRE ATT&CK techniques across 7 free tools**

---

## Coverage by Tool

| Tool | Techniques Detected | Strength |
|------|--------------------|--------------------|
| Zeek | 14 | Network-layer detection, protocol analysis |
| RITA | 6 | Statistical C2 beaconing detection |
| Arkime | 15 | Full PCAP evidence, file extraction |
| Velociraptor | 24 | Deep endpoint forensics, live response |
| OSQuery | 22 | Continuous SQL monitoring, compliance |
| MISP | 10 | Known threat actor IOCs, global intel |
| Sigma Rules | 8 | Portable, SIEM-agnostic detection rules |

---

## Gaps and How to Fill Them

| Gap | Why | Mitigation |
|-----|-----|------------|
| Phishing email detection | No mail server in lab | Add Proxmox Mail Gateway (from soc-lab-free) |
| Cloud API abuse | No cloud integration | Add AWS CloudTrail / Azure Sentinel |
| Active Directory attacks | No AD in lab | Add Windows Server + Sysmon |
| Browser exploitation | No EDR browser hooks | Add Sysmon + Wazuh on Windows target |
| Supply chain attacks | Complex to simulate | Use SolarWinds simulation labs |

---

## Improving Coverage

### Add Sysmon for Windows Targets

```powershell
# On Windows target (192.168.30.20)
# Download Sysmon + config
Invoke-WebRequest -Uri https://live.sysinternals.com/Sysmon64.exe -OutFile Sysmon64.exe
Invoke-WebRequest -Uri https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml -OutFile sysmon-config.xml

# Install with SwiftOnSecurity config
.\Sysmon64.exe -accepteula -i sysmon-config.xml

# Forward logs to Wazuh agent (from soc-lab-free/02-wazuh-siem)
# This adds 30+ more ATT&CK techniques on Windows
```

### Add YARA Scanning (via Velociraptor)

```yaml
# Add to Velociraptor artifact — scans all processes with YARA rules
name: SOCLab.YARAProcessScan
sources:
  - query: |
      LET rules = SELECT read_file(filename="/etc/yara-rules/malware.yar") AS Rule FROM scope()
      SELECT * FROM foreach(row=pslist(),
        query={ SELECT * FROM yara(files=Exe, rules=rules.Rule) WHERE Rule })
```
