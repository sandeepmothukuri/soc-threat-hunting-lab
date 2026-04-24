# Velociraptor Threat Hunting Queries (VQL)

All queries run from: **Velociraptor UI → Hunt Manager → New Hunt → Custom Query**

---

## Hunt 1 — Active Network Connections to Suspicious Ports

```sql
-- Detect connections to common C2/backdoor ports
SELECT Pid, Name, Laddr.IP AS LocalIP, Laddr.Port AS LocalPort,
       Raddr.IP AS RemoteIP, Raddr.Port AS RemotePort, Status, Type
FROM netstat()
WHERE Status = "ESTABLISHED"
  AND Raddr.Port IN (4444, 4445, 1234, 5555, 6666, 7777, 8888,
                     31337, 12345, 54321, 9001, 9030, 1337)
  AND NOT Raddr.IP =~ "^(127\\.|192\\.168\\.|10\\.|172\\.)"
```

---

## Hunt 2 — Detect Reverse Shells / Backdoor Processes

```sql
-- Find processes with suspicious parent-child relationships
-- e.g. web server spawning bash
SELECT Pid, Ppid, Name, CommandLine, CreateTime,
       Exe, Username,
       {SELECT Name, CommandLine FROM pslist(pid=Ppid)} AS ParentProcess
FROM pslist()
WHERE (Name IN ("bash", "sh", "zsh", "dash", "nc", "ncat", "netcat")
       OR CommandLine =~ "(-i >& /dev/tcp|-e /bin/bash|/bin/sh -i)")
  AND Ppid > 1
```

---

## Hunt 3 — Recently Installed Packages / Binaries

```sql
-- Find executables modified or created in the last 24 hours
SELECT FullPath, Mtime, Atime, Ctime, Size,
       hash(path=FullPath) AS SHA256
FROM glob(globs=["/usr/bin/*", "/usr/sbin/*", "/bin/*", "/sbin/*",
                 "/tmp/*", "/dev/shm/*", "/var/tmp/*"])
WHERE Mtime > now() - 86400
  AND NOT IsDir
ORDER BY Mtime DESC
```

---

## Hunt 4 — Memory-Only Malware (Fileless)

```sql
-- Find processes running from deleted files or unusual paths
SELECT Pid, Name, CommandLine, Exe, Username,
       {SELECT Size FROM stat(filename=Exe)} AS FileSize
FROM pslist()
WHERE (Exe =~ "(/tmp/|/dev/shm/|/var/tmp/|deleted)")
   OR (Exe = "" AND Name NOT IN ("kworker", "ksoftirqd", "migration"))
```

---

## Hunt 5 — Lateral Movement via SSH

```sql
-- Find SSH connections made from this host to other internal hosts
SELECT Pid, Name, CommandLine, Username,
       Laddr.IP AS LocalIP, Raddr.IP AS RemoteIP,
       Raddr.Port AS RemotePort
FROM netstat()
WHERE Name = "ssh"
  AND Status = "ESTABLISHED"
  AND Raddr.IP =~ "^(192\\.168\\.|10\\.|172\\.16\\.)"
  AND Raddr.Port = 22
```

---

## Hunt 6 — Detect Mimikatz / Credential Dumping (Linux)

```sql
-- Find access to sensitive files (passwd, shadow, keys)
SELECT Pid, Name, CommandLine, Username,
       OpenFiles
FROM pslist()
WHERE OpenFiles =~ "(/etc/shadow|/etc/passwd|id_rsa|id_ed25519|\\.gnupg)"
```

---

## Hunt 7 — Scheduled Tasks / Cron (Persistence)

```sql
-- Find all cron jobs with execution in suspicious directories
SELECT FullPath, Mtime,
       read_file(filename=FullPath, length=1000) AS Content
FROM glob(globs=["/etc/cron.*/*", "/var/spool/cron/*", "/etc/crontab"])
WHERE Content =~ "(/tmp/|/dev/shm/|curl|wget|bash -c|python|perl|nc )"
```

---

## Hunt 8 — Windows: Detect PowerShell Abuse (Windows Agents)

```sql
-- Find PowerShell execution with encoded commands or download cradles
SELECT Pid, Ppid, Name, CommandLine, CreateTime, Username
FROM pslist()
WHERE Name =~ "(?i)powershell"
  AND (CommandLine =~ "(?i)(-enc|-encodedcommand|downloadstring|invoke-expression|iex|frombase64)"
    OR CommandLine =~ "(?i)(bypass|hidden|noprofile|windowstyle hidden)")
```

---

## Hunt 9 — Kernel Module Loading (Rootkit Detection)

```sql
-- Find kernel modules loaded in last hour
SELECT name, size, refcnt, used_by
FROM modules()

-- Cross-reference: any module NOT in known baseline
-- Run baseline first: SELECT name FROM modules() > /root/module-baseline.txt
```

---

## Hunt 10 — Full DFIR Timeline (Post-Compromise)

```sql
-- Build filesystem timeline for last 48 hours (for a specific directory)
-- Run as a targeted collection after identifying compromised host

SELECT FullPath, Mtime, Atime, Ctime,
       Size, Mode,
       hash(path=FullPath) AS SHA256
FROM glob(globs=["/**"])
WHERE (Mtime > now() - 172800    -- Modified last 48h
    OR Ctime > now() - 172800)   -- Changed last 48h
  AND NOT FullPath =~ "^/(proc|sys|dev|run)"
ORDER BY Mtime DESC
LIMIT 5000
```

---

## Running Hunts at Scale

```
# In Velociraptor UI:
1. Hunt Manager → New Hunt
2. Select: All Clients
3. Paste query above
4. Set timeout: 300 seconds
5. Launch Hunt

# Monitor progress: Hunt Manager → your hunt → Results
# Export: Download CSV or JSON
```
