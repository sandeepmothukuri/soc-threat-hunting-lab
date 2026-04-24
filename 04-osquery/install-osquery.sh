#!/usr/bin/env bash
# =============================================================================
# install-osquery.sh — Endpoint Visibility via SQL
# Target: All Linux endpoints (Ubuntu Targets, Zeek VM, etc.)
# OSQuery: Query endpoint state like a database (processes, network, files, users)
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; BLUE='\033[0;34m'; NC='\033[0m'
info() { echo -e "${GREEN}[INFO]${NC}  $*"; }
step() { echo -e "\n${BLUE}══ $* ══${NC}"; }

[[ $EUID -ne 0 ]] && { echo "Run as root"; exit 1; }

step "1/3 — Install OSQuery"
curl -fsSL https://pkg.osquery.io/deb/pubkey.gpg | \
    gpg --dearmor -o /usr/share/keyrings/osquery.gpg

echo "deb [arch=amd64 signed-by=/usr/share/keyrings/osquery.gpg] \
    https://pkg.osquery.io/deb deb main" \
    > /etc/apt/sources.list.d/osquery.list

apt-get update -qq
apt-get install -y osquery

step "2/3 — Configure OSQuery Daemon"
cat > /etc/osquery/osquery.conf << 'CONF'
{
  "options": {
    "config_plugin": "filesystem",
    "logger_plugin": "filesystem",
    "logger_path": "/var/log/osquery",
    "disable_logging": "false",
    "log_result_events": "true",
    "schedule_splay_percent": "10",
    "pidfile": "/var/osquery/osquery.pidfile",
    "events_expiry": "3600",
    "database_path": "/var/osquery/osquery.db",
    "verbose": "false",
    "worker_threads": "2",
    "enable_monitor": "true",
    "disable_events": "false"
  },
  "schedule": {
    "processes_snapshot": {
      "query": "SELECT pid, name, path, cmdline, uid, gid, start_time FROM processes WHERE start_time > (SELECT CAST(strftime('%s','now','-5 minutes') AS INTEGER));",
      "interval": 300,
      "description": "New processes in last 5 minutes"
    },
    "network_connections": {
      "query": "SELECT p.name, p.pid, p.cmdline, n.local_address, n.local_port, n.remote_address, n.remote_port, n.state FROM process_open_sockets n JOIN processes p ON n.pid = p.pid WHERE n.remote_port > 0 AND n.state = 'ESTABLISHED';",
      "interval": 60,
      "description": "Active outbound connections"
    },
    "listening_ports": {
      "query": "SELECT p.name, p.pid, l.port, l.protocol, l.address FROM listening_ports l JOIN processes p ON l.pid = p.pid WHERE l.port > 0;",
      "interval": 300,
      "description": "Services listening on ports"
    },
    "crontab": {
      "query": "SELECT * FROM crontab;",
      "interval": 3600,
      "description": "Cron jobs (persistence check)"
    },
    "users": {
      "query": "SELECT username, uid, gid, shell, directory FROM users WHERE uid >= 1000;",
      "interval": 3600,
      "description": "User accounts"
    },
    "suid_binaries": {
      "query": "SELECT path, username, permissions, inode, uid, gid FROM suid_bin;",
      "interval": 3600,
      "description": "SUID/SGID binaries"
    },
    "ssh_authorized_keys": {
      "query": "SELECT * FROM authorized_keys;",
      "interval": 3600,
      "description": "SSH authorized keys (backdoor detection)"
    },
    "kernel_modules": {
      "query": "SELECT name, size, used_by FROM kernel_modules;",
      "interval": 3600,
      "description": "Loaded kernel modules (rootkit detection)"
    },
    "iptables": {
      "query": "SELECT * FROM iptables;",
      "interval": 300,
      "description": "Firewall rules changes"
    }
  },
  "packs": {
    "soc-detections": "/etc/osquery/packs/soc-detections.conf",
    "incident-response": "/etc/osquery/packs/incident-response.conf"
  },
  "decorators": {
    "load": [
      "SELECT uuid AS host_uuid FROM system_info;",
      "SELECT user AS username FROM logged_in_users ORDER BY time DESC LIMIT 1;"
    ]
  },
  "file_paths": {
    "etc": ["/etc/%%"],
    "homes": ["/root/.%%", "/home/%/.%%"],
    "tmp": ["/tmp/%%", "/var/tmp/%%", "/dev/shm/%%"]
  },
  "events": {
    "disable_subscribers": []
  }
}
CONF

step "3/3 — Deploy Detection Packs"
mkdir -p /etc/osquery/packs
cp packs/soc-detections.conf /etc/osquery/packs/ 2>/dev/null || true
cp packs/incident-response.conf /etc/osquery/packs/ 2>/dev/null || true

systemctl enable --now osqueryd
info "OSQuery daemon started"
info "Logs: /var/log/osquery/osqueryd.results.log"

echo ""
echo "Test with: osqueryi 'SELECT name, pid, path FROM processes LIMIT 10;'"
