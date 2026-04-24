#!/usr/bin/env bash
# =============================================================================
# install-rita.sh — Real Intelligence Threat Analytics
# Analyzes Zeek logs to detect: C2 beaconing, DNS tunneling,
# long connections, data exfiltration, scanning behavior
# Target: Same VM as Zeek (192.168.50.10)
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; BLUE='\033[0;34m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
step()  { echo -e "\n${BLUE}══ $* ══${NC}"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo $0"

RITA_VERSION="v4.8.0"

step "1/4 — Install MongoDB (RITA database backend)"
# Import MongoDB public GPG key
curl -fsSL https://www.mongodb.org/static/pgp/server-6.0.asc | \
    gpg --dearmor -o /usr/share/keyrings/mongodb-server-6.0.gpg

echo "deb [ arch=amd64,arm64 signed-by=/usr/share/keyrings/mongodb-server-6.0.gpg ] \
    https://repo.mongodb.org/apt/ubuntu jammy/mongodb-org/6.0 multiverse" \
    > /etc/apt/sources.list.d/mongodb-org-6.0.list

apt-get update -qq
apt-get install -y mongodb-org

systemctl enable --now mongod
info "MongoDB started"

step "2/4 — Install RITA"
# Download RITA installer
curl -fsSL "https://github.com/activecm/rita/releases/download/${RITA_VERSION}/install.sh" \
    -o /tmp/rita-install.sh
chmod +x /tmp/rita-install.sh
/tmp/rita-install.sh

# Verify installation
rita --version 2>/dev/null || { info "RITA installed at $(which rita)"; }

step "3/4 — Configure RITA"
mkdir -p /etc/rita

cat > /etc/rita/config.yaml << 'RITACONF'
# RITA Configuration — SOC Threat Detection Lab
MongoDB:
  ConnectionString: "mongodb://localhost:27017"
  AuthenticationMechanism: ""
  SocketTimeout: 2
  TLS:
    Enable: false

LogConfig:
  LogLevel: 2
  LogPath: /var/log/rita/rita.log
  RitaLogPath: /var/log/rita/

UserConfig:
  # Minimum beacon score to report (0.0 - 1.0, higher = more confident)
  # 0.7+ is suspicious, 0.9+ is very likely beaconing
  MinBeaconScore: 0.7

  # Beacon detection thresholds
  BeaconScoreWeightConsistency: 0.25
  BeaconScoreWeightFrequency:   0.25
  BeaconScoreWeightHistogram:   0.25
  BeaconScoreWeightBimodal:     0.25

  # Long connection threshold (seconds)
  LongConnectionCutoff: 3600  # Alert on connections > 1 hour

  # DNS threshold
  DNSExplodedEnabled: true
  DNSThreshold: 100  # Unique subdomains of same domain

  # Scanning: connections per hour to unique IPs
  ScanThreshold: 100

  # Blacklisted IPs (MISP integration)
  Blacklist:
    CustomIPsEnabled: false
    CustomIPs: []
    CustomHostnamesEnabled: false
    CustomHostnames: []

  # InternalSubnets — traffic between these is "internal"
  InternalSubnets:
    - "192.168.0.0/16"
    - "10.0.0.0/8"
    - "172.16.0.0/12"

  # Filtering: ignore benign noise
  AlwaysInclude: []
  NeverInclude:
    - "224.0.0.0/4"      # Multicast
    - "255.255.255.255/32" # Broadcast
    - "::1"              # IPv6 loopback

ImportConfig:
  # Where Zeek logs are stored
  ImportDirectory: "/opt/zeek/logs/current/"
  ZeekConfig: "/opt/zeek/etc/zeekctl.cfg"
RITACONF

mkdir -p /var/log/rita

step "4/4 — Create RITA Analysis Schedule"
# Daily analysis cron job
cat > /etc/cron.d/rita-analyze << 'CRON'
# RITA — Import and analyze Zeek logs daily at 01:00
0 1 * * * root rita import --config /etc/rita/config.yaml --database zeek-$(date +%Y%m%d) /opt/zeek/logs/$(date -d yesterday +%Y-%m-%d) 2>&1 | logger -t rita
30 1 * * * root rita analyze --config /etc/rita/config.yaml --database zeek-$(date +%Y%m%d) 2>&1 | logger -t rita
CRON

# Manual import helper script
cat > /usr/local/bin/rita-analyze-now << 'SCRIPT'
#!/bin/bash
# Run RITA analysis on today's Zeek logs
DB="zeek-$(date +%Y%m%d)"
echo "[RITA] Importing today's Zeek logs into database: $DB"
rita import --config /etc/rita/config.yaml --database "$DB" /opt/zeek/logs/current/

echo "[RITA] Running analysis..."
rita analyze --config /etc/rita/config.yaml --database "$DB"

echo ""
echo "[RITA] === BEACONING RESULTS ==="
rita show-beacons --config /etc/rita/config.yaml --database "$DB" --human-readable

echo ""
echo "[RITA] === LONG CONNECTIONS ==="
rita show-long-connections --config /etc/rita/config.yaml --database "$DB" --human-readable

echo ""
echo "[RITA] === DNS TUNNELING ==="
rita show-exploded-dns --config /etc/rita/config.yaml --database "$DB" --human-readable

echo ""
echo "[RITA] === SCANNING ==="
rita show-scans --config /etc/rita/config.yaml --database "$DB" --human-readable
SCRIPT

chmod +x /usr/local/bin/rita-analyze-now

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  RITA Installation Complete!                             ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Analyze now:  rita-analyze-now                          ║${NC}"
echo -e "${GREEN}║  Show beacons: rita show-beacons --database zeek-DATE    ║${NC}"
echo -e "${GREEN}║  HTML report:  rita html-report --database zeek-DATE     ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
