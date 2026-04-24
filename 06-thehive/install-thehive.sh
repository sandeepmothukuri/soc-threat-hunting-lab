#!/usr/bin/env bash
# =============================================================================
# install-thehive.sh — TheHive 5 Case Management + Cortex Analysis
# Target: Ubuntu 22.04 (192.168.60.20)
# TheHive: SOC case management, incident tracking, analyst collaboration
# Cortex: IOC enrichment analyzers (VirusTotal, MISP, Shodan, abuse.ch)
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; BLUE='\033[0;34m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
step()  { echo -e "\n${BLUE}══ $* ══${NC}"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo $0"

HIVE_IP="${HIVE_IP:-192.168.60.20}"
HIVE_ADMIN_PASS="${HIVE_ADMIN_PASS:-$(openssl rand -base64 16 | tr -d '/+=')}"

step "1/5 — Install Java 11 + Dependencies"
apt-get update -qq
apt-get install -y openjdk-11-jre-headless curl gnupg apt-transport-https wget

step "2/5 — Install Cassandra (Database)"
# Cassandra 4.x for TheHive 5
wget -qO- https://downloads.apache.org/cassandra/KEYS | gpg --dearmor -o /usr/share/keyrings/cassandra.gpg
echo "deb [signed-by=/usr/share/keyrings/cassandra.gpg] https://debian.cassandra.apache.org 40x main" \
    > /etc/apt/sources.list.d/cassandra.list
apt-get update -qq && apt-get install -y cassandra

# Configure Cassandra for TheHive
sed -i "s/cluster_name: 'Test Cluster'/cluster_name: 'SOC-Lab'/" /etc/cassandra/cassandra.yaml
sed -i "s/^# data_file_directories:/data_file_directories:/" /etc/cassandra/cassandra.yaml

systemctl enable --now cassandra
info "Cassandra started — waiting 30s for startup..."
sleep 30

step "3/5 — Install TheHive 5"
# Add TheHive repository
wget -qO- https://raw.githubusercontent.com/StrangeBee/TheHive/main/PGP-PUBLIC-KEY | \
    gpg --dearmor -o /usr/share/keyrings/thehive.gpg
echo "deb [signed-by=/usr/share/keyrings/thehive.gpg] https://deb.thehive-project.org release main" \
    > /etc/apt/sources.list.d/thehive.list

apt-get update -qq && apt-get install -y thehive

step "4/5 — Configure TheHive"
mkdir -p /opt/thehive/{data,logs,attachments}
chown -R thehive:thehive /opt/thehive

cat > /etc/thehive/application.conf << THEHIVE_CONF
# TheHive 5 Configuration — SOC Lab
# ===================================

# Database
db.janusgraph {
  storage {
    backend: cql
    hostname: ["127.0.0.1"]
    cql {
      cluster-name: SOC-Lab
      keyspace: thehive
    }
  }
}

# File attachments
storage {
  provider: localfs
  localfs.location: /opt/thehive/attachments
}

# HTTP server
play.http.secret.key: "$(openssl rand -base64 32)"
play.server.http.port: 9000

# MISP integration
misp {
  servers: [
    {
      name: "SOC-Lab-MISP"
      url: "https://192.168.60.10"
      key: "\${?MISP_API_KEY}"
      tags: ["MISP"]
      max-events: 50
      exclusion {
        organisations: []
        tags: ["tlp:red"]
      }
    }
  ]
}

# Cortex integration
cortex {
  servers: [
    {
      name: "SOC-Lab-Cortex"
      url: "http://192.168.60.20:9001"
      key: "\${?CORTEX_API_KEY}"
      timeout: 60 seconds
    }
  ]
}

# Notifications
notification.webhook.endpoints: [
  {
    name: shuffle-webhook
    url: "http://192.168.60.30:3001/api/v1/hooks/thehive-new-case"
    auth {
      type: "hmac"
      algorithm: "hmac-sha256"
    }
  }
]

# Audit logs
audit {
  enabled: true
  format: json
  path: /opt/thehive/logs/audit.log
}
THEHIVE_CONF

chown thehive:thehive /etc/thehive/application.conf

step "5/5 — Install Cortex (IOC Enrichment Engine)"
echo "deb [signed-by=/usr/share/keyrings/thehive.gpg] https://deb.thehive-project.org release main" \
    > /etc/apt/sources.list.d/cortex.list
apt-get update -qq && apt-get install -y cortex 2>/dev/null || \
    info "Cortex install skipped — install manually from: https://docs.thehive-project.org/cortex/"

# Start services
systemctl enable --now thehive
sleep 15

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  TheHive 5 Case Management Ready!                            ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  TheHive UI:  http://${HIVE_IP}:9000                   ║${NC}"
echo -e "${GREEN}║  Cortex UI:   http://${HIVE_IP}:9001 (if installed)    ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Default Login: admin@thehive.local / secret              ║${NC}"
echo -e "${GREEN}║  Change password on first login!                             ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Docs: https://docs.thehive-project.org/thehive/            ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
