#!/usr/bin/env bash
# =============================================================================
# install-arkime.sh — Full Packet Capture + Search Platform
# Target: Ubuntu 22.04 (192.168.50.20) — needs 200GB+ disk
# Arkime (formerly Moloch) stores full PCAPs searchable like Splunk
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; BLUE='\033[0;34m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
step()  { echo -e "\n${BLUE}══ $* ══${NC}"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo $0"

ARKIME_VERSION="4.3.1"
CAPTURE_IFACE="${CAPTURE_IFACE:-eth1}"
PCAP_DIR="${PCAP_DIR:-/data/pcap}"
ARKIME_PASS="${ARKIME_PASS:-$(openssl rand -base64 12 | tr -d '/+=')}}"

step "1/5 — Prerequisites"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y curl wget libpcap-dev libnss3-dev libglib2.0-dev \
    libssl-dev libkrb5-dev uuid-dev libmaxminddb-dev libyaml-dev \
    net-tools jq python3 python3-pip

mkdir -p "$PCAP_DIR"

step "2/5 — Install Elasticsearch (Arkime data store)"
curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | \
    gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg

echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] \
    https://artifacts.elastic.co/packages/8.x/apt stable main" \
    > /etc/apt/sources.list.d/elastic-8.x.list

apt-get update -qq
apt-get install -y elasticsearch

# Configure Elasticsearch for Arkime
cat > /etc/elasticsearch/elasticsearch.yml << 'ESCONF'
cluster.name: arkime-cluster
node.name: arkime-node
network.host: 127.0.0.1
http.port: 9200
discovery.type: single-node
xpack.security.enabled: false
xpack.security.http.ssl.enabled: false
indices.query.bool.max_clause_count: 8192
thread_pool:
  search:
    queue_size: 100000
ESCONF

# Set JVM heap
RAM_MB=$(free -m | awk '/^Mem:/{print $2}')
HEAP=$((RAM_MB / 4))
[[ $HEAP -gt 4096 ]] && HEAP=4096
sed -i "s/-Xms[0-9]*g/-Xms${HEAP}m/" /etc/elasticsearch/jvm.options
sed -i "s/-Xmx[0-9]*g/-Xmx${HEAP}m/" /etc/elasticsearch/jvm.options

systemctl enable --now elasticsearch
info "Waiting for Elasticsearch..."
for i in {1..20}; do
    curl -s http://localhost:9200/_cluster/health 2>/dev/null | grep -q '"status"' && break
    sleep 5; echo -n "."
done
echo ""

step "3/5 — Install Arkime"
wget -qO /tmp/arkime.deb \
    "https://github.com/arkime/arkime/releases/download/v${ARKIME_VERSION}/arkime_${ARKIME_VERSION}-1.ubuntu2204_amd64.deb"
dpkg -i /tmp/arkime.deb

step "4/5 — Configure Arkime"
cat > /opt/arkime/etc/config.ini << ARKIMECONF
[default]
# Elasticsearch connection
elasticsearch=http://localhost:9200

# Capture interface (promiscuous mode)
interface=${CAPTURE_IFACE}

# PCAP storage
pcapDir=${PCAP_DIR}
maxFileSizeG=5
maxFileTimeM=60

# Retention (delete oldest when disk > 90%)
freeSpaceG=5

# Performance
maxPacketsInQueue=200000
dbBulkSize=500000
compressES=false
maxStreams=1500000

# Viewer web server
viewPort=8005

# Password for web access (hashed on first run)
passwordSecret=${ARKIME_PASS}

# GeoIP for IP geolocation
geoLite2Country=/opt/arkime/etc/GeoLite2-Country.mmdb;/usr/share/GeoIP/GeoLite2-Country.mmdb
geoLite2City=/opt/arkime/etc/GeoLite2-City.mmdb;/usr/share/GeoIP/GeoLite2-City.mmdb
geoLite2ASN=/opt/arkime/etc/GeoLite2-ASN.mmdb;/usr/share/GeoIP/GeoLite2-ASN.mmdb

# Capture settings
bpf=not port 22 and not port 5353
# ^ Exclude SSH management and mDNS from capture to reduce noise

# Tags for easy filtering in UI
tags=soc-lab

# Plugins
rootPlugins=wise.so
wiseHost=127.0.0.1

# Smart field mapping
parseSMTP=true
parseSMTPHeaderAll=true
parseQSValue=false
supportSha256=true
maxReqBody=64
maxResponseBody=64
ARKIMECONF

# Initialize Arkime database
/opt/arkime/db/db.pl http://localhost:9200 init --shards 1 --replicas 0

# Create admin user
/opt/arkime/bin/arkime_add_user.sh admin "SOC Admin" "$ARKIME_PASS" --admin

step "5/5 — Enable Services"
# Enable promiscuous mode on capture interface
ip link set "$CAPTURE_IFACE" promisc on

systemctl enable --now arkimecapture arkimeviewer

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Arkime Installation Complete!                           ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Web UI:  http://192.168.50.20:8005                      ║${NC}"
echo -e "${GREEN}║  Login:   admin / ${ARKIME_PASS}          ║${NC}"
echo -e "${GREEN}║  PCAPs:   ${PCAP_DIR}                           ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Capturing on interface: ${CAPTURE_IFACE}                ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
