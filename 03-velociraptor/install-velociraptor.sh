#!/usr/bin/env bash
# =============================================================================
# install-velociraptor.sh — EDR / DFIR Platform
# Target: Ubuntu 22.04 (192.168.50.30)
# Velociraptor: Live endpoint forensics, threat hunting, incident response
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; BLUE='\033[0;34m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
step()  { echo -e "\n${BLUE}══ $* ══${NC}"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo $0"

VELO_VERSION="0.72.3"
SERVER_IP="${SERVER_IP:-192.168.50.30}"
ADMIN_PASS="${ADMIN_PASS:-$(openssl rand -base64 16 | tr -d '/+=')}"

step "1/4 — Download Velociraptor"
VELO_URL="https://github.com/Velocidex/velociraptor/releases/download/v${VELO_VERSION}/velociraptor-v${VELO_VERSION}-linux-amd64"
curl -fsSL -o /usr/local/bin/velociraptor "$VELO_URL"
chmod +x /usr/local/bin/velociraptor
info "Velociraptor $(velociraptor version | head -1) installed"

step "2/4 — Generate Server Config"
mkdir -p /etc/velociraptor /opt/velociraptor/{datastore,logs,public}

# Generate self-signed certs and config
velociraptor config generate --merge '{
  "Client": {
    "server_urls": ["https://'"$SERVER_IP"':8000/"],
    "use_self_signed_ssl": true
  },
  "API": {
    "bind_address": "0.0.0.0",
    "bind_port": 8001
  },
  "GUI": {
    "bind_address": "0.0.0.0",
    "bind_port": 8889,
    "internal_cidr": ["192.168.0.0/16"]
  },
  "Frontend": {
    "bind_address": "0.0.0.0",
    "bind_port": 8000,
    "hostname": "'"$SERVER_IP"'"
  },
  "Datastore": {
    "implementation": "FileBaseDataStore",
    "location": "/opt/velociraptor/datastore",
    "filestore_directory": "/opt/velociraptor/datastore"
  },
  "Logging": {
    "output_directory": "/opt/velociraptor/logs",
    "separate_logs_per_component": true
  }
}' > /etc/velociraptor/server.config.yaml

# Create admin user
velociraptor --config /etc/velociraptor/server.config.yaml \
    user add --role administrator admin "$ADMIN_PASS"

step "3/4 — Install Custom Artifacts"
mkdir -p /opt/velociraptor/artifacts

# Copy our custom artifacts
for artifact in artifacts/*.yaml; do
    [[ -f "$artifact" ]] && cp "$artifact" /opt/velociraptor/artifacts/
done

step "4/4 — Create Systemd Service"
cat > /etc/systemd/system/velociraptor.service << 'SYSTEMD'
[Unit]
Description=Velociraptor EDR Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/velociraptor --config /etc/velociraptor/server.config.yaml frontend
Restart=always
RestartSec=5
LimitNOFILE=1048576
LimitNPROC=512

[Install]
WantedBy=multi-user.target
SYSTEMD

systemctl daemon-reload
systemctl enable --now velociraptor

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Velociraptor Server Ready!                              ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Web UI: https://192.168.50.30:8889                      ║${NC}"
echo -e "${GREEN}║  Login:  admin / ${ADMIN_PASS}             ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Generate agent installer:                               ║${NC}"
echo -e "${GREEN}║    velociraptor config client > client.config.yaml       ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"

# Save credentials
echo "VELO_URL=https://${SERVER_IP}:8889" > /root/.velociraptor-creds
echo "VELO_USER=admin" >> /root/.velociraptor-creds
echo "VELO_PASS=${ADMIN_PASS}" >> /root/.velociraptor-creds
chmod 600 /root/.velociraptor-creds
