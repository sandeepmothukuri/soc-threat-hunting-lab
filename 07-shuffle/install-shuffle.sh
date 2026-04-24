#!/usr/bin/env bash
# =============================================================================
# install-shuffle.sh — Shuffle SOAR (Security Orchestration, Automation, Response)
# Target: Ubuntu 22.04 (192.168.60.30)
# Shuffle: Open-source SOAR platform — automate IR workflows visually
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; BLUE='\033[0;34m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
step()  { echo -e "\n${BLUE}══ $* ══${NC}"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo $0"

SHUFFLE_IP="${SHUFFLE_IP:-192.168.60.30}"

step "1/4 — Install Docker + Docker Compose"
curl -fsSL https://get.docker.com | sh
apt-get install -y docker-compose-plugin
systemctl enable --now docker
info "Docker $(docker --version) ready"

step "2/4 — Clone Shuffle"
cd /opt
git clone https://github.com/Shuffle/Shuffle.git shuffle 2>/dev/null || {
    cd shuffle && git pull && cd ..
}
cd /opt/shuffle
info "Shuffle source ready"

step "3/4 — Configure Environment"
# Generate secrets
SHUFFLE_SECRET=$(openssl rand -base64 32 | tr -d '/+=')
SHUFFLE_OPENSEARCH_PASS=$(openssl rand -base64 16 | tr -d '/+=')

cat > /opt/shuffle/.env << ENV
SHUFFLE_DEFAULT_USERNAME=admin
SHUFFLE_DEFAULT_PASSWORD=${SHUFFLE_SECRET}
SHUFFLE_DEFAULT_APIKEY=$(openssl rand -hex 32)
SHUFFLE_OPENSEARCH_USERNAME=admin
SHUFFLE_OPENSEARCH_PASSWORD=${SHUFFLE_OPENSEARCH_PASS}
BASE_URL=http://${SHUFFLE_IP}:3001
OUTER_HOSTNAME=${SHUFFLE_IP}
HTTPS_PROXY=
HTTP_PROXY=
no_proxy=
ENV

# Patch docker-compose to use our env vars
if [[ -f docker-compose.yml ]]; then
    sed -i "s/SHUFFLE_DEFAULT_PASSWORD=.*/SHUFFLE_DEFAULT_PASSWORD=${SHUFFLE_SECRET}/" docker-compose.yml
fi

step "4/4 — Start Shuffle"
docker compose up -d

info "Waiting for services to start (60s)..."
sleep 60

# Verify
if curl -s http://localhost:3001/api/v1/health | grep -q "success\|ok" 2>/dev/null; then
    info "Shuffle API responding"
else
    info "Shuffle starting up — may take 2-3 minutes on first run"
fi

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Shuffle SOAR Ready!                                         ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Web UI:  http://${SHUFFLE_IP}:3001                    ║${NC}"
echo -e "${GREEN}║  Login:   admin / ${SHUFFLE_SECRET:0:20}          ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Next: Import workflows from workflows/ directory            ║${NC}"
echo -e "${GREEN}║    1. Login → Workflows → Import                             ║${NC}"
echo -e "${GREEN}║    2. Import: soc-incident-response.json                     ║${NC}"
echo -e "${GREEN}║    3. Import: misp-to-thehive.json                           ║${NC}"
echo -e "${GREEN}║    4. Configure apps: TheHive, MISP, Slack/Email             ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"

# Save creds
echo "SHUFFLE_URL=http://${SHUFFLE_IP}:3001" > /root/.shuffle-creds
echo "SHUFFLE_USER=admin" >> /root/.shuffle-creds
echo "SHUFFLE_PASS=${SHUFFLE_SECRET}" >> /root/.shuffle-creds
chmod 600 /root/.shuffle-creds
