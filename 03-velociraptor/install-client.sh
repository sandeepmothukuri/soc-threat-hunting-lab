#!/bin/bash
# install-client.sh — Install and register Velociraptor client agent
# Usage: sudo VELOCIRAPTOR_SERVER=192.168.50.30 ./install-client.sh
set -euo pipefail

VELO_SERVER="${VELOCIRAPTOR_SERVER:-192.168.50.30}"
VELO_PORT="${VELOCIRAPTOR_PORT:-8000}"
VELO_VERSION="${VELOCIRAPTOR_VERSION:-0.7.0}"
INSTALL_DIR="/opt/velociraptor"
CONFIG_DIR="/etc/velociraptor"
LOG_DIR="/var/log/velociraptor"
ARCH=$(uname -m)

log()  { echo "[$(date +%H:%M:%S)] $*"; }
die()  { echo "ERROR: $*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run as root: sudo $0"
[[ -n "$VELO_SERVER" ]] || die "Set VELOCIRAPTOR_SERVER env var"

# ── Detect architecture ──────────────────────────────────────────────────────
case "$ARCH" in
  x86_64)  VELO_ARCH="linux-amd64" ;;
  aarch64) VELO_ARCH="linux-arm64" ;;
  *)       die "Unsupported architecture: $ARCH" ;;
esac

log "Installing Velociraptor client → server: $VELO_SERVER:$VELO_PORT"
log "Version: $VELO_VERSION | Arch: $VELO_ARCH"

# ── Install dependencies ─────────────────────────────────────────────────────
apt-get update -qq
apt-get install -y -qq curl wget jq

# ── Download Velociraptor binary ─────────────────────────────────────────────
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR"

BINARY="$INSTALL_DIR/velociraptor"
DOWNLOAD_URL="https://github.com/Velocidex/velociraptor/releases/download/v${VELO_VERSION}/velociraptor-v${VELO_VERSION}-${VELO_ARCH}"

log "Downloading from: $DOWNLOAD_URL"
wget -q --show-progress -O "$BINARY" "$DOWNLOAD_URL"
chmod +x "$BINARY"

log "Binary installed at: $BINARY"
"$BINARY" version 2>/dev/null | grep -E "Version|BuildTime" || true

# ── Fetch client config from server ─────────────────────────────────────────
# The server exposes a client config at its frontend port
CONFIG_FILE="$CONFIG_DIR/client.config.yaml"

log "Fetching client config from server $VELO_SERVER:$VELO_PORT ..."
if ! curl -sk --max-time 10 \
    "https://$VELO_SERVER:$VELO_PORT/server.pem" -o /tmp/server.pem 2>/dev/null; then
  log "Cannot reach server automatically — generating standalone config"
  "$BINARY" config generate --merge '{"Client":{"server_urls":["https://'"$VELO_SERVER"':'"$VELO_PORT"'/"]}}' \
    > "$CONFIG_FILE"
else
  # Server reachable — use server-generated client config
  "$BINARY" config generate \
    --merge "{\"Client\":{\"server_urls\":[\"https://$VELO_SERVER:$VELO_PORT/\"]}}" \
    > "$CONFIG_FILE"
fi

log "Client config written: $CONFIG_FILE"

# ── Create systemd service ────────────────────────────────────────────────────
cat > /etc/systemd/system/velociraptor-client.service << SERVICE
[Unit]
Description=Velociraptor Client Agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=$BINARY --config $CONFIG_FILE client
Restart=on-failure
RestartSec=10
StandardOutput=append:$LOG_DIR/client.log
StandardError=append:$LOG_DIR/client-error.log

[Install]
WantedBy=multi-user.target
SERVICE

# ── Enable and start service ─────────────────────────────────────────────────
systemctl daemon-reload
systemctl enable --now velociraptor-client.service

sleep 3
if systemctl is-active --quiet velociraptor-client.service; then
  log "✅ Velociraptor client running"
  log "   Check server UI at: https://$VELO_SERVER:8889"
  log "   Agent should appear in 'Clients' within 30 seconds"
else
  log "⚠️  Service may not have started — check: journalctl -u velociraptor-client -n 50"
fi

log "Done. Logs: $LOG_DIR/client.log"
