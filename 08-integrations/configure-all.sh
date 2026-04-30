#!/bin/bash
# configure-all.sh — Wire up all SOC tool integrations
# Run once after all 9 tools are installed and running.
# Sets API keys, webhooks, Cortex analyzers, Shuffle workflows.
set -euo pipefail

# ── Configuration (edit these to match your lab IPs) ─────────────────────────
MISP_IP="${MISP_IP:-192.168.60.10}"
THEHIVE_IP="${THEHIVE_IP:-192.168.60.20}"
CORTEX_IP="${CORTEX_IP:-192.168.60.21}"
SHUFFLE_IP="${SHUFFLE_IP:-192.168.60.30}"
VELOCIRAPTOR_IP="${VELOCIRAPTOR_IP:-192.168.50.30}"

THEHIVE_API_KEY="${THEHIVE_API_KEY:-}"
CORTEX_API_KEY="${CORTEX_API_KEY:-}"
MISP_API_KEY="${MISP_API_KEY:-}"
VIRUSTOTAL_API_KEY="${VIRUSTOTAL_API_KEY:-}"
ABUSEIPDB_API_KEY="${ABUSEIPDB_API_KEY:-}"

INTEGRATION_DIR="$(dirname "$(realpath "$0")")/08-integrations/scripts"

# ── Helper functions ──────────────────────────────────────────────────────────
log()     { echo "[$(date +%H:%M:%S)] $*"; }
success() { echo "[$(date +%H:%M:%S)] ✅ $*"; }
warn()    { echo "[$(date +%H:%M:%S)] ⚠️  $*"; }
die()     { echo "ERROR: $*" >&2; exit 1; }

check_reachable() {
  local name="$1" url="$2"
  if curl -sk --max-time 5 "$url" -o /dev/null; then
    success "$name reachable at $url"
    return 0
  else
    warn "$name not reachable at $url — check it is running"
    return 1
  fi
}

require_api_key() {
  local name="$1" key="$2"
  if [[ -z "$key" ]]; then
    warn "$name API key not set — skipping related integrations (set env var ${name^^}_API_KEY)"
    return 1
  fi
  return 0
}

# ── Step 1: Verify all services reachable ─────────────────────────────────────
log "=== Step 1: Service Connectivity Check ==="
check_reachable "TheHive"       "http://$THEHIVE_IP:9000/api/status" || true
check_reachable "Cortex"        "http://$CORTEX_IP:9001/api/status"  || true
check_reachable "MISP"          "https://$MISP_IP"                   || true
check_reachable "Shuffle"       "http://$SHUFFLE_IP:3001"            || true
check_reachable "Velociraptor"  "https://$VELOCIRAPTOR_IP:8889"      || true

# ── Step 2: Configure OSQuery → TheHive forwarder ────────────────────────────
log ""
log "=== Step 2: OSQuery → TheHive Forwarder ==="

OSQUERY_FORWARDER="$INTEGRATION_DIR/osquery-to-thehive.py"
if [[ -f "$OSQUERY_FORWARDER" ]]; then
  if require_api_key "TheHive" "$THEHIVE_API_KEY"; then
    cat > /etc/systemd/system/osquery-thehive.service << SERVICE
[Unit]
Description=OSQuery to TheHive Forwarder
After=osqueryd.service network-online.target
Requires=osqueryd.service

[Service]
Type=simple
Environment=THEHIVE_URL=http://$THEHIVE_IP:9000
Environment=THEHIVE_API_KEY=$THEHIVE_API_KEY
Environment=OSQUERY_LOG=/var/log/osquery/osqueryd.results.log
ExecStart=/usr/bin/python3 $OSQUERY_FORWARDER --watch
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
SERVICE
    systemctl daemon-reload
    systemctl enable --now osquery-thehive.service
    success "OSQuery → TheHive forwarder installed (60s poll interval)"
  fi
else
  warn "osquery-to-thehive.py not found at $OSQUERY_FORWARDER"
fi

# ── Step 3: Configure Zeek → TheHive forwarder ───────────────────────────────
log ""
log "=== Step 3: Zeek → TheHive Forwarder ==="

ZEEK_FORWARDER="$INTEGRATION_DIR/zeek-to-thehive.py"
if [[ -f "$ZEEK_FORWARDER" ]] && require_api_key "TheHive" "$THEHIVE_API_KEY"; then
  cat > /etc/systemd/system/zeek-thehive.service << SERVICE
[Unit]
Description=Zeek to TheHive Forwarder
After=network-online.target

[Service]
Type=simple
Environment=THEHIVE_URL=http://$THEHIVE_IP:9000
Environment=THEHIVE_API_KEY=$THEHIVE_API_KEY
ExecStart=/usr/bin/python3 $ZEEK_FORWARDER --watch
Restart=on-failure
RestartSec=30

[Install]
WantedBy=multi-user.target
SERVICE
  systemctl daemon-reload
  systemctl enable --now zeek-thehive.service
  success "Zeek → TheHive forwarder installed"
fi

# ── Step 4: Enable Cortex Analyzers ──────────────────────────────────────────
log ""
log "=== Step 4: Cortex Analyzer Configuration ==="

if require_api_key "Cortex" "$CORTEX_API_KEY"; then
  ANALYZERS_CONF="/etc/cortex/application.conf"
  if [[ -f "$ANALYZERS_CONF" ]]; then
    # Inject API keys for key analyzers
    [[ -n "$VIRUSTOTAL_API_KEY" ]] && \
      sed -i "s/VIRUSTOTAL_API_KEY_PLACEHOLDER/$VIRUSTOTAL_API_KEY/" "$ANALYZERS_CONF" && \
      success "VirusTotal analyzer configured"

    [[ -n "$ABUSEIPDB_API_KEY" ]] && \
      sed -i "s/ABUSEIPDB_API_KEY_PLACEHOLDER/$ABUSEIPDB_API_KEY/" "$ANALYZERS_CONF" && \
      success "AbuseIPDB analyzer configured"
  else
    warn "Cortex config not found at $ANALYZERS_CONF — configure analyzers manually at http://$CORTEX_IP:9001"
  fi
fi

# ── Step 5: Connect TheHive → Cortex ─────────────────────────────────────────
log ""
log "=== Step 5: TheHive → Cortex Link ==="

if require_api_key "TheHive" "$THEHIVE_API_KEY" && require_api_key "Cortex" "$CORTEX_API_KEY"; then
  PAYLOAD=$(cat <<JSON
{
  "name": "SOCLab-Cortex",
  "url": "http://$CORTEX_IP:9001",
  "auth": {"type": "bearer", "key": "$CORTEX_API_KEY"},
  "autoExtractArtifacts": true
}
JSON
)
  RESP=$(curl -sk -X POST \
    "http://$THEHIVE_IP:9000/api/v1/connector/cortex" \
    -H "Authorization: Bearer $THEHIVE_API_KEY" \
    -H "Content-Type: application/json" \
    -d "$PAYLOAD" 2>&1)

  if echo "$RESP" | grep -q '"_id"'; then
    success "TheHive → Cortex connector registered"
  else
    warn "Could not auto-register Cortex in TheHive — do it manually: http://$THEHIVE_IP:9000 → Organization → Connectors"
  fi
fi

# ── Step 6: Import Shuffle Workflows ─────────────────────────────────────────
log ""
log "=== Step 6: Shuffle Workflow Import ==="

WORKFLOW_DIR="$(dirname "$(realpath "$0")")/07-shuffle/workflows"
if [[ -d "$WORKFLOW_DIR" ]] && require_api_key "Shuffle" "${SHUFFLE_API_KEY:-}"; then
  for wf in "$WORKFLOW_DIR"/*.json; do
    wf_name=$(basename "$wf" .json)
    curl -sk -X POST "http://$SHUFFLE_IP:3001/api/v1/workflows" \
      -H "Authorization: Bearer $SHUFFLE_API_KEY" \
      -H "Content-Type: application/json" \
      -d @"$wf" -o /dev/null && success "Workflow imported: $wf_name"
  done
else
  warn "Import Shuffle workflows manually from 07-shuffle/workflows/ at http://$SHUFFLE_IP:3001"
fi

# ── Done ──────────────────────────────────────────────────────────────────────
log ""
log "=== Integration Setup Complete ==="
log "Next: run ./scripts/health-check.sh to verify all connections"
log ""
log "Manual steps remaining (if API keys not set):"
log "  1. Cortex analyzers: http://$CORTEX_IP:9001 → Organization → Analyzers"
log "  2. TheHive → Cortex: http://$THEHIVE_IP:9000 → Organization → Connectors"
log "  3. Shuffle workflows: http://$SHUFFLE_IP:3001 → Workflows → Import"
log "  4. MISP → TheHive connector: set THEHIVE_URL in MISP sync settings"
