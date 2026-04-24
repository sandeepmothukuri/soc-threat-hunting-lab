#!/usr/bin/env bash
# =============================================================================
# health-check.sh — Verify All Lab Services Are Running
# Run from: Any host with network access to lab VLANs
# Usage: ./health-check.sh [--fix] [--verbose]
# =============================================================================

GREEN='\033[0;32m'; RED='\033[0;31m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
PASS=0; FAIL=0; WARN=0

pass()  { echo -e "  ${GREEN}[✓ PASS]${NC} $*"; ((PASS++)); }
fail()  { echo -e "  ${RED}[✗ FAIL]${NC} $*"; ((FAIL++)); }
warn()  { echo -e "  ${YELLOW}[! WARN]${NC} $*"; ((WARN++)); }
header(){ echo -e "\n${BLUE}── $* ──${NC}"; }

# Timeout for all checks
TIMEOUT=3

# TCP port check
check_port() {
    local host="$1" port="$2" name="$3"
    if nc -z -w "$TIMEOUT" "$host" "$port" 2>/dev/null; then
        pass "$name ($host:$port) — reachable"
    else
        fail "$name ($host:$port) — UNREACHABLE"
    fi
}

# HTTP check (status code)
check_http() {
    local url="$1" name="$2" expected="${3:-200}"
    local code
    code=$(curl -sk -o /dev/null -w "%{http_code}" --max-time "$TIMEOUT" "$url" 2>/dev/null)
    if [[ "$code" == "$expected" || "$code" == "200" || "$code" == "302" || "$code" == "301" ]]; then
        pass "$name → HTTP $code"
    else
        fail "$name → HTTP $code (expected 200/302)"
    fi
}

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   Threat Detection Lab — Health Check                ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════════════════╝${NC}"
echo -e "  Run at: $(date)"

# ── Detection VLAN (192.168.50.0/24) ─────────────────────────────────────────
header "Detection VLAN — 192.168.50.0/24"

# Zeek VM
check_port "192.168.50.10" 22   "Zeek VM — SSH"
# Check Zeek is running on the VM (via SSH if key auth set up)
if ssh -q -o BatchMode=yes -o ConnectTimeout=3 root@192.168.50.10 \
    "systemctl is-active zeek" 2>/dev/null | grep -q "active"; then
    pass "Zeek service — running"
else
    warn "Zeek service — cannot verify (SSH key required)"
fi

# RITA
check_port "192.168.50.10" 4380 "RITA API"
check_http "https://192.168.50.10:4380" "RITA Web"

# Arkime
check_port "192.168.50.20" 22   "Arkime VM — SSH"
check_port "192.168.50.20" 8005 "Arkime Web UI"
check_port "192.168.50.20" 9200 "Elasticsearch"
check_http "http://192.168.50.20:8005" "Arkime UI"

# Velociraptor
check_port "192.168.50.30" 22   "Velociraptor VM — SSH"
check_port "192.168.50.30" 8000 "Velociraptor Frontend (agent port)"
check_port "192.168.50.30" 8889 "Velociraptor Web UI"
check_http "https://192.168.50.30:8889" "Velociraptor UI"

# ── Intel VLAN (192.168.60.0/24) ─────────────────────────────────────────────
header "Intel VLAN — 192.168.60.0/24"

# MISP
check_port "192.168.60.10" 22  "MISP VM — SSH"
check_port "192.168.60.10" 443 "MISP HTTPS"
check_http "https://192.168.60.10" "MISP Web UI"

# TheHive
check_port "192.168.60.20" 22   "TheHive VM — SSH"
check_port "192.168.60.20" 9000 "TheHive API"
check_port "192.168.60.20" 9001 "Cortex"
check_http "http://192.168.60.20:9000" "TheHive Web UI"

# Shuffle
check_port "192.168.60.30" 22   "Shuffle VM — SSH"
check_port "192.168.60.30" 3001 "Shuffle Web UI"
check_http "http://192.168.60.30:3001" "Shuffle UI"

# ── Target VLAN (192.168.30.0/24) ────────────────────────────────────────────
header "Target VLAN — 192.168.30.0/24"

check_port "192.168.30.10" 22  "Ubuntu Target — SSH"
# Check OSQuery on target
if ssh -q -o BatchMode=yes -o ConnectTimeout=3 root@192.168.30.10 \
    "systemctl is-active osqueryd" 2>/dev/null | grep -q "active"; then
    pass "OSQuery daemon — running on Ubuntu Target"
else
    warn "OSQuery daemon — cannot verify (SSH key required)"
fi
# Check Velociraptor agent
if ssh -q -o BatchMode=yes -o ConnectTimeout=3 root@192.168.30.10 \
    "systemctl is-active velociraptor_client" 2>/dev/null | grep -q "active"; then
    pass "Velociraptor client — running on Ubuntu Target"
else
    warn "Velociraptor client — cannot verify (SSH key required)"
fi

# ── Integration checks ────────────────────────────────────────────────────────
header "Integration Processes"

for proc in "rita-to-thehive" "zeek-to-thehive" "ioc-sync"; do
    if pgrep -f "$proc" > /dev/null 2>&1; then
        pass "Integration: $proc — running"
    else
        warn "Integration: $proc — not running (start with: nohup python3 08-integrations/scripts/${proc}.py --watch &)"
    fi
done

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo -e "${BLUE}══════════════════════════════════════════════════════${NC}"
echo -e "  Results: ${GREEN}${PASS} passed${NC}  ${RED}${FAIL} failed${NC}  ${YELLOW}${WARN} warnings${NC}"
echo -e "${BLUE}══════════════════════════════════════════════════════${NC}"

if [[ $FAIL -gt 0 ]]; then
    echo -e "\n  ${RED}Lab not fully operational — fix failing services before exercises${NC}"
    exit 1
elif [[ $WARN -gt 0 ]]; then
    echo -e "\n  ${YELLOW}Lab mostly ready — review warnings above${NC}"
    exit 0
else
    echo -e "\n  ${GREEN}All services healthy — lab is ready!${NC}"
    exit 0
fi
