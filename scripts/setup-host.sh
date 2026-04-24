#!/usr/bin/env bash
# =============================================================================
# setup-host.sh — Prepare Host Machine for Threat Detection Lab
# Run on: Your laptop/workstation (NOT inside a VM)
# Purpose: Install VirtualBox, create host-only networks, check prerequisites
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[✓]${NC} $*"; }
step()  { echo -e "\n${BLUE}══ $* ══${NC}"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
error() { echo -e "${RED}[✗]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }

step "System Requirements Check"
# RAM
TOTAL_RAM_GB=$(free -g | awk '/^Mem:/{print $2}')
if [[ $TOTAL_RAM_GB -lt 16 ]]; then
    warn "RAM: ${TOTAL_RAM_GB}GB detected — 16GB minimum, 32GB recommended"
    warn "Running all 8 VMs simultaneously requires ~24GB RAM"
else
    ok "RAM: ${TOTAL_RAM_GB}GB ✓"
fi

# Disk
FREE_DISK_GB=$(df -BG / | awk 'NR==2{print $4}' | tr -d 'G')
if [[ $FREE_DISK_GB -lt 150 ]]; then
    warn "Free disk: ${FREE_DISK_GB}GB — 150GB+ recommended for PCAP storage"
else
    ok "Disk: ${FREE_DISK_GB}GB free ✓"
fi

# CPU cores
CPU_CORES=$(nproc)
ok "CPU: ${CPU_CORES} cores"

# Virtualization support
if grep -q "vmx\|svm" /proc/cpuinfo; then
    ok "Hardware virtualization (VT-x/AMD-V): Enabled ✓"
else
    error "Hardware virtualization not detected — enable in BIOS/UEFI"
fi

step "Install VirtualBox 7.x"
if command -v vboxmanage &>/dev/null; then
    ok "VirtualBox already installed: $(vboxmanage --version)"
else
    # Ubuntu/Debian
    if command -v apt-get &>/dev/null; then
        wget -qO- https://www.virtualbox.org/download/oracle_vbox_2016.asc | \
            gpg --dearmor -o /usr/share/keyrings/oracle-virtualbox.gpg
        echo "deb [arch=amd64 signed-by=/usr/share/keyrings/oracle-virtualbox.gpg] \
            https://download.virtualbox.org/virtualbox/debian $(lsb_release -cs) contrib" \
            > /etc/apt/sources.list.d/virtualbox.list
        apt-get update -qq && apt-get install -y virtualbox-7.0
    # macOS
    elif command -v brew &>/dev/null; then
        brew install --cask virtualbox
    else
        error "Please install VirtualBox 7.x manually: https://www.virtualbox.org/wiki/Downloads"
    fi
    ok "VirtualBox installed"
fi

step "Install Python Dependencies"
pip3 install \
    requests \
    pymisp \
    thehive4py \
    python-dateutil \
    urllib3 \
    colorama \
    --break-system-packages --quiet

ok "Python packages installed"

step "Create VirtualBox Host-Only Networks"

# Helper: create network if it doesn't exist
create_hostonly() {
    local name="$1" ip="$2" mask="$3"
    if vboxmanage list hostonlyifs | grep -q "^Name:.*${name}$"; then
        ok "${name} already exists"
    else
        vboxmanage hostonlyif create
        # Get the name of the newly created interface
        NEW_IF=$(vboxmanage list hostonlyifs | grep "^Name:" | tail -1 | awk '{print $2}')
        vboxmanage hostonlyif ipconfig "$NEW_IF" --ip "$ip" --netmask "$mask"
        ok "Created ${NEW_IF}: ${ip}/24"
    fi
}

# Attacker VLAN (Kali)
create_hostonly "vboxnet0" "192.168.20.1"  "255.255.255.0"

# Target VLAN (Ubuntu/Windows targets)
create_hostonly "vboxnet1" "192.168.30.1"  "255.255.255.0"

# Detection VLAN (Zeek, Arkime, Velociraptor)
create_hostonly "vboxnet2" "192.168.50.1"  "255.255.255.0"

# Intel VLAN (MISP, TheHive, Shuffle)
create_hostonly "vboxnet3" "192.168.60.1"  "255.255.255.0"

step "Network Summary"
echo ""
echo "  VLAN            Network           Host Gateway    Purpose"
echo "  ──────────────  ────────────────  ──────────────  ───────────────────────"
echo "  Attacker        192.168.20.0/24   192.168.20.1    Kali Linux"
echo "  Target          192.168.30.0/24   192.168.30.1    Ubuntu + Windows targets"
echo "  Detection       192.168.50.0/24   192.168.50.1    Zeek, Arkime, Velociraptor"
echo "  Intel           192.168.60.0/24   192.168.60.1    MISP, TheHive, Shuffle"
echo ""

step "VM Build Order"
echo ""
echo "  Build your VMs in this order (one at a time to save RAM during setup):"
echo ""
echo "  1. Ubuntu 22.04 → Zeek/RITA VM    (192.168.50.10)  2 vCPU, 4GB RAM"
echo "  2. Ubuntu 22.04 → Arkime VM       (192.168.50.20)  4 vCPU, 8GB RAM"
echo "  3. Ubuntu 22.04 → Velociraptor    (192.168.50.30)  2 vCPU, 4GB RAM"
echo "  4. Ubuntu 22.04 → MISP            (192.168.60.10)  4 vCPU, 8GB RAM"
echo "  5. Ubuntu 22.04 → TheHive         (192.168.60.20)  4 vCPU, 8GB RAM"
echo "  6. Ubuntu 22.04 → Shuffle         (192.168.60.30)  2 vCPU, 4GB RAM"
echo "  7. Ubuntu 22.04 → Ubuntu Target   (192.168.30.10)  2 vCPU, 2GB RAM"
echo "  8. Kali Linux   → Attacker        (192.168.20.10)  2 vCPU, 4GB RAM"
echo ""
echo "  See docs/vm-build-guide.md for step-by-step instructions."
echo ""

info "Host setup complete!"
info "Next: Follow docs/vm-build-guide.md to create your VMs"
