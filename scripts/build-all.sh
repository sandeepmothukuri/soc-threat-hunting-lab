#!/usr/bin/env bash
# =============================================================================
# build-all.sh — Master Orchestration Script for SOC Threat Hunting Lab
# Purpose: Build, provision, and verify the complete 8-VM lab environment.
#
# Usage:
#   ./scripts/build-all.sh --vagrant          # Build all 8 VMs via Vagrant (Recommended)
#   ./scripts/build-all.sh --profile network   # Build only Network Sensors (Zeek, Arkime, Target)
#   ./scripts/build-all.sh --profile endpoint  # Build only Endpoint DFIR (Velociraptor, Target)
#   ./scripts/build-all.sh --profile intel     # Build only Threat Intel & SOAR (MISP, TheHive, Shuffle)
#   ./scripts/build-all.sh --check            # Run health checks on all lab services
# =============================================================================
set -euo pipefail

GREEN='\033[0;32m'; BLUE='\033[0;34m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
step()  { echo -e "\n${BLUE}══════════════════════════════════════════════════════${NC}\n${BLUE}  $*${NC}\n${BLUE}══════════════════════════════════════════════════════${NC}"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_DIR"

MODE="${1:---vagrant}"

case "$MODE" in
    --vagrant)
        step "Building Complete Lab with Vagrant (All 8 VMs)"
        if ! command -v vagrant &>/dev/null; then
            error "Vagrant is not installed. Install Vagrant from https://www.vagrantup.com/downloads or use manual VM build guide in docs/vm-build-guide.md"
        fi

        info "Starting Vagrant multi-machine provisioning..."
        vagrant up

        step "Running Post-Build Health Verification"
        ./scripts/health-check.sh
        ;;

    --profile)
        PROFILE="${2:-network}"
        step "Building Functional Lab Profile: $PROFILE"
        case "$PROFILE" in
            network)
                info "Starting Network Sensor Profile (zeek-rita, arkime, ubuntu-target, kali)..."
                vagrant up zeek-rita arkime ubuntu-target kali
                ;;
            endpoint)
                info "Starting Endpoint DFIR Profile (velociraptor, ubuntu-target, kali)..."
                vagrant up velociraptor ubuntu-target kali
                ;;
            intel)
                info "Starting Intel & SOAR Profile (misp, thehive, shuffle)..."
                vagrant up misp thehive shuffle
                ;;
            *)
                error "Unknown profile: $PROFILE. Options: network, endpoint, intel"
                ;;
        esac
        ;;

    --check)
        step "Running Lab Health Verification"
        ./scripts/health-check.sh
        ;;

    --help|-h)
        echo "Usage: $0 [--vagrant | --profile <network|endpoint|intel> | --check]"
        exit 0
        ;;

    *)
        error "Unknown argument: $MODE. Use --help for usage."
        ;;
esac

echo ""
info "Master build orchestration completed successfully!"
