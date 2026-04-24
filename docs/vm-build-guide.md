# 🖥️ VM Build Guide — Step-by-Step

> **Before you start:** Run `scripts/setup-host.sh` on your host to create the VirtualBox networks.

---

## VM Specifications

| # | VM Name | OS | IP | vCPU | RAM | Disk | Role |
|---|---------|----|----|------|-----|------|------|
| 1 | zeek-rita | Ubuntu 22.04 | 192.168.50.10 | 2 | 4GB | 40GB | Network Monitor |
| 2 | arkime | Ubuntu 22.04 | 192.168.50.20 | 4 | 8GB | 100GB | Packet Capture |
| 3 | velociraptor | Ubuntu 22.04 | 192.168.50.30 | 2 | 4GB | 40GB | EDR Server |
| 4 | misp | Ubuntu 22.04 | 192.168.60.10 | 4 | 8GB | 50GB | Threat Intel |
| 5 | thehive | Ubuntu 22.04 | 192.168.60.20 | 4 | 8GB | 50GB | Case Mgmt |
| 6 | shuffle | Ubuntu 22.04 | 192.168.60.30 | 2 | 4GB | 40GB | SOAR |
| 7 | ubuntu-target | Ubuntu 22.04 | 192.168.30.10 | 2 | 2GB | 30GB | Target |
| 8 | kali | Kali Linux | 192.168.20.10 | 2 | 4GB | 40GB | Attacker |

**Total:** ~34GB RAM, ~390GB disk (minimum to run all VMs)

---

## Step 1 — Download ISOs

```bash
# Ubuntu 22.04 LTS (used for 7 VMs — download once)
wget https://releases.ubuntu.com/22.04/ubuntu-22.04.3-live-server-amd64.iso -P ~/Downloads/

# Kali Linux (attacker VM)
wget https://cdimage.kali.org/kali-2024.1/kali-linux-2024.1-installer-amd64.iso -P ~/Downloads/
```

---

## Step 2 — Create VMs in VirtualBox

### Template: Create One VM Then Clone

```
1. VirtualBox → New
   Name: ubuntu-base
   Type: Linux / Ubuntu (64-bit)
   RAM: 2048 MB (we'll adjust per VM)
   Disk: 30 GB (VDI, Dynamically allocated)

2. Settings → Network:
   Adapter 1: Host-Only (vboxnet1 — management)
   Adapter 2: Host-Only (assign per role — see table below)

3. Settings → System → Processor:
   CPU: 2 (adjust per VM)
   Enable PAE/NX ✓
   Enable VT-x/AMD-V ✓

4. Settings → Display:
   Video Memory: 16 MB
   Acceleration: Disabled (server VM)

5. Install Ubuntu Server 22.04:
   Language: English
   Keyboard: Your layout
   Network: Configure eth0 (management IP — see table)
   Storage: Use entire disk (guided)
   Profile: name=labuser, server=hostname, username=labuser
   SSH: Install OpenSSH server ✓ (IMPORTANT)
   Packages: nothing extra — install tools via scripts
```

### Network Adapter Assignments

| VM | Adapter 1 (eth0) | Adapter 2 (eth1) | Notes |
|----|-----------------|-----------------|-------|
| zeek-rita | vboxnet2 (50.x) | vboxnet1 (30.x) | eth1 = promiscuous capture |
| arkime | vboxnet2 (50.x) | vboxnet1 (30.x) | eth1 = promiscuous capture |
| velociraptor | vboxnet2 (50.x) | — | Agents connect to eth0 |
| misp | vboxnet3 (60.x) | NAT (internet) | NAT for feed downloads |
| thehive | vboxnet3 (60.x) | — | |
| shuffle | vboxnet3 (60.x) | — | Docker bridge |
| ubuntu-target | vboxnet1 (30.x) | — | Install agents here |
| kali | vboxnet0 (20.x) | — | Attack from here |

---

## Step 3 — Static IP Setup (netplan)

After Ubuntu install, set static IPs. Repeat for each VM with the correct IP:

```bash
# SSH into each VM: ssh labuser@192.168.X.X

# Edit netplan config
sudo nano /etc/netplan/00-installer-config.yaml
```

**Example for Zeek VM (192.168.50.10):**

```yaml
network:
  version: 2
  renderer: networkd
  ethernets:
    eth0:
      dhcp4: false
      addresses: [192.168.50.10/24]
      nameservers:
        addresses: [8.8.8.8, 1.1.1.1]
    eth1:
      dhcp4: false
      # No IP on capture interface — promiscuous mode only
```

```bash
sudo netplan apply
# Verify
ip addr show
ping -c 2 192.168.50.1  # Should reach host gateway
```

---

## Step 4 — Enable Promiscuous Mode (Zeek + Arkime)

The capture VMs need to see ALL traffic on the target VLAN:

```bash
# On your host (not inside VM):
# VirtualBox → zeek-rita Settings → Network → Adapter 2
# Promiscuous Mode: Allow All

# Also set via VBoxManage:
VBoxManage modifyvm "zeek-rita" --nicpromisc2 allow-all
VBoxManage modifyvm "arkime" --nicpromisc2 allow-all

# Inside Zeek VM — confirm eth1 sees traffic
sudo ip link set eth1 promisc on
sudo tcpdump -i eth1 -c 10 -nn
# Should see traffic from other VMs in the target VLAN
```

---

## Step 5 — Install Tools

With VMs running and networked, install tools via the lab scripts.

**Run on each VM (SSH in first):**

```bash
# Clone the repo onto each VM
git clone https://github.com/sandeepmothukuri/soc-threat-hunting-lab.git
cd soc-threat-hunting-lab

# Zeek VM:
sudo ./01-zeek-rita/install-zeek.sh
sudo ./01-zeek-rita/install-rita.sh

# Arkime VM:
sudo ./02-arkime/install-arkime.sh

# Velociraptor Server VM:
sudo SERVER_IP=192.168.50.30 ./03-velociraptor/install-velociraptor.sh

# Ubuntu Target (install agents):
sudo ./04-osquery/install-osquery.sh

# MISP VM:
sudo MISP_IP=192.168.60.10 ./05-misp/install-misp.sh

# TheHive VM:
sudo HIVE_IP=192.168.60.20 ./06-thehive/install-thehive.sh

# Shuffle VM:
sudo SHUFFLE_IP=192.168.60.30 ./07-shuffle/install-shuffle.sh
```

---

## Step 6 — Verify Everything Works

```bash
# From your host machine:
./scripts/health-check.sh

# Expected output:
# [✓ PASS] Zeek VM — SSH (192.168.50.10:22)
# [✓ PASS] Arkime Web UI (192.168.50.20:8005)
# [✓ PASS] Velociraptor Web UI (192.168.50.30:8889)
# [✓ PASS] MISP Web UI (192.168.60.10:443)
# [✓ PASS] TheHive Web UI (192.168.60.20:9000)
# [✓ PASS] Shuffle UI (192.168.60.30:3001)
# Results: 20 passed  0 failed  0 warnings
```

---

## Quick Troubleshooting

| Problem | Fix |
|---------|-----|
| VM can't reach host-only network | Check VirtualBox network adapter settings |
| Zeek not seeing target traffic | Enable promiscuous mode on eth1 |
| MISP can't reach internet for feeds | Add NAT adapter to MISP VM |
| TheHive won't start | Check Cassandra: `systemctl status cassandra` |
| Shuffle containers failing | Check Docker: `docker compose -f /opt/shuffle/docker-compose.yml logs` |
| OSQuery not logging | Check: `systemctl status osqueryd` and check `/var/log/osquery/` |

---

## VM Snapshots (Save Your Progress)

Take a snapshot after each successful tool install:

```bash
# VirtualBox → Machine → Take Snapshot
# Name each snapshot clearly:
# "zeek-installed-clean"
# "arkime-installed-clean"
# etc.

# Via CLI:
VBoxManage snapshot zeek-rita take "zeek-installed-clean" --description "Zeek + RITA installed, tests passing"
```
