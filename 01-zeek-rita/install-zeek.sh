#!/usr/bin/env bash
# =============================================================================
# install-zeek.sh — Install Zeek Network Security Monitor + RITA
# Target: Ubuntu 22.04 LTS (192.168.50.10)
# Zeek: Passive network monitor - generates structured JSON logs
# RITA: Analyzes Zeek logs for C2 beaconing, DNS tunneling, long connections
# =============================================================================
set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }
step()  { echo -e "\n${BLUE}══ $* ══${NC}"; }

[[ $EUID -ne 0 ]] && error "Run as root: sudo $0"

# Config — set MONITOR_IFACE to the interface that sees target traffic
MONITOR_IFACE="${MONITOR_IFACE:-eth1}"
MGMT_IFACE="${MGMT_IFACE:-eth0}"
ZEEK_VERSION="6.0"

step "1/6 — System Preparation"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y curl wget gnupg2 apt-transport-https ca-certificates \
    cmake make gcc g++ flex bison libpcap-dev libssl-dev python3-dev \
    swig zlib1g-dev libmaxminddb-dev python3-pip git jq net-tools

step "2/6 — Install Zeek"
# Add Zeek repository
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' \
    > /etc/apt/sources.list.d/security:zeek.list

curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key \
    | gpg --dearmor > /etc/apt/trusted.gpg.d/security_zeek.gpg

apt-get update -qq
apt-get install -y zeek

# Add zeek to PATH
echo 'export PATH=/opt/zeek/bin:$PATH' >> /etc/environment
export PATH=/opt/zeek/bin:$PATH

step "3/6 — Configure Zeek"
# Set monitoring interface
sed -i "s/interface=eth0/interface=${MONITOR_IFACE}/" /opt/zeek/etc/node.cfg

# Configure networks Zeek should consider "local"
cat > /opt/zeek/etc/networks.cfg << 'NETWORKS'
192.168.0.0/16     Private RFC 1918
10.0.0.0/8         Private RFC 1918
172.16.0.0/12      Private RFC 1918
NETWORKS

# Copy and apply our custom detection policy
cp policies/soc-detection.zeek /opt/zeek/share/zeek/site/ 2>/dev/null || true

cat > /opt/zeek/share/zeek/site/local.zeek << 'LOCAL'
# Zeek Local Policy — SOC Threat Detection Lab
@load base/protocols/conn
@load base/protocols/dns
@load base/protocols/http
@load base/protocols/ssl
@load base/protocols/ftp
@load base/protocols/smtp
@load base/protocols/ssh
@load base/protocols/rdp
@load base/protocols/smb
@load base/files/hash
@load base/files/extract
@load policy/protocols/ssl/validate-certs
@load policy/protocols/ssl/log-hostcerts-only
@load policy/protocols/dns/detect-external-names
@load policy/frameworks/software/vulnerable
@load policy/frameworks/software/version-changes
@load policy/frameworks/notice/extend-email/hostnames
@load policy/integration/collective-intel
@load policy/frameworks/intel/seen
@load policy/frameworks/intel/do_notice

# JA3 TLS fingerprinting (detect known malware TLS)
@load policy/protocols/ssl/ja3

# Log all files transferred
@load base/files/extract

# Enable JSON output format
redef LogAscii::use_json = T;
redef LogAscii::json_timestamps = JSON::TS_ISO8601;

# Increase connection table for busy networks
redef tcp_inactivity_timeout = 5 min;
redef udp_inactivity_timeout = 1 min;

# Alert on self-signed certs
redef SSL::notify_when_no_ssl_client_cert_seen = F;

# Custom variables
redef Site::local_nets = {
    192.168.0.0/16,
    10.0.0.0/8,
    172.16.0.0/12
};
LOCAL

step "4/6 — Deploy Zeek Custom Detection Scripts"
cat > /opt/zeek/share/zeek/site/soc-detection.zeek << 'ZEEKSCRIPT'
# SOC Lab Custom Zeek Detections
# Detects: DNS tunneling, C2 patterns, data exfiltration, lateral movement

module SOCLab;

export {
    redef enum Notice::Type += {
        DNS_Tunnel_Suspected,
        Long_HTTP_Connection,
        Large_DNS_Response,
        Suspicious_User_Agent,
        Internal_Portscan,
        SMB_Lateral_Movement,
        FTP_Brute_Force,
        SSH_Lateral_Internal
    };
}

# --- DNS Tunneling Detection ---
# Detect unusually long DNS queries (encoding data in subdomains)
event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    if ( |query| > 50 && qtype == 1 )  # A record with long query
    {
        NOTICE([$note=DNS_Tunnel_Suspected,
               $conn=c,
               $msg=fmt("Long DNS query (%d chars): %s", |query|, query),
               $identifier=cat(c$id$orig_h)]);
    }
}

# Detect high-frequency DNS queries to same base domain (tunneling pattern)
global dns_query_count: table[addr, string] of count &default=0 &create_expire=1min;

event dns_request(c: connection, msg: dns_msg, query: string, qtype: count, qclass: count)
{
    local parts = split_string(query, /\./);
    if ( |parts| >= 2 )
    {
        local base_domain = fmt("%s.%s", parts[|parts|-2], parts[|parts|-1]);
        dns_query_count[c$id$orig_h, base_domain] += 1;

        if ( dns_query_count[c$id$orig_h, base_domain] > 50 )
        {
            NOTICE([$note=DNS_Tunnel_Suspected,
                   $conn=c,
                   $msg=fmt("High-frequency DNS to %s: %d queries/min from %s",
                            base_domain,
                            dns_query_count[c$id$orig_h, base_domain],
                            c$id$orig_h),
                   $identifier=cat(c$id$orig_h, base_domain)]);
        }
    }
}

# --- Suspicious User Agents (C2 frameworks) ---
global suspicious_ua_patterns = vector(
    "python-requests",
    "Go-http-client",
    "curl/",
    "Wget/",
    "libwww-perl",
    "masscan",
    "sqlmap",
    "nikto",
    "nmap"
);

event http_header(c: connection, is_orig: bool, name: string, value: string)
{
    if ( is_orig && name == "USER-AGENT" )
    {
        for ( i in suspicious_ua_patterns )
        {
            if ( suspicious_ua_patterns[i] in value )
            {
                NOTICE([$note=Suspicious_User_Agent,
                       $conn=c,
                       $msg=fmt("Suspicious user agent: %s", value),
                       $identifier=cat(c$id$orig_h, value)]);
            }
        }
    }
}

# --- Internal Port Scanning ---
global conn_count: table[addr] of count &default=0 &create_expire=1min;
global port_count: table[addr] of set[port] &create_expire=1min;

event new_connection(c: connection)
{
    if ( Site::is_local_addr(c$id$orig_h) && Site::is_local_addr(c$id$resp_h) )
    {
        conn_count[c$id$orig_h] += 1;
        if ( c$id$orig_h !in port_count )
            port_count[c$id$orig_h] = set();
        add port_count[c$id$orig_h][c$id$resp_p];

        if ( |port_count[c$id$orig_h]| > 20 )
        {
            NOTICE([$note=Internal_Portscan,
                   $src=c$id$orig_h,
                   $msg=fmt("Internal port scan from %s: %d unique ports in 1 min",
                            c$id$orig_h, |port_count[c$id$orig_h]|),
                   $identifier=cat(c$id$orig_h)]);
        }
    }
}

# --- SMB Lateral Movement Detection ---
event smb1_message(c: connection, hdr: SMB1::Header, is_orig: bool) {}

event connection_state_remove(c: connection)
{
    if ( c$id$resp_p == 445/tcp &&
         Site::is_local_addr(c$id$orig_h) &&
         Site::is_local_addr(c$id$resp_h) )
    {
        NOTICE([$note=SMB_Lateral_Movement,
               $conn=c,
               $msg=fmt("Internal SMB connection: %s -> %s",
                        c$id$orig_h, c$id$resp_h),
               $identifier=cat(c$id$orig_h, c$id$resp_h)]);
    }
}
ZEEKSCRIPT

# Add custom script to local.zeek
echo '@load soc-detection' >> /opt/zeek/share/zeek/site/local.zeek

step "5/6 — Enable Promiscuous Mode on Monitor Interface"
ip link set "$MONITOR_IFACE" promisc on

# Persist promiscuous mode
cat > /etc/systemd/system/zeek-promisc.service << SYSTEMD
[Unit]
Description=Enable promiscuous mode for Zeek monitoring
After=network.target

[Service]
Type=oneshot
ExecStart=/sbin/ip link set ${MONITOR_IFACE} promisc on
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
SYSTEMD

systemctl enable zeek-promisc

step "6/6 — Start Zeek and Configure Auto-Rotate"
/opt/zeek/bin/zeekctl deploy 2>/dev/null || /opt/zeek/bin/zeekctl start

# Hourly log rotation via cron
echo "0 * * * * /opt/zeek/bin/zeekctl rotate" | crontab -

# Create systemd service
cat > /etc/systemd/system/zeek.service << 'ZEEKSVC'
[Unit]
Description=Zeek Network Security Monitor
After=network.target

[Service]
Type=forking
ExecStart=/opt/zeek/bin/zeekctl start
ExecStop=/opt/zeek/bin/zeekctl stop
Restart=on-failure

[Install]
WantedBy=multi-user.target
ZEEKSVC

systemctl enable zeek

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Zeek Installation Complete!                         ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Logs:      /opt/zeek/logs/current/                  ║${NC}"
echo -e "${GREEN}║  Status:    /opt/zeek/bin/zeekctl status             ║${NC}"
echo -e "${GREEN}║  Monitor:   ${MONITOR_IFACE} (promiscuous mode)              ║${NC}"
echo -e "${GREEN}╠══════════════════════════════════════════════════════╣${NC}"
echo -e "${GREEN}║  Next: Run install-rita.sh to add beaconing detect   ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
