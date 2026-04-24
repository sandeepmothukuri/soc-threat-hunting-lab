#!/usr/bin/env python3
"""
zeek-to-thehive.py — Forward Zeek notice.log and custom detections to TheHive
==============================================================================
Monitors Zeek's notice.log and custom detection logs in real-time.
Converts Zeek notices into TheHive alerts for SOC triage.

Detections forwarded:
  - Port scans (Scan::Port_Scan)
  - DNS tunneling (long subdomain queries)
  - Suspicious user-agents (python-requests, sqlmap, nikto)
  - Internal SMB lateral movement
  - Zeek custom notices from soc-detection.zeek

Usage:
  python3 zeek-to-thehive.py --watch
  python3 zeek-to-thehive.py --file /opt/zeek/logs/current/notice.log
"""

import json
import time
import os
import re
import argparse
import logging
import requests
from datetime import datetime
from pathlib import Path
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

THEHIVE_URL  = os.getenv("THEHIVE_URL", "http://192.168.60.20:9000")
THEHIVE_KEY  = os.getenv("THEHIVE_KEY", "YOUR_THEHIVE_API_KEY")
ZEEK_LOG_DIR = os.getenv("ZEEK_LOG_DIR", "/opt/zeek/logs/current")

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    handlers=[logging.FileHandler("/var/log/zeek-to-thehive.log"), logging.StreamHandler()]
)
log = logging.getLogger(__name__)

# Map Zeek notice types to TheHive severity + tags
NOTICE_CONFIG = {
    "Scan::Port_Scan": {
        "severity": 2, "tags": ["port-scan", "recon", "T1046"],
        "description": "Port scan detected — host may be performing reconnaissance"
    },
    "SOC::DNS_Tunnel": {
        "severity": 3, "tags": ["dns-tunnel", "exfil", "T1071.004"],
        "description": "DNS tunneling detected — possible data exfiltration via DNS"
    },
    "SOC::Suspicious_UA": {
        "severity": 2, "tags": ["suspicious-ua", "tool-scan", "T1595"],
        "description": "Suspicious HTTP user-agent — possible automated attack tool"
    },
    "SOC::Lateral_Move": {
        "severity": 3, "tags": ["lateral-movement", "smb", "T1021.002"],
        "description": "SMB lateral movement detected — host connecting to multiple internal SMB services"
    },
    "Scan::Address_Scan": {
        "severity": 2, "tags": ["host-scan", "recon", "T1046"],
        "description": "Host address sweep detected"
    },
}


def parse_zeek_notice(line: str) -> dict | None:
    """Parse a single Zeek notice.log TSV line into a dict."""
    if line.startswith("#"):
        return None
    try:
        fields = line.strip().split("\t")
        if len(fields) < 10:
            return None
        # notice.log field order: ts uid id.orig_h id.orig_p id.resp_h id.resp_p proto note msg ...
        return {
            "ts":       fields[0],
            "src_ip":   fields[2] if len(fields) > 2 else "-",
            "dst_ip":   fields[4] if len(fields) > 4 else "-",
            "note":     fields[7] if len(fields) > 7 else "Unknown",
            "msg":      fields[8] if len(fields) > 8 else "",
        }
    except Exception:
        return None


def create_alert(notice: dict) -> bool:
    """Create a TheHive alert from a Zeek notice."""
    note    = notice.get("note", "Unknown")
    src_ip  = notice.get("src_ip", "-")
    dst_ip  = notice.get("dst_ip", "-")
    msg     = notice.get("msg", "")

    config = NOTICE_CONFIG.get(note, {
        "severity": 2, "tags": ["zeek-notice"],
        "description": f"Zeek notice: {note}"
    })

    alert = {
        "title": f"Zeek: {note} — {src_ip}",
        "description": (
            f"## Zeek Network Detection\n\n"
            f"**Notice Type:** `{note}`\n"
            f"**Source IP:** {src_ip}\n"
            f"**Destination:** {dst_ip}\n"
            f"**Zeek Message:** {msg}\n\n"
            f"### Description\n{config['description']}\n\n"
            f"### Investigation\n"
            f"```bash\n"
            f"# View full Zeek context\n"
            f"zeek-cut ts id.orig_h id.resp_h id.resp_p proto duration < "
            f"/opt/zeek/logs/current/conn.log | grep {src_ip}\n\n"
            f"# Check Arkime for PCAP\n"
            f"# Arkime UI: ip.src == {src_ip} AND ip.dst == {dst_ip}\n"
            f"```"
        ),
        "type": "Zeek-Network-Detection",
        "source": "Zeek-IDS",
        "sourceRef": f"zeek-{note}-{int(time.time())}",
        "severity": config["severity"],
        "status": "New",
        "tags": config["tags"],
        "observables": [
            {"dataType": "ip", "data": src_ip, "tags": ["source"]},
        ]
    }
    if dst_ip and dst_ip != "-":
        alert["observables"].append({"dataType": "ip", "data": dst_ip, "tags": ["destination"]})

    try:
        resp = requests.post(
            f"{THEHIVE_URL}/api/v1/alert",
            headers={"Authorization": f"Bearer {THEHIVE_KEY}", "Content-Type": "application/json"},
            json=alert, timeout=15
        )
        resp.raise_for_status()
        log.info(f"Alert created: {note} from {src_ip}")
        return True
    except Exception as e:
        log.error(f"TheHive alert failed: {e}")
        return False


def tail_file(filepath: str):
    """Tail a file, yielding new lines as they appear."""
    with open(filepath, "r") as f:
        f.seek(0, 2)  # Seek to end
        while True:
            line = f.readline()
            if line:
                yield line
            else:
                time.sleep(1)


def main():
    parser = argparse.ArgumentParser(description="Zeek → TheHive notice forwarder")
    parser.add_argument("--watch", action="store_true", help="Watch notice.log in real-time")
    parser.add_argument("--file",  default=f"{ZEEK_LOG_DIR}/notice.log")
    args = parser.parse_args()

    log.info(f"Watching {args.file} for Zeek notices...")
    log.info(f"Forwarding to TheHive: {THEHIVE_URL}")

    if args.watch:
        for line in tail_file(args.file):
            notice = parse_zeek_notice(line)
            if notice and notice.get("note") in NOTICE_CONFIG:
                create_alert(notice)
    else:
        with open(args.file) as f:
            count = 0
            for line in f:
                notice = parse_zeek_notice(line)
                if notice and notice.get("note") in NOTICE_CONFIG:
                    if create_alert(notice):
                        count += 1
        log.info(f"Processed file: {count} alerts sent")


if __name__ == "__main__":
    main()
