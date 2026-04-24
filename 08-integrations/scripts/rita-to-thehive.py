#!/usr/bin/env python3
"""
rita-to-thehive.py — Forward RITA beaconing detections to TheHive
=================================================================
RITA detects C2 beaconing in Zeek logs. This script reads RITA's output
and creates TheHive alerts for high-confidence beacons.

Usage:
  python3 rita-to-thehive.py --once        # Single run
  python3 rita-to-thehive.py --watch       # Watch every 5 min
  python3 rita-to-thehive.py --threshold 0.8  # Custom beacon score threshold
"""

import subprocess
import json
import requests
import argparse
import logging
import time
import os
from datetime import datetime
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

THEHIVE_URL = os.getenv("THEHIVE_URL", "http://192.168.60.20:9000")
THEHIVE_KEY = os.getenv("THEHIVE_KEY", "YOUR_THEHIVE_API_KEY")
RITA_DB     = os.getenv("RITA_DB", "soc-hunt")
THRESHOLD   = float(os.getenv("BEACON_THRESHOLD", "0.7"))

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.INFO,
    handlers=[
        logging.FileHandler("/var/log/rita-to-thehive.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)


def get_rita_beacons(db: str, threshold: float) -> list:
    """Run rita show-beacons and parse output."""
    try:
        result = subprocess.run(
            ["rita", "show-beacons", db, "--no-color"],
            capture_output=True, text=True, timeout=60
        )
        beacons = []
        for line in result.stdout.splitlines():
            # RITA output: Score | Source | Destination | Connections | Avg Delta
            parts = line.split()
            if len(parts) >= 5:
                try:
                    score = float(parts[0])
                    if score >= threshold:
                        beacons.append({
                            "score":       score,
                            "source_ip":   parts[1],
                            "dest_ip":     parts[2],
                            "connections": int(parts[3]),
                            "avg_delta":   parts[4]
                        })
                except (ValueError, IndexError):
                    continue
        log.info(f"RITA: found {len(beacons)} beacons above threshold {threshold}")
        return beacons
    except FileNotFoundError:
        log.error("rita not found — is it installed? sudo ./01-zeek-rita/install-rita.sh")
        return []
    except subprocess.TimeoutExpired:
        log.error("rita show-beacons timed out")
        return []


def create_thehive_alert(beacon: dict) -> bool:
    """Create a TheHive alert from a beacon detection."""
    score     = beacon["score"]
    source    = beacon["source_ip"]
    dest      = beacon["dest_ip"]
    conns     = beacon["connections"]
    delta     = beacon["avg_delta"]

    # Severity: 0.7-0.8=Medium, 0.8-0.9=High, 0.9+=Critical
    severity = 2
    if score >= 0.9:
        severity = 4  # Critical
    elif score >= 0.8:
        severity = 3  # High

    alert = {
        "title": f"C2 Beaconing: {source} → {dest} (score: {score:.2f})",
        "description": (
            f"## RITA Beaconing Detection\n\n"
            f"**Beacon Score:** {score:.2f} (1.0 = perfect beacon)\n"
            f"**Source Host:** {source}\n"
            f"**C2 Destination:** {dest}\n"
            f"**Total Connections:** {conns}\n"
            f"**Avg Interval:** {delta} seconds\n\n"
            f"### What This Means\n"
            f"The host `{source}` is making regular, rhythmic connections to `{dest}` "
            f"every ~{delta}s — a strong indicator of malware C2 callback (beaconing).\n\n"
            f"### Next Steps\n"
            f"1. Check Arkime: `ip.src == {source} AND ip.dst == {dest}`\n"
            f"2. Velociraptor: hunt processes on {source} with outbound connections\n"
            f"3. MISP: check if {dest} is a known C2 server\n"
            f"4. Consider isolating {source} if confirmed malicious\n\n"
            f"*Detected by RITA statistical analysis on Zeek conn.log*"
        ),
        "type": "Network-C2-Beaconing",
        "source": "RITA-Zeek",
        "sourceRef": f"rita-{source.replace('.','_')}-{int(time.time())}",
        "severity": severity,
        "status": "New",
        "tags": ["beaconing", "c2", "rita", "network", f"score:{score:.1f}"],
        "observables": [
            {"dataType": "ip", "data": source, "tags": ["source", "victim"]},
            {"dataType": "ip", "data": dest,   "tags": ["destination", "c2-suspect"]}
        ],
        "follow": True
    }

    try:
        resp = requests.post(
            f"{THEHIVE_URL}/api/v1/alert",
            headers={"Authorization": f"Bearer {THEHIVE_KEY}", "Content-Type": "application/json"},
            json=alert,
            timeout=15
        )
        resp.raise_for_status()
        result = resp.json()
        log.info(f"TheHive alert #{result.get('number')} created: {source} → {dest} ({score:.2f})")
        return True
    except requests.RequestException as e:
        log.error(f"TheHive request failed: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(description="RITA → TheHive beacon forwarder")
    parser.add_argument("--once",      action="store_true", help="Run once and exit")
    parser.add_argument("--watch",     action="store_true", help="Continuous mode")
    parser.add_argument("--threshold", type=float, default=THRESHOLD)
    parser.add_argument("--db",        default=RITA_DB, help="RITA database name")
    parser.add_argument("--interval",  type=int, default=300, help="Watch interval seconds")
    args = parser.parse_args()

    def run_once():
        beacons = get_rita_beacons(args.db, args.threshold)
        for beacon in beacons:
            create_thehive_alert(beacon)
        return len(beacons)

    if args.watch:
        log.info(f"Watch mode: checking RITA every {args.interval}s, threshold={args.threshold}")
        while True:
            count = run_once()
            log.info(f"Sent {count} alerts to TheHive. Next check in {args.interval}s")
            time.sleep(args.interval)
    else:
        count = run_once()
        log.info(f"Done: {count} beacon alerts sent to TheHive")


if __name__ == "__main__":
    main()
