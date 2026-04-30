#!/usr/bin/env python3
"""
osquery-to-thehive.py — Forward OSQuery scheduled detection results to TheHive
===============================================================================
Runs as a systemd timer (every 60s). Reads OSQuery differential results from
/var/log/osquery/osqueryd.results.log and pushes detections as TheHive alerts.

Detections covered:
  - Reverse shells / suspicious outbound connections (proc_net_activity)
  - New SUID binaries added to filesystem
  - New cron persistence entries
  - Backdoor listening ports (unknown processes)
  - Fileless execution (memfd / anonymous mappings)

Usage:
  python3 osquery-to-thehive.py
  python3 osquery-to-thehive.py --log /var/log/osquery/osqueryd.results.log
  python3 osquery-to-thehive.py --dry-run    # Print alerts without sending
"""

import json
import os
import sys
import time
import logging
import argparse
import requests
from datetime import datetime, timezone
from pathlib import Path
from urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger(__name__)

THEHIVE_URL = os.getenv("THEHIVE_URL", "http://192.168.60.20:9000")
THEHIVE_API_KEY = os.getenv("THEHIVE_API_KEY", "your-thehive-api-key")
OSQUERY_LOG = os.getenv("OSQUERY_LOG", "/var/log/osquery/osqueryd.results.log")
STATE_FILE = "/tmp/osquery-thehive.state"

DETECTION_RULES = {
    "proc_net_activity": {
        "title": "Suspicious Outbound Connection Detected",
        "description": "OSQuery detected a process with an unusual outbound network connection. Possible reverse shell or C2 callback.",
        "severity": 3,
        "tags": ["osquery", "network", "reverse-shell", "T1059"],
        "mitre": "T1059 - Command and Script Interpreter",
    },
    "suid_new": {
        "title": "New SUID Binary Added",
        "description": "A new SUID binary was detected on the filesystem. This may indicate privilege escalation persistence.",
        "severity": 3,
        "tags": ["osquery", "privilege-escalation", "suid", "T1548"],
        "mitre": "T1548.001 - Setuid and Setgid",
    },
    "cron_new": {
        "title": "New Cron Persistence Entry",
        "description": "A new cron job was added. This may indicate persistence via scheduled task.",
        "severity": 2,
        "tags": ["osquery", "persistence", "cron", "T1053"],
        "mitre": "T1053.003 - Cron",
    },
    "listening_ports": {
        "title": "Unknown Process Listening on New Port",
        "description": "OSQuery detected a new listening port opened by an unrecognised process. Possible backdoor.",
        "severity": 3,
        "tags": ["osquery", "backdoor", "network", "T1543"],
        "mitre": "T1543 - Create or Modify System Process",
    },
    "process_open_files": {
        "title": "Possible Fileless Execution (memfd)",
        "description": "A process has anonymous or memfd-based file mappings — potential fileless malware execution.",
        "severity": 3,
        "tags": ["osquery", "fileless", "evasion", "T1620"],
        "mitre": "T1620 - Reflective Code Loading",
    },
}


def read_state():
    try:
        return int(Path(STATE_FILE).read_text().strip())
    except Exception:
        return 0


def write_state(pos):
    Path(STATE_FILE).write_text(str(pos))


def parse_log_line(line):
    try:
        return json.loads(line.strip())
    except json.JSONDecodeError:
        return None


def build_alert(rule_name, rule, row, hostname):
    now = datetime.now(timezone.utc).isoformat()
    description = (
        f"**Detection:** {rule['title']}\n\n"
        f"**Host:** `{hostname}`\n"
        f"**MITRE:** {rule['mitre']}\n"
        f"**Time:** {now}\n\n"
        f"**OSQuery Result:**\n```json\n{json.dumps(row, indent=2)}\n```\n\n"
        f"{rule['description']}"
    )
    return {
        "title": f"[OSQuery] {rule['title']} on {hostname}",
        "description": description,
        "type": "osquery-detection",
        "source": "osquery-to-thehive",
        "sourceRef": f"osq-{rule_name}-{int(time.time())}",
        "severity": rule["severity"],
        "date": int(time.time() * 1000),
        "tags": rule["tags"] + [f"host:{hostname}"],
        "tlp": 2,
    }


def send_alert(alert, dry_run=False):
    if dry_run:
        logger.info(f"[DRY RUN] Would send: {alert['title']}")
        return True
    try:
        resp = requests.post(
            f"{THEHIVE_URL}/api/v1/alert",
            json=alert,
            headers={
                "Authorization": f"Bearer {THEHIVE_API_KEY}",
                "Content-Type": "application/json",
            },
            verify=False,
            timeout=10,
        )
        if resp.status_code in (200, 201):
            logger.info(f"Alert sent: {alert['title']} (id={resp.json().get('_id')})")
            return True
        else:
            logger.error(f"TheHive returned {resp.status_code}: {resp.text[:200]}")
            return False
    except requests.RequestException as e:
        logger.error(f"Failed to reach TheHive: {e}")
        return False


def process_log(log_path, dry_run=False):
    path = Path(log_path)
    if not path.exists():
        logger.warning(f"Log file not found: {log_path}")
        return

    offset = read_state()
    sent = 0

    with open(path, "r") as f:
        f.seek(offset)
        for line in f:
            entry = parse_log_line(line)
            if not entry or entry.get("action") != "added":
                continue

            query_name = entry.get("name", "")
            rows = entry.get("columns", entry.get("diffResults", {}).get("added", []))
            if isinstance(rows, dict):
                rows = [rows]

            hostname = entry.get("hostIdentifier", "unknown")

            for rule_name, rule in DETECTION_RULES.items():
                if rule_name in query_name:
                    for row in rows:
                        alert = build_alert(rule_name, rule, row, hostname)
                        if send_alert(alert, dry_run):
                            sent += 1

        write_state(f.tell())

    if sent:
        logger.info(f"Forwarded {sent} detection(s) to TheHive")


def main():
    parser = argparse.ArgumentParser(description="OSQuery → TheHive forwarder")
    parser.add_argument("--log", default=OSQUERY_LOG, help="OSQuery results log path")
    parser.add_argument("--dry-run", action="store_true", help="Print without sending")
    parser.add_argument("--watch", action="store_true", help="Run in loop every 60s")
    args = parser.parse_args()

    if args.watch:
        logger.info("Starting OSQuery → TheHive watcher (60s interval)")
        while True:
            process_log(args.log, args.dry_run)
            time.sleep(60)
    else:
        process_log(args.log, args.dry_run)


if __name__ == "__main__":
    main()
