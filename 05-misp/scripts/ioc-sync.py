#!/usr/bin/env python3
"""
ioc-sync.py — Sync IOCs from MISP to Wazuh/OSQuery/TheHive
=============================================================
Pulls threat intelligence from MISP and pushes to:
  - Wazuh: via custom rules (IP/domain blocklists)
  - OSQuery: via packs (suspicious IP monitoring)
  - TheHive: auto-create cases for high-confidence IOCs

Usage:
  python3 ioc-sync.py --mode sync         # Full sync
  python3 ioc-sync.py --mode export-ips   # Export malicious IPs
  python3 ioc-sync.py --mode export-domains  # Export malicious domains
  python3 ioc-sync.py --mode thehive      # Push high-severity IOCs to TheHive
  python3 ioc-sync.py --mode watch        # Continuous sync every 30 min
"""

import requests
import json
import sys
import time
import argparse
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

# ─── Config ─────────────────────────────────────────────────────────────────
MISP_URL    = os.getenv("MISP_URL",    "https://192.168.60.10")
MISP_KEY    = os.getenv("MISP_KEY",    "YOUR_MISP_API_KEY_HERE")
THEHIVE_URL = os.getenv("THEHIVE_URL", "http://192.168.60.20:9000")
THEHIVE_KEY = os.getenv("THEHIVE_KEY", "YOUR_THEHIVE_API_KEY_HERE")
WAZUH_ACTIVE_RESPONSE_DIR = "/var/ossec/active-response/bin/"
OUTPUT_DIR  = Path("/etc/soc-lab/ioc-lists")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("/var/log/ioc-sync.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)


class MISPClient:
    def __init__(self, url: str, key: str):
        self.url = url.rstrip("/")
        self.headers = {
            "Authorization": key,
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

    def get_attributes(self, attr_type: str, threat_level: int = 2,
                       published: bool = True, limit: int = 10000) -> list:
        """Fetch attributes by type from published events."""
        payload = {
            "returnFormat": "json",
            "type": attr_type,
            "to_ids": 1,
            "published": published,
            "threat_level_id": threat_level,
            "limit": limit
        }
        try:
            resp = requests.post(
                f"{self.url}/attributes/restSearch",
                headers=self.headers,
                json=payload,
                verify=False,
                timeout=30
            )
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", {}).get("Attribute", [])
        except Exception as e:
            log.error(f"MISP query failed for type={attr_type}: {e}")
            return []

    def get_events(self, threat_level: int = 1, last: str = "1d") -> list:
        """Get recent high-severity events."""
        payload = {
            "returnFormat": "json",
            "threat_level_id": threat_level,
            "last": last,
            "published": True,
            "limit": 100
        }
        try:
            resp = requests.post(
                f"{self.url}/events/restSearch",
                headers=self.headers,
                json=payload,
                verify=False,
                timeout=30
            )
            resp.raise_for_status()
            return resp.json().get("response", [])
        except Exception as e:
            log.error(f"MISP events query failed: {e}")
            return []


class TheHiveClient:
    def __init__(self, url: str, key: str):
        self.url = url.rstrip("/")
        self.headers = {
            "Authorization": f"Bearer {key}",
            "Content-Type": "application/json"
        }

    def create_alert(self, title: str, description: str, severity: int,
                     tags: list, observables: list) -> dict:
        """Create an alert in TheHive from MISP IOCs."""
        alert = {
            "title": title,
            "description": description,
            "type": "MISP-IOC",
            "source": "MISP-Auto-Sync",
            "sourceRef": f"MISP-{int(time.time())}",
            "severity": severity,  # 1=Low, 2=Medium, 3=High, 4=Critical
            "status": "New",
            "tags": tags,
            "observables": observables,
            "follow": True
        }
        try:
            resp = requests.post(
                f"{self.url}/api/v1/alert",
                headers=self.headers,
                json=alert,
                timeout=15
            )
            resp.raise_for_status()
            result = resp.json()
            log.info(f"TheHive alert created: #{result.get('number')} - {title}")
            return result
        except Exception as e:
            log.error(f"TheHive alert creation failed: {e}")
            return {}


def export_ip_list(misp: MISPClient) -> list:
    """Export all malicious IPs from MISP."""
    ips = set()
    for attr_type in ["ip-dst", "ip-src", "ip-dst|port"]:
        attrs = misp.get_attributes(attr_type, threat_level=2)
        for attr in attrs:
            value = attr.get("value", "").split("|")[0]
            if value:
                ips.add(value)
    log.info(f"Collected {len(ips)} malicious IPs from MISP")
    return list(ips)


def export_domain_list(misp: MISPClient) -> list:
    """Export all malicious domains from MISP."""
    domains = set()
    for attr_type in ["domain", "hostname", "domain|ip"]:
        attrs = misp.get_attributes(attr_type, threat_level=2)
        for attr in attrs:
            value = attr.get("value", "").split("|")[0]
            if value:
                domains.add(value)
    log.info(f"Collected {len(domains)} malicious domains from MISP")
    return list(domains)


def export_hash_list(misp: MISPClient) -> list:
    """Export all malicious file hashes from MISP."""
    hashes = set()
    for attr_type in ["md5", "sha1", "sha256", "sha512"]:
        attrs = misp.get_attributes(attr_type, threat_level=2)
        for attr in attrs:
            value = attr.get("value", "")
            hash_type = attr_type.upper()
            if value:
                hashes.add(f"{hash_type}:{value}")
    log.info(f"Collected {len(hashes)} malicious hashes from MISP")
    return list(hashes)


def write_osquery_pack(ips: list, domains: list) -> None:
    """Generate OSQuery pack with MISP IOCs."""
    ip_list = ",".join([f'"{ip}"' for ip in ips[:500]])  # OSQuery limit
    domain_list = ",".join([f'"{d}"' for d in domains[:200]])

    pack = {
        "queries": {
            "misp_c2_connections": {
                "query": f"""SELECT p.name, p.pid, p.cmdline, n.remote_address, n.remote_port, n.state
                FROM process_open_sockets n JOIN processes p ON n.pid = p.pid
                WHERE n.remote_address IN ({ip_list}) AND n.state = 'ESTABLISHED';""",
                "interval": 60,
                "description": f"MISP IOC: connections to known C2 IPs (updated {datetime.now().strftime('%Y-%m-%d')})"
            }
        }
    }

    output_path = Path("/etc/osquery/packs/misp-iocs.conf")
    output_path.write_text(json.dumps(pack, indent=2))
    log.info(f"OSQuery MISP pack written: {output_path}")


def write_wazuh_cdb(ips: list, domains: list) -> None:
    """Write Wazuh CDB lists for IP/domain blocking."""
    ip_path = Path("/var/ossec/etc/lists/misp-malicious-ips")
    dom_path = Path("/var/ossec/etc/lists/misp-malicious-domains")

    ip_path.parent.mkdir(parents=True, exist_ok=True)

    with open(ip_path, "w") as f:
        for ip in sorted(set(ips)):
            f.write(f"{ip}:malicious-ip\n")

    with open(dom_path, "w") as f:
        for domain in sorted(set(domains)):
            f.write(f"{domain}:malicious-domain\n")

    log.info(f"Wazuh CDB lists updated: {len(ips)} IPs, {len(domains)} domains")


def push_to_thehive(misp: MISPClient, hive: TheHiveClient) -> None:
    """Push high-severity MISP events to TheHive as alerts."""
    events = misp.get_events(threat_level=1, last="24h")  # High + Critical
    log.info(f"Found {len(events)} high-severity MISP events in last 24h")

    for event_data in events[:20]:  # Limit to 20 per run
        event = event_data.get("Event", {})
        title    = event.get("info", "Unknown MISP Event")
        org      = event.get("Orgc", {}).get("name", "Unknown")
        attrs    = event.get("Attribute", [])
        tags     = [t.get("name", "") for t in event.get("Tag", [])]
        threat   = int(event.get("threat_level_id", 3))

        # Map MISP threat level → TheHive severity
        severity_map = {1: 4, 2: 3, 3: 2, 4: 1}
        severity = severity_map.get(threat, 2)

        # Build observables from attributes
        type_map = {
            "ip-dst": "ip", "ip-src": "ip",
            "domain": "domain", "hostname": "domain",
            "md5": "hash", "sha256": "hash", "sha1": "hash",
            "url": "url", "email-src": "mail"
        }
        observables = []
        for attr in attrs[:30]:
            obs_type = type_map.get(attr.get("type", ""), None)
            if obs_type:
                observables.append({
                    "dataType": obs_type,
                    "data": attr.get("value", ""),
                    "tags": [f"misp:{attr.get('type')}"],
                    "message": attr.get("comment", "")
                })

        description = (
            f"**MISP Event:** {title}\n\n"
            f"**Organization:** {org}\n"
            f"**Published:** {event.get('date', 'Unknown')}\n"
            f"**Threat Level:** {threat}\n\n"
            f"**Attributes:** {len(attrs)} IOCs\n\n"
            f"*Auto-imported by ioc-sync.py*"
        )

        hive.create_alert(
            title=f"[MISP] {title}",
            description=description,
            severity=severity,
            tags=tags + ["source:misp", "auto-import"],
            observables=observables
        )


def full_sync(misp: MISPClient, hive: TheHiveClient) -> None:
    """Run complete IOC synchronization."""
    log.info("Starting full MISP IOC sync...")

    ips     = export_ip_list(misp)
    domains = export_domain_list(misp)
    hashes  = export_hash_list(misp)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUTPUT_DIR / "malicious-ips.txt").write_text("\n".join(sorted(ips)))
    (OUTPUT_DIR / "malicious-domains.txt").write_text("\n".join(sorted(domains)))
    (OUTPUT_DIR / "malicious-hashes.txt").write_text("\n".join(sorted(hashes)))

    write_osquery_pack(ips, domains)
    write_wazuh_cdb(ips, domains)
    push_to_thehive(misp, hive)

    log.info(f"Sync complete — IPs: {len(ips)}, Domains: {len(domains)}, Hashes: {len(hashes)}")


def main():
    parser = argparse.ArgumentParser(description="MISP IOC Sync Tool")
    parser.add_argument("--mode", choices=["sync","export-ips","export-domains","thehive","watch"],
                        default="sync")
    parser.add_argument("--interval", type=int, default=1800, help="Watch interval in seconds")
    args = parser.parse_args()

    misp = MISPClient(MISP_URL, MISP_KEY)
    hive = TheHiveClient(THEHIVE_URL, THEHIVE_KEY)

    if args.mode == "sync":
        full_sync(misp, hive)
    elif args.mode == "export-ips":
        ips = export_ip_list(misp)
        print("\n".join(ips))
    elif args.mode == "export-domains":
        domains = export_domain_list(misp)
        print("\n".join(domains))
    elif args.mode == "thehive":
        push_to_thehive(misp, hive)
    elif args.mode == "watch":
        log.info(f"Watch mode: syncing every {args.interval}s")
        while True:
            full_sync(misp, hive)
            log.info(f"Next sync in {args.interval}s...")
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
