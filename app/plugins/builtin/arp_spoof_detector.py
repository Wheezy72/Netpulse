from __future__ import annotations
import re
import subprocess
from datetime import datetime
from typing import Any, Dict, List


class ArpSpoofDetector:
    name = "ARP Spoof Detector"
    description = "Detects ARP spoofing/MITM attacks by monitoring ARP table changes"
    version = "1.0.0"
    category = "detector"

    def __init__(self):
        self.arp_table: Dict[str, str] = {}
        self.alerts: List[Dict] = []

    def initialize(self, config: Dict[str, Any]) -> None:
        pass

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        try:
            result = subprocess.run(['ip', 'neigh'], capture_output=True, text=True, timeout=5)
            entries = self._parse_arp(result.stdout)
            alerts = []

            for ip, mac in entries.items():
                if ip in self.arp_table and self.arp_table[ip] != mac:
                    alerts.append({
                        "type": "arp_change",
                        "severity": "high",
                        "ip": ip,
                        "old_mac": self.arp_table[ip],
                        "new_mac": mac,
                        "message": f"MAC address for {ip} changed from {self.arp_table[ip]} to {mac} - possible ARP spoofing!",
                        "timestamp": datetime.now().isoformat()
                    })
                self.arp_table[ip] = mac

            return {
                "status": "ok",
                "entries_checked": len(entries),
                "alerts": alerts,
                "arp_table": entries
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def _parse_arp(self, output: str) -> Dict[str, str]:
        entries = {}
        for line in output.strip().split('\n'):
            if not line.strip():
                continue
            parts = line.split()
            if len(parts) >= 5 and parts[2] == 'lladdr':
                entries[parts[0]] = parts[4]
            elif len(parts) >= 4:
                ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                mac_match = re.search(r'([0-9a-f]{2}(:[0-9a-f]{2}){5})', line, re.I)
                if ip_match and mac_match:
                    entries[ip_match.group(1)] = mac_match.group(1)
        return entries

    def cleanup(self) -> None:
        self.arp_table.clear()
