from __future__ import annotations
import re
import subprocess
from datetime import datetime
from typing import Any, Dict, List


class RogueDhcpDetector:
    name = "Rogue DHCP Detector"
    description = "Detects unauthorized DHCP servers on the network"
    version = "1.0.0"
    category = "detector"

    def __init__(self):
        self.authorized_servers: List[str] = []

    def initialize(self, config: Dict[str, Any]) -> None:
        self.authorized_servers = config.get("authorized_dhcp_servers", [])

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        target = context.get("target", "192.168.1.0/24")
        try:
            result = subprocess.run(
                ['nmap', '--script=broadcast-dhcp-discover', '-e', context.get('interface', 'eth0')],
                capture_output=True, text=True, timeout=30
            )

            found_servers = []
            for line in result.stdout.split('\n'):
                if 'Server Identifier' in line:
                    ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
                    if ip_match:
                        found_servers.append(ip_match.group(1))

            rogue = [s for s in found_servers if s not in self.authorized_servers]

            return {
                "status": "ok",
                "found_servers": found_servers,
                "authorized": [s for s in found_servers if s in self.authorized_servers],
                "rogue": rogue,
                "alerts": [
                    {"type": "rogue_dhcp", "severity": "critical", "ip": s,
                     "message": f"Unauthorized DHCP server detected at {s}!",
                     "timestamp": datetime.now().isoformat()}
                    for s in rogue
                ]
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def cleanup(self) -> None:
        pass
