from __future__ import annotations
import re
import subprocess
from datetime import datetime
from typing import Any, Dict, List


class PortKnockDetector:
    name = "Port Knock Detector"
    description = "Detects sequential port scanning patterns against your hosts"
    version = "1.0.0"
    category = "detector"

    def __init__(self):
        self.scan_patterns: Dict[str, List] = {}
        self.threshold = 10

    def initialize(self, config: Dict[str, Any]) -> None:
        self.threshold = config.get("threshold", 10)

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        try:
            result = subprocess.run(
                ['ss', '-tn', 'state', 'all'],
                capture_output=True, text=True, timeout=5
            )

            connections: Dict[str, set] = {}
            for line in result.stdout.strip().split('\n')[1:]:
                parts = line.split()
                if len(parts) >= 5:
                    remote = parts[4] if len(parts) > 4 else parts[3]
                    ip_match = re.match(r'(\d+\.\d+\.\d+\.\d+):(\d+)', remote)
                    if ip_match:
                        ip = ip_match.group(1)
                        port = int(ip_match.group(2))
                        if ip not in connections:
                            connections[ip] = set()
                        connections[ip].add(port)

            alerts = []
            for ip, ports in connections.items():
                if len(ports) >= self.threshold:
                    alerts.append({
                        "type": "port_scan",
                        "severity": "medium",
                        "source_ip": ip,
                        "ports_accessed": len(ports),
                        "message": f"Possible port scan from {ip} - {len(ports)} ports accessed",
                        "timestamp": datetime.now().isoformat()
                    })

            return {
                "status": "ok",
                "sources_analyzed": len(connections),
                "alerts": alerts
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def cleanup(self) -> None:
        self.scan_patterns.clear()
