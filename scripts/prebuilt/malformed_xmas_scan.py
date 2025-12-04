from __future__ import annotations

from typing import Any

from scapy.all import IP, TCP, send  # type: ignore[import-untyped]


def run(ctx: Any) -> dict:
    """Template: TCP Xmas scan-style malformed packets.

    Parameters (ctx.params):
      {
        "target_ip": "10.0.0.5",
        "ports": [22, 80, 443],
        "count": 1
      }

    Flags set: FIN + PSH + URG (classic "Xmas" pattern).
    """
    params = getattr(ctx, "params", {}) or {}
    target_ip = params.get("target_ip")
    ports = params.get("ports", [22, 80, 443])
    count = int(params.get("count", 1))

    if not target_ip:
        raise ValueError("target_ip is required")

    if not isinstance(ports, list) or not ports:
        ports = [22, 80, 443]

    ctx.logger(
        f"malformed_xmas_scan: sending Xmas packets to {target_ip} on ports {ports} "
        f"x{count}"
    )

    pkts = []
    for _ in range(count):
        for port in ports:
            ip = IP(dst=target_ip)
            tcp = TCP(dport=int(port), flags="FPU")
            pkts.append(ip / tcp)

    send(pkts, verbose=False)

    ctx.logger("malformed_xmas_scan: completed")
    return {"status": "sent", "packets": len(pkts), "target_ip": target_ip, "ports": ports}