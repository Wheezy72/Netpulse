from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

from scapy.all import rdpcap, sendp  # type: ignore[import-untyped]


def run(ctx: Any) -> dict:
    """Replay packets from a PCAP file.

    Parameters (ctx.params):
      {
        "pcap_path": "/data/pcap/capture_12.pcap",
        "iface": "eth0"
      }

    Notes:
      - This is intended for lab use to understand traffic patterns.
      - Container needs permission to send raw packets on the given interface.
      - For high-speed replay, external tools such as tcpreplay may be better.
    """
    params = getattr(ctx, "params", {}) or {}
    pcap_path = params.get("pcap_path")
    iface = params.get("iface", "eth0")

    if not pcap_path:
        raise ValueError("pcap_path is required")

    path = Path(pcap_path)
    if not path.exists():
        raise FileNotFoundError(f"PCAP not found at {pcap_path}")

    ctx.logger(f"replay_pcap: loading packets from {pcap_path}")
    packets = rdpcap(str(path))

    if not packets:
        ctx.logger("replay_pcap: no packets in file")
        return {"status": "empty", "pcap_path": pcap_path}

    ctx.logger(f"replay_pcap: sending {len(packets)} packets via {iface}")

    # Best-effort replay with Scapy; for precise timing, consider tcpreplay.
    sendp(packets, iface=iface, verbose=False)

    ctx.logger("replay_pcap: completed")
    return {"status": "replayed", "pcap_path": pcap_path, "count": len(packets)}