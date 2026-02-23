from __future__ import annotations

"""
Prebuilt script: defense_block_ip.py

Template for blocking a source IP at the container's host firewall
using iptables. In many production environments you would adapt this
to call a central firewall API instead of manipulating iptables directly.
"""

import ipaddress
import subprocess
from typing import Any


def run(ctx: Any) -> dict:
    """Template: block an IP at the host firewall level.

    Parameters (ctx.params):
      {
        "target_ip": "10.0.0.5"
      }

    This script assumes iptables is available inside the container and that
    it has NET_ADMIN capabilities. In many lab setups you may instead want
    to log the intended command and apply it on the host manually.
    """
    params = getattr(ctx, "params", {}) or {}
    target_ip = params.get("target_ip")

    if not target_ip:
        raise ValueError("target_ip is required")

    try:
        ipaddress.ip_address(target_ip)
    except ValueError:
        raise ValueError(f"target_ip is not a valid IP address: {target_ip}")

    ctx.logger(f"defense_block_ip: attempting to block {target_ip} via iptables")

    cmd = ["iptables", "-A", "INPUT", "-s", target_ip, "-j", "DROP"]

    try:
        result = subprocess.run(cmd, check=False, capture_output=True, text=True)
        if result.returncode != 0:
            ctx.logger(
                f"iptables returned {result.returncode}: {result.stderr.strip()}"
            )
            return {
                "status": "error",
                "target_ip": target_ip,
                "returncode": result.returncode,
                "stderr": result.stderr,
            }
    except FileNotFoundError:
        message = "iptables not found in container; log-only mode."
        ctx.logger(message)
        return {"status": "iptables_missing", "target_ip": target_ip}

    ctx.logger("defense_block_ip: rule appended")
    return {"status": "blocked", "target_ip": target_ip}