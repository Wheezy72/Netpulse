from __future__ import annotations

from typing import Any


async def run(ctx: Any) -> dict:
    """Kill a specific TCP connection using TCP RST packets.

    Expects ScriptJob.params to contain:

        {
          "src_ip": "...",
          "src_port": 12345,
          "dst_ip": "...",
          "dst_port": 80,
          "count": 3  # optional
        }

    The actual packet crafting and sending is provided by ctx.network.tcp_rst.
    """
    params = ctx.params or {}

    try:
        src_ip = params["src_ip"]
        src_port = int(params["src_port"])
        dst_ip = params["dst_ip"]
        dst_port = int(params["dst_port"])
    except KeyError as exc:
        raise ValueError(f"Missing required parameter: {exc}") from exc

    count = int(params.get("count", 3))

    ctx.logger(
        f"kill_switch: sending TCP RST from {src_ip}:{src_port} to {dst_ip}:{dst_port} "
        f"({count} packets)"
    )

    await ctx.network.tcp_rst(
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        count=count,
    )

    ctx.logger("kill_switch: completed")
    return {"status": "rst_sent", "src_ip": src_ip, "dst_ip": dst_ip}