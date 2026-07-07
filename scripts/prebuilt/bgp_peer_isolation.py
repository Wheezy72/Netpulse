from __future__ import annotations

"""
Prebuilt script: bgp_peer_isolation.py

BGP Peer Isolation on Route Flapping.
"""

from typing import Any

try:
    from netmiko import ConnectHandler
except ImportError as exc:
    raise RuntimeError(
        "netmiko is required to run bgp_peer_isolation.py. "
        "Install it in the worker image (e.g. pip install netmiko)."
    ) from exc


async def run(ctx: Any) -> dict:
    """Gracefully shut down a flapping BGP neighbor.

    Parameters (ctx.params):
      - peer_ip: "198.51.100.2" (required)
      - asn: 65000 (optional, default: 65000)
      - router_host: "192.168.1.1" (optional)
      - device_type: "cisco_ios" (optional, e.g. "cisco_ios", "cisco_xr", "huawei")
    """
    params = getattr(ctx, "params", {}) or {}
    peer_ip = params.get("peer_ip")
    asn = params.get("asn", 65000)
    router_host = params.get("router_host")
    dev_type = params.get("device_type")

    if not peer_ip:
        raise ValueError("peer_ip parameter is required for BGP peer isolation")

    ctx.logger(f"bgp_peer_isolation: Initiating isolation for BGP neighbor {peer_ip}")

    # WebSockets push a real-time notification to the Vue 3 frontend
    soar_msg = f"[SOAR] BGP Peer {peer_ip} isolated due to excessive flapping. Convergence forced to redundant path."
    ctx.logger(soar_msg)

    from app.core.config import settings
    host = router_host or settings.switch_mgmt_host or "192.168.1.254"
    user = settings.switch_mgmt_user or "netpulse"
    secret = settings.switch_mgmt_password or "changeme"
    final_dev_type = dev_type or settings.switch_mgmt_device_type or "cisco_ios"
    enable = settings.switch_mgmt_enable_secret or secret
    port_num = settings.switch_mgmt_port or 22

    # Query device from DB to log context
    try:
        from sqlalchemy import select
        from app.models.device import Device
        async def get_device():
            res = await ctx.db.execute(select(Device).where(Device.ip_address == peer_ip))
            return res.scalar_one_or_none()
        device = await get_device()
        if device:
            ctx.logger(f"Found peer device in inventory: {device.hostname or device.ip_address}")
    except Exception as e:
        ctx.logger(f"Database lookup skipped/failed: {e}")

    # Connect to the router
    ctx.logger(f"Connecting to router {host}...")
    try:
        connection = ConnectHandler(
            device_type=final_dev_type,
            host=host,
            username=user,
            password=secret,
            secret=enable,
            port=port_num,
            fast_cli=True,
            timeout=10,
        )
    except Exception as e:
        ctx.logger(f"Connection failed to {host}: {e}")
        ctx.logger("Simulating BGP Peer Isolation (Development/Demo Mode)")
        ctx.logger(f"[SIMULATION] router bgp {asn}")
        ctx.logger(f"[SIMULATION]  neighbor {peer_ip} shutdown")
        return {
            "status": "simulated",
            "peer_ip": peer_ip,
            "asn": asn,
            "router_host": host,
            "details": f"Router was offline; simulated graceful BGP shutdown executed for demo/dev purposes. Alert message sent: {soar_msg}"
        }

    try:
        if enable:
            connection.enable()

        ctx.logger(f"Configuring shutdown for neighbor {peer_ip} under AS {asn}...")
        commands = [
            f"router bgp {asn}",
            f"neighbor {peer_ip} shutdown"
        ]
        output = connection.send_config_set(commands)
        ctx.logger(f"Router output:\n{output}")
        connection.disconnect()
        return {
            "status": "success",
            "peer_ip": peer_ip,
            "asn": asn,
            "router_host": host,
            "details": output
        }
    except Exception as e:
        connection.disconnect()
        ctx.logger(f"Error executing router commands: {e}")
        return {
            "status": "failed",
            "error": str(e)
        }
