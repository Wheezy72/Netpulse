from __future__ import annotations

"""
Prebuilt script: rogue_dhcp_mitigation.py

Rogue DHCP Server Mitigation.
"""

from typing import Any
import re

try:
    from netmiko import ConnectHandler
except ImportError as exc:
    raise RuntimeError(
        "netmiko is required to run rogue_dhcp_mitigation.py. "
        "Install it in the worker image (e.g. pip install netmiko)."
    ) from exc


async def run(ctx: Any) -> dict:
    """Deploy ACLs and configure DHCP Snooping to mitigate a rogue DHCP server.

    Parameters (ctx.params):
      - rogue_ip: "192.168.1.99" (required)
      - rogue_mac: "00:11:22:33:44:55" (optional)
      - switch_host: "192.168.1.10" (optional)
      - uplink_port: "GigabitEthernet 1/0/24" (optional, default: "GigabitEthernet 1/0/24")
    """
    params = getattr(ctx, "params", {}) or {}
    rogue_ip = params.get("rogue_ip")
    rogue_mac = params.get("rogue_mac")
    switch_host = params.get("switch_host")
    uplink_port = params.get("uplink_port", "GigabitEthernet 1/0/24")

    if not rogue_ip:
        raise ValueError("rogue_ip parameter is required for rogue DHCP server mitigation")

    ctx.logger(f"rogue_dhcp_mitigation: Initiating mitigation for rogue DHCP IP {rogue_ip}")

    from app.core.config import settings
    host = switch_host or settings.switch_mgmt_host or "192.168.1.254"
    user = settings.switch_mgmt_user or "netpulse"
    secret = settings.switch_mgmt_password or "changeme"
    dev_type = settings.switch_mgmt_device_type or "cisco_ios"
    enable = settings.switch_mgmt_enable_secret or secret
    port_num = settings.switch_mgmt_port or 22

    # Query device from DB to log context
    try:
        from sqlalchemy import select
        from app.models.device import Device
        async def get_device():
            res = await ctx.db.execute(select(Device).where(Device.ip_address == rogue_ip))
            return res.scalar_one_or_none()
        device = await get_device()
        if device:
            ctx.logger(f"Found rogue device in database: {device.hostname or device.ip_address}")
            if not rogue_mac:
                rogue_mac = device.mac_address
    except Exception as e:
        ctx.logger(f"Database lookup skipped/failed: {e}")

    # Connect to the switch
    ctx.logger(f"Connecting to switch {host}...")
    try:
        connection = ConnectHandler(
            device_type=dev_type,
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
        ctx.logger("Simulating Rogue DHCP Mitigation (Development/Demo Mode)")
        ctx.logger(f"[SIMULATION] Deploying ACL on distribution layer blocking UDP 67/68 from {rogue_ip}")
        ctx.logger("[SIMULATION] ip dhcp snooping")
        ctx.logger(f"[SIMULATION] interface {uplink_port}")
        ctx.logger("[SIMULATION]  ip dhcp snooping trust")
        return {
            "status": "simulated",
            "rogue_ip": rogue_ip,
            "rogue_mac": rogue_mac,
            "switch_host": host,
            "uplink_port": uplink_port,
            "details": "Switch was offline; simulated ACL and DHCP Snooping configuration executed for demo/dev purposes."
        }

    try:
        if enable:
            connection.enable()

        ctx.logger("Configuring ACL and DHCP Snooping...")
        # Create ACL to block DHCP traffic from the rogue server IP
        # Enable DHCP snooping globally and trust the designated uplink port
        commands = [
            "ip access-list extended BLOCK-ROGUE-DHCP",
            f"deny udp host {rogue_ip} any eq bootps",
            f"deny udp host {rogue_ip} any eq bootpc",
            "permit ip any any",
            "ip dhcp snooping",
            "ip dhcp snooping vlan 1",
            f"interface {uplink_port}",
            "ip dhcp snooping trust"
        ]
        output = connection.send_config_set(commands)
        ctx.logger(f"Switch output:\n{output}")
        connection.disconnect()
        return {
            "status": "success",
            "rogue_ip": rogue_ip,
            "rogue_mac": rogue_mac,
            "switch_host": host,
            "uplink_port": uplink_port,
            "details": output
        }
    except Exception as e:
        connection.disconnect()
        ctx.logger(f"Error executing switch commands: {e}")
        return {
            "status": "failed",
            "error": str(e)
        }
