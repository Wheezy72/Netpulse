from __future__ import annotations

"""
Prebuilt script: broadcast_storm_mitigation.py

Automated Port Isolation for Broadcast Storms and MAC Flapping.
"""

from typing import Any
import re

try:
    from netmiko import ConnectHandler
except ImportError as exc:
    raise RuntimeError(
        "netmiko is required to run broadcast_storm_mitigation.py. "
        "Install it in the worker image (e.g. pip install netmiko)."
    ) from exc


async def run(ctx: Any) -> dict:
    """Isolate a port causing a broadcast storm or MAC flap.

    Parameters (ctx.params):
      - mac_address: "00:11:22:33:44:55" (required)
      - switch_host: "192.168.1.10" (optional, falls back to settings or auto-detection)
      - switch_port: "GigabitEthernet 1/0/12" (optional, auto-detected if omitted)
    """
    params = getattr(ctx, "params", {}) or {}
    mac_address = params.get("mac_address")
    switch_host = params.get("switch_host")
    switch_port = params.get("switch_port")

    if not mac_address:
        raise ValueError("mac_address parameter is required for broadcast storm mitigation")

    ctx.logger(f"broadcast_storm_mitigation: Initiating isolation for MAC {mac_address}")

    # Fallback/Settings defaults
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
            res = await ctx.db.execute(select(Device).where(Device.mac_address == mac_address))
            return res.scalar_one_or_none()
        device = await get_device()
        if device:
            ctx.logger(f"Found associated device in database: {device.hostname or device.ip_address}")
    except Exception as e:
        ctx.logger(f"Database lookup skipped/failed: {e}")

    # Connect to the switch
    ctx.logger(f"Connecting to management switch {host}...")
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
        ctx.logger("Simulating port isolation (Development/Demo Mode)")
        simulated_port = switch_port or "GigabitEthernet 1/0/12"
        ctx.logger(f"[SIMULATION] interface {simulated_port}")
        ctx.logger("[SIMULATION]  description AUTO-DISABLED: Broadcast Storm Detected")
        ctx.logger("[SIMULATION]  shutdown")
        return {
            "status": "simulated",
            "mac_address": mac_address,
            "switch_host": host,
            "isolated_port": simulated_port,
            "details": "Switch was offline; simulated shutdown executed for demo/dev purposes."
        }

    try:
        if enable:
            connection.enable()

        # If switch_port is not provided, try to auto-discover it
        if not switch_port:
            ctx.logger(f"Querying CAM address table for MAC {mac_address}...")
            # Normalize MAC to Cisco format (xxxx.xxxx.xxxx) or default
            clean_mac = mac_address.replace(":", "").replace("-", "").lower()
            if len(clean_mac) == 12:
                cisco_mac = f"{clean_mac[:4]}.{clean_mac[4:8]}.{clean_mac[8:]}"
            else:
                cisco_mac = mac_address

            mac_table_output = connection.send_command(f"show mac address-table address {cisco_mac}")
            ctx.logger(f"CAM table output:\n{mac_table_output}")

            # Simple regex search for common interface patterns
            match = re.search(r"(Gi\d+/\d+/\d+|Fa\d+/\d+|\bEthernet\s*\d+/\d+\b|\bGigabitEthernet\s*\d+/\d+/\d+\b)", mac_table_output, re.IGNORECASE)
            if match:
                switch_port = match.group(1)
                ctx.logger(f"Auto-discovered switchport: {switch_port}")
            else:
                raise ValueError(f"Could not auto-discover switch port for MAC {mac_address}. Please specify switch_port.")

        # Safety Check: Verify that we are not shutting down an uplink or trunk port
        ctx.logger(f"Verifying switchport {switch_port} safety check...")
        safety_output = connection.send_command(f"show interface {switch_port} description")
        ctx.logger(f"Interface description output:\n{safety_output}")
        
        unsafe_keywords = ["uplink", "trunk", "core", "transit", "backbone", "po", "port-channel"]
        if any(kw in safety_output.lower() or kw in switch_port.lower() for kw in unsafe_keywords):
            ctx.logger(f"[SAFETY ALARM] Aborting shutdown. Interface {switch_port} is flagged as a critical link/uplink/trunk.")
            connection.disconnect()
            return {
                "status": "aborted",
                "reason": f"Safety check failed: interface {switch_port} is flagged as an uplink, trunk, or core link."
            }

        ctx.logger(f"Configuring shutdown on switch port: {switch_port}")
        commands = [
            f"interface {switch_port}",
            "description AUTO-DISABLED: Broadcast Storm Detected",
            "shutdown"
        ]
        output = connection.send_config_set(commands)
        ctx.logger(f"Switch output:\n{output}")
        connection.disconnect()
        return {
            "status": "success",
            "mac_address": mac_address,
            "switch_host": host,
            "isolated_port": switch_port,
            "details": output
        }
    except Exception as e:
        connection.disconnect()
        ctx.logger(f"Error executing switch commands: {e}")
        return {
            "status": "failed",
            "error": str(e)
        }
