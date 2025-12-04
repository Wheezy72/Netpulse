from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Any

try:
    from netmiko import ConnectHandler
except ImportError as exc:
    raise RuntimeError(
        "netmiko is required to run backup_switch.py. "
        "Install it in the worker image (e.g. pip install netmiko)."
    ) from exc


async def run(ctx: Any) -> dict:
    """Backup running-config from all devices classified as 'switch'.

    This script demonstrates how to use the NetPulse script context:

    - ctx.db: async SQLAlchemy session
    - ctx.logger: logging callback
    - ctx.job_id: current ScriptJob ID
    """
    ctx.logger("backup_switch: starting backup of switches")

    result = await ctx.db.execute(
        "SELECT id, hostname, ip_address FROM devices WHERE device_type = :dtype",
        {"dtype": "switch"},
    )
    switches = result.fetchall()

    backups_dir = Path("/data/backups")
    backups_dir.mkdir(parents=True, exist_ok=True)

    backup_results: list[dict[str, str]] = []

    for sw in switches:
        display_name = sw.hostname or sw.ip_address
        ctx.logger(f"Connecting to switch {display_name}")

        conn = ConnectHandler(
            device_type="cisco_ios",
            host=sw.ip_address,
            username="netpulse",
            password="changeme",
        )
        config = conn.send_command("show running-config")
        conn.disconnect()

        ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
        filename = backups_dir / f"{display_name}-{ts}.cfg"
        filename.write_text(config)

        backup_results.append(
            {"device_id": str(sw.id), "hostname": display_name, "file": str(filename)}
        )
        ctx.logger(f"backup_switch: saved config for {display_name} to {filename}")

    ctx.logger("backup_switch: completed")
    return {"backups": backup_results}