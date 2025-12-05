from __future__ import annotations

"""
Prebuilt script: new_device_report.py

Generates a simple report of devices first seen within a recent time window.
Intended for spotting new hosts on your LAN (lab or home network).

This script does not send alerts by itself; it returns a summary in the
ScriptJob.result and logs basic details via ctx.logger.
"""

from datetime import datetime, timedelta
from typing import Any, Dict, List


async def run(ctx: Any) -> Dict[str, Any]:
    """
    List devices first seen within the last N minutes.

    Parameters
    ----------
    ctx.params["minutes"] : int (optional, default 60)
        Lookback window in minutes.

    Returns
    -------
    dict with count and a list of device records.
    """
    minutes = int(ctx.params.get("minutes", 60))
    window_start = datetime.utcnow() - timedelta(minutes=minutes)
    ctx.logger(f"new_device_report: finding devices first seen since {window_start}")

    sql = """
        SELECT id, hostname, ip_address, mac_address, device_type, last_seen
        FROM devices
        WHERE last_seen >= :from_ts
        ORDER BY last_seen DESC
    """
    result = await ctx.db.execute(sql, {"from_ts": window_start})
    rows = result.fetchall()

    devices: List[Dict[str, str]] = []
    for row in rows:
        devices.append(
            {
                "id": str(row.id),
                "hostname": row.hostname or "",
                "ip_address": row.ip_address or "",
                "mac_address": row.mac_address or "",
                "device_type": row.device_type or "",
                "last_seen": row.last_seen.isoformat() if row.last_seen else "",
            }
        )
        ctx.logger(
            f"new_device_report: device {row.hostname or row.ip_address} "
            f"({row.mac_address}) last_seen={row.last_seen}"
        )

    ctx.logger(f"new_device_report: found {len(devices)} device(s) in the window")
    return {"count": len(devices), "window_minutes": minutes, "devices": devices}