from __future__ import annotations

"""
Prebuilt script: device_inventory_export.py

Exports the current device inventory to a CSV file under /data/reports.
Useful for quick audits or feeding other tooling without querying the API.
"""

import csv
from datetime import datetime
from pathlib import Path
from typing import Any


async def run(ctx: Any) -> dict:
    """
    Export device inventory to CSV.

    The CSV contains:
      id, hostname, ip_address, mac_address, device_type, is_gateway, last_seen
    """
    ctx.logger("device_inventory_export: starting")

    sql = """
        SELECT id, hostname, ip_address, mac_address, device_type, is_gateway, last_seen
        FROM devices
        ORDER BY id
    """
    result = await ctx.db.execute(sql)
    rows = result.fetchall()

    reports_dir = Path("/data/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    ts = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    path = reports_dir / f"device_inventory_{ts}.csv"

    with path.open("w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(
            ["id", "hostname", "ip_address", "mac_address", "device_type", "is_gateway", "last_seen"]
        )
        for row in rows:
            writer.writerow(
                [
                    row.id,
                    row.hostname or "",
                    row.ip_address,
                    row.mac_address or "",
                    row.device_type or "",
                    bool(row.is_gateway),
                    row.last_seen.isoformat() if row.last_seen else "",
                ]
            )

    ctx.logger(f"device_inventory_export: wrote {len(rows)} devices to {path}")
    return {"status": "ok", "count": len(rows), "path": str(path)}