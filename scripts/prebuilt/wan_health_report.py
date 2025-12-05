from __future__ import annotations

"""
Prebuilt script: wan_health_report.py

Summarises recent Internet Health metrics into a JSON report file under
/data/reports. Intended for scheduled reporting or quick health checks
without building a separate analytics pipeline.
"""

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


async def run(ctx: Any) -> dict:
    """
    Generate a simple WAN health report for the last 24 hours.

    The report includes:
      - number of samples
      - min/avg/max Internet Health score
      - timestamp range
    """
    ctx.logger("wan_health_report: collecting metrics for last 24 hours")

    now = datetime.utcnow()
    window_start = now - timedelta(hours=24)

    sql = """
        SELECT timestamp, value
        FROM metrics
        WHERE metric_type = :metric_type
          AND timestamp >= :from_ts
        ORDER BY timestamp ASC
    """
    result = await ctx.db.execute(
        sql,
        {"metric_type": "internet_health", "from_ts": window_start},
    )
    rows = result.fetchall()

    if not rows:
        ctx.logger("wan_health_report: no metrics found in window")
        summary = {
            "status": "empty",
            "samples": 0,
            "from": window_start.isoformat(),
            "to": now.isoformat(),
        }
    else:
        values = [float(r.value) for r in rows]
        summary = {
            "status": "ok",
            "samples": len(values),
            "from": rows[0].timestamp.isoformat(),
            "to": rows[-1].timestamp.isoformat(),
            "min_health": min(values),
            "max_health": max(values),
            "avg_health": sum(values) / len(values),
        }

    reports_dir = Path("/data/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    ts = now.strftime("%Y%m%d-%H%M%S")
    path = reports_dir / f"wan_health_{ts}.json"

    path.write_text(json.dumps(summary, indent=2))
    ctx.logger(f"wan_health_report: wrote report to {path}")
    return {"status": summary.get("status"), "path": str(path), "samples": summary.get("samples", 0)}