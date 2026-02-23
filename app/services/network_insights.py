from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.device import Device
from app.models.metric import Metric


async def detect_bottlenecks(db: AsyncSession) -> List[Dict[str, Any]]:
    """Detect potential network bottlenecks based on persisted metrics.

    This implementation intentionally avoids "fake" per-device fields and instead
    derives signals from real Metric rows.

    Current signal:
    - High interface bandwidth (if_in_bps / if_out_bps) collected via SNMP polling.
    """

    now = datetime.utcnow()
    window_start = now - timedelta(minutes=5)

    metric_result = await db.execute(
        select(Metric)
        .where(Metric.metric_type.in_({"if_in_bps", "if_out_bps"}))
        .where(Metric.timestamp >= window_start)
        .order_by(Metric.timestamp.desc())
        .limit(5000)
    )
    metrics = list(metric_result.scalars().all())

    # Pair in/out samples by (device_id, ifIndex, timestamp) then compute total bps.
    samples: Dict[tuple[int, int, datetime], Dict[str, Any]] = {}

    for m in metrics:
        if m.device_id is None:
            continue

        tags = m.tags or {}
        raw_if = tags.get("ifIndex")
        try:
            if_index = int(raw_if)
        except (TypeError, ValueError):
            continue

        key = (int(m.device_id), if_index, m.timestamp)
        s = samples.setdefault(
            key,
            {
                "in_bps": 0.0,
                "out_bps": 0.0,
                "ifDescr": tags.get("ifDescr"),
            },
        )
        if m.metric_type == "if_in_bps":
            s["in_bps"] = float(m.value)
        elif m.metric_type == "if_out_bps":
            s["out_bps"] = float(m.value)

        if not s.get("ifDescr") and tags.get("ifDescr"):
            s["ifDescr"] = tags.get("ifDescr")

    # Reduce to per-interface peak total bps over the window.
    per_iface_peak: Dict[tuple[int, int], Dict[str, Any]] = {}
    for (device_id, if_index, _), s in samples.items():
        total_bps = float(s.get("in_bps", 0.0)) + float(s.get("out_bps", 0.0))
        k = (device_id, if_index)
        existing = per_iface_peak.get(k)
        if existing is None or total_bps > float(existing["total_bps"]):
            per_iface_peak[k] = {
                "total_bps": total_bps,
                "in_bps": float(s.get("in_bps", 0.0)),
                "out_bps": float(s.get("out_bps", 0.0)),
                "ifDescr": s.get("ifDescr"),
            }

    # Thresholds are intentionally conservative defaults (bits/sec).
    warning_bps = 50_000_000.0
    critical_bps = 200_000_000.0

    flagged: Dict[int, List[Dict[str, Any]]] = {}

    for (device_id, if_index), peak in per_iface_peak.items():
        total_bps = float(peak["total_bps"])
        if total_bps < warning_bps:
            continue

        severity = "warning" if total_bps < critical_bps else "critical"

        issues = flagged.setdefault(device_id, [])
        issues.append(
            {
                "severity": severity,
                "ifIndex": if_index,
                "ifDescr": peak.get("ifDescr"),
                "in_bps": float(peak["in_bps"]),
                "out_bps": float(peak["out_bps"]),
                "total_bps": total_bps,
            }
        )

    if not flagged:
        return []

    device_ids = list(flagged.keys())
    device_result = await db.execute(select(Device).where(Device.id.in_(device_ids)))
    devices = {d.id: d for d in device_result.scalars().all()}

    bottlenecks: List[Dict[str, Any]] = []

    for device_id, iface_issues in flagged.items():
        device = devices.get(device_id)
        if device is None:
            continue

        # Pick the most severe issue as the device severity.
        device_severity = "warning"
        if any(i["severity"] == "critical" for i in iface_issues):
            device_severity = "critical"

        issue_lines: List[str] = []
        for i in sorted(iface_issues, key=lambda x: float(x["total_bps"]), reverse=True)[:3]:
            label = i.get("ifDescr") or f"ifIndex {i['ifIndex']}"
            mbps = float(i["total_bps"]) / 1_000_000.0
            issue_lines.append(f"High interface traffic on {label}: {mbps:.1f} Mbps")

        bottlenecks.append(
            {
                "device_id": device.id,
                "hostname": device.hostname or "Unknown",
                "ip_address": device.ip_address,
                "device_type": device.device_type or "unknown",
                "issues": issue_lines,
                "severity": device_severity,
                "recommendation": _get_recommendation(issue_lines, device),
            }
        )

    bottlenecks.sort(key=lambda x: {"critical": 0, "warning": 1, "info": 2}.get(x["severity"], 3))

    return bottlenecks


def _get_recommendation(issues: List[str], device: Device) -> str:
    """Generate a recommendation based on detected issues."""
    recommendations = []
    
    for issue in issues:
        if "latency" in issue.lower():
            recommendations.append("Check for congestion on network path")
            recommendations.append("Verify no bandwidth-heavy processes running")
        if "packet loss" in issue.lower():
            recommendations.append("Check physical connections and cable quality")
            recommendations.append("Review switch port statistics for errors")
        if "cpu" in issue.lower():
            recommendations.append("Identify high-CPU processes")
            recommendations.append("Consider load balancing or hardware upgrade")
        if any(k in issue.lower() for k in ["bandwidth", "interface traffic", "traffic"]):
            recommendations.append("Identify top bandwidth consumers")
            recommendations.append("Implement QoS policies or rate limits")
    
    return "; ".join(recommendations[:2]) if recommendations else "Monitor and investigate further"


async def get_nmap_recommendations(
    target_ip: str,
    target_type: Optional[str] = None,
    db: Optional[AsyncSession] = None,
) -> Dict[str, Any]:
    """Get intelligent nmap scan recommendations based on target characteristics.
    
    Args:
        target_ip: The IP address to scan
        target_type: Optional hint about target type (router, server, iot, etc.)
        db: Database session for looking up known device info
    """
    device_info = None
    if db:
        result = await db.execute(
            select(Device).where(Device.ip_address == target_ip)
        )
        device_info = result.scalar_one_or_none()
    
    recommendations = []
    
    if device_info:
        known_type = getattr(device_info, 'device_type', None)
        if known_type:
            target_type = known_type
    
    recommendations.append({
        "scan_type": "Discovery",
        "command": f"nmap -sn {target_ip}",
        "description": "Quick ping sweep to check if host is up",
        "time_estimate": "< 1 second",
        "risk": "low",
    })
    
    recommendations.append({
        "scan_type": "Quick Port Scan",
        "command": f"nmap -T4 -F {target_ip}",
        "description": "Fast scan of top 100 ports",
        "time_estimate": "5-10 seconds",
        "risk": "low",
    })
    
    if target_type:
        type_lower = target_type.lower()
        
        if type_lower in ["router", "switch", "firewall", "network"]:
            recommendations.append({
                "scan_type": "Network Device Scan",
                "command": f"nmap -sV --script=snmp-info,http-title -p 22,23,80,161,443,830 {target_ip}",
                "description": "Scan common network device ports with service detection",
                "time_estimate": "30-60 seconds",
                "risk": "low",
            })
        
        elif type_lower in ["server", "linux", "windows"]:
            recommendations.append({
                "scan_type": "Server Audit",
                "command": f"nmap -sV -sC -p- --min-rate=1000 {target_ip}",
                "description": "Full port scan with service detection and scripts",
                "time_estimate": "5-15 minutes",
                "risk": "medium",
            })
            recommendations.append({
                "scan_type": "Vulnerability Scan",
                "command": f"nmap --script=vuln -p 21,22,80,443,445,3389 {target_ip}",
                "description": "Check for known vulnerabilities on common ports",
                "time_estimate": "2-5 minutes",
                "risk": "medium",
            })
        
        elif type_lower in ["web", "http", "webserver"]:
            recommendations.append({
                "scan_type": "Web Server Scan",
                "command": f"nmap -sV --script=http-enum,http-headers,ssl-enum-ciphers -p 80,443,8080 {target_ip}",
                "description": "Comprehensive web server analysis",
                "time_estimate": "1-3 minutes",
                "risk": "low",
            })
        
        elif type_lower in ["database", "db", "mysql", "postgres"]:
            recommendations.append({
                "scan_type": "Database Scan",
                "command": f"nmap -sV --script=mysql-info,ms-sql-info,mongodb-info -p 1433,3306,5432,27017 {target_ip}",
                "description": "Database server enumeration",
                "time_estimate": "30-60 seconds",
                "risk": "low",
            })
        
        elif type_lower in ["iot", "camera", "smart"]:
            recommendations.append({
                "scan_type": "IoT Device Scan",
                "command": f"nmap -sV --script=http-title,upnp-info -p 80,443,554,1883,8080 {target_ip}",
                "description": "IoT device discovery and service detection",
                "time_estimate": "30-60 seconds",
                "risk": "low",
            })
    
    recommendations.append({
        "scan_type": "Comprehensive Audit",
        "command": f"nmap -sS -sV -O -A -p- {target_ip}",
        "description": "Full TCP scan with OS detection and aggressive scripts",
        "time_estimate": "15-30 minutes",
        "risk": "high",
    })
    
    return {
        "target": target_ip,
        "detected_type": target_type,
        "recommendations": recommendations,
        "note": "Higher risk scans may trigger IDS/IPS alerts. Use with caution.",
    }


async def get_network_health_summary(db: AsyncSession) -> Dict[str, Any]:
    """Get overall network health summary."""
    result = await db.execute(select(Device))
    devices = result.scalars().all()
    
    total_devices = len(devices)

    now = datetime.utcnow()
    online_window = timedelta(minutes=5)
    online_devices = sum(
        1
        for d in devices
        if d.last_seen is not None and (now - d.last_seen) <= online_window
    )
    offline_devices = total_devices - online_devices
    
    bottlenecks = await detect_bottlenecks(db)
    critical_issues = sum(1 for b in bottlenecks if b["severity"] == "critical")
    warning_issues = sum(1 for b in bottlenecks if b["severity"] == "warning")
    
    if critical_issues > 0:
        health_status = "critical"
        health_score = max(0, 100 - (critical_issues * 20) - (warning_issues * 5))
    elif warning_issues > 0:
        health_status = "degraded"
        health_score = max(50, 100 - (warning_issues * 10))
    elif offline_devices > total_devices * 0.1:
        health_status = "degraded"
        health_score = 80
    else:
        health_status = "healthy"
        health_score = 100
    
    return {
        "status": health_status,
        "health_score": health_score,
        "total_devices": total_devices,
        "online_devices": online_devices,
        "offline_devices": offline_devices,
        "critical_issues": critical_issues,
        "warning_issues": warning_issues,
        "bottlenecks": bottlenecks[:5],
        "last_updated": datetime.utcnow().isoformat(),
    }
