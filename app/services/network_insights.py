from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.device import Device


async def detect_bottlenecks(db: AsyncSession) -> List[Dict[str, Any]]:
    """Detect potential network bottlenecks based on device metrics.
    
    Returns a list of devices or network segments that may be experiencing issues.
    """
    bottlenecks = []
    
    result = await db.execute(select(Device))
    devices = result.scalars().all()
    
    for device in devices:
        issues = []
        severity = "info"
        
        if hasattr(device, 'last_response_time_ms') and device.last_response_time_ms:
            if device.last_response_time_ms > 200:
                issues.append(f"High latency: {device.last_response_time_ms}ms response time")
                severity = "warning"
            if device.last_response_time_ms > 500:
                severity = "critical"
        
        if hasattr(device, 'packet_loss_percent') and device.packet_loss_percent:
            if device.packet_loss_percent > 1:
                issues.append(f"Packet loss: {device.packet_loss_percent}%")
                severity = "warning"
            if device.packet_loss_percent > 5:
                severity = "critical"
        
        if hasattr(device, 'cpu_utilization') and device.cpu_utilization:
            if device.cpu_utilization > 80:
                issues.append(f"High CPU: {device.cpu_utilization}%")
                severity = "warning"
        
        if hasattr(device, 'bandwidth_utilization') and device.bandwidth_utilization:
            if device.bandwidth_utilization > 80:
                issues.append(f"High bandwidth utilization: {device.bandwidth_utilization}%")
                severity = "warning"
        
        if issues:
            bottlenecks.append({
                "device_id": device.id,
                "hostname": device.hostname or "Unknown",
                "ip_address": device.ip_address,
                "device_type": getattr(device, 'device_type', 'unknown'),
                "issues": issues,
                "severity": severity,
                "recommendation": _get_recommendation(issues, device),
            })
    
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
        if "bandwidth" in issue.lower():
            recommendations.append("Implement QoS policies")
            recommendations.append("Identify top bandwidth consumers")
    
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
    online_devices = sum(1 for d in devices if getattr(d, 'is_online', True))
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
