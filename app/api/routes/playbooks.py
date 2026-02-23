from __future__ import annotations

import asyncio
import hashlib
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, List, Literal, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, get_current_user
from app.core.celery_app import celery_app
from app.models.router_config_baseline import RouterConfigBaseline
from app.models.scan_job import ScanJob, ScanJobStatus
from app.models.user import User
from app.services.routers import create_router_driver

router = APIRouter()


class PlaybookScan(BaseModel):
    id: str
    name: str
    description: str
    category: str
    nmap_args: str
    ports: Optional[str] = None
    scripts: Optional[List[str]] = None
    recommended_for: List[str]
    risk_level: str
    estimated_time: str


HOME_LAB_SCANS = [
    PlaybookScan(
        id="quick-ping",
        name="Quick Ping Sweep",
        description="Fast discovery of live hosts on your network",
        category="Discovery",
        nmap_args="-sn -T4",
        recommended_for=["home", "small-office"],
        risk_level="low",
        estimated_time="< 1 min",
    ),
    PlaybookScan(
        id="home-router-check",
        name="Router Security Check",
        description="Scan your router for common vulnerabilities and open ports",
        category="Security",
        nmap_args="-sV -sC --script=http-title,http-headers,ssl-enum-ciphers",
        ports="22,23,80,443,8080,8443",
        recommended_for=["home"],
        risk_level="low",
        estimated_time="2-3 min",
    ),
    PlaybookScan(
        id="iot-discovery",
        name="IoT Device Discovery",
        description="Find smart devices, cameras, and IoT equipment on your network",
        category="Discovery",
        nmap_args="-sV -O --osscan-limit",
        ports="80,443,554,1883,8080,8883,5683",
        scripts=["http-title", "upnp-info"],
        recommended_for=["home", "smart-home"],
        risk_level="low",
        estimated_time="3-5 min",
    ),
    PlaybookScan(
        id="nas-audit",
        name="NAS & Storage Audit",
        description="Check NAS devices for exposed shares and services",
        category="Security",
        nmap_args="-sV --script=smb-enum-shares,nfs-showmount,afp-showmount",
        ports="21,22,139,445,548,2049,5000-5001,8080",
        recommended_for=["home", "small-office"],
        risk_level="low",
        estimated_time="2-4 min",
    ),
    PlaybookScan(
        id="media-server-check",
        name="Media Server Check",
        description="Discover Plex, Jellyfin, Emby and other media servers",
        category="Discovery",
        nmap_args="-sV --script=http-title",
        ports="8096,8920,32400,8123,7878,8989,9117",
        recommended_for=["home", "media-server"],
        risk_level="low",
        estimated_time="1-2 min",
    ),
]

ENTERPRISE_SCANS = [
    PlaybookScan(
        id="full-port-scan",
        name="Comprehensive Port Scan",
        description="Full TCP port scan with service detection",
        category="Discovery",
        nmap_args="-sS -sV -p- -T4 --min-rate=1000",
        recommended_for=["enterprise", "security-audit"],
        risk_level="medium",
        estimated_time="15-30 min",
    ),
    PlaybookScan(
        id="vuln-assessment",
        name="Vulnerability Assessment",
        description="Detect known vulnerabilities using NSE scripts",
        category="Security",
        nmap_args="-sV --script=vuln --script-timeout=60s",
        ports="21,22,23,25,53,80,110,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,8080",
        recommended_for=["enterprise", "security-audit"],
        risk_level="medium",
        estimated_time="10-20 min",
    ),
    PlaybookScan(
        id="windows-domain",
        name="Windows Domain Recon",
        description="Enumerate Windows domain controllers and services",
        category="Enterprise",
        nmap_args="-sV --script=smb-os-discovery,smb-enum-users,smb-enum-shares,ldap-rootdse",
        ports="53,88,135,139,389,445,464,636,3268,3269",
        recommended_for=["enterprise", "windows"],
        risk_level="low",
        estimated_time="5-10 min",
    ),
    PlaybookScan(
        id="web-server-audit",
        name="Web Server Audit",
        description="Comprehensive web server security assessment",
        category="Security",
        nmap_args="-sV --script=http-enum,http-methods,http-security-headers,ssl-cert,ssl-enum-ciphers",
        ports="80,443,8080,8443,8000,3000,5000",
        recommended_for=["enterprise", "web"],
        risk_level="low",
        estimated_time="5-8 min",
    ),
    PlaybookScan(
        id="database-audit",
        name="Database Server Audit",
        description="Check database servers for security issues",
        category="Security",
        nmap_args="-sV --script=mysql-info,ms-sql-info,oracle-sid-brute,mongodb-info,redis-info",
        ports="1433,1521,3306,5432,6379,27017,9042",
        recommended_for=["enterprise", "database"],
        risk_level="medium",
        estimated_time="3-5 min",
    ),
    PlaybookScan(
        id="network-infrastructure",
        name="Network Infrastructure Scan",
        description="Discover routers, switches, and network devices",
        category="Infrastructure",
        nmap_args="-sV --script=snmp-info,snmp-sysdescr,http-title",
        ports="22,23,80,161,443,830,8080",
        recommended_for=["enterprise", "network"],
        risk_level="low",
        estimated_time="5-10 min",
    ),
    PlaybookScan(
        id="firewall-evasion",
        name="Firewall Detection & Analysis",
        description="Detect firewall rules and test for bypass techniques",
        category="Security",
        nmap_args="-sA -Pn --script=firewalk",
        recommended_for=["enterprise", "security-audit"],
        risk_level="high",
        estimated_time="10-15 min",
    ),
    PlaybookScan(
        id="ssl-tls-audit",
        name="SSL/TLS Security Audit",
        description="Comprehensive SSL/TLS configuration assessment",
        category="Security",
        nmap_args="-sV --script=ssl-cert,ssl-enum-ciphers,ssl-known-key,ssl-heartbleed",
        ports="443,465,636,993,995,8443,9443",
        recommended_for=["enterprise", "compliance"],
        risk_level="low",
        estimated_time="3-5 min",
    ),
    PlaybookScan(
        id="dns-audit",
        name="DNS Server Audit",
        description="DNS server enumeration and zone transfer check",
        category="Security",
        nmap_args="-sV --script=dns-zone-transfer,dns-cache-snoop,dns-recursion",
        ports="53",
        recommended_for=["enterprise", "dns"],
        risk_level="low",
        estimated_time="2-3 min",
    ),
    PlaybookScan(
        id="mail-server-audit",
        name="Mail Server Audit",
        description="Check mail servers for security configurations",
        category="Security",
        nmap_args="-sV --script=smtp-commands,smtp-enum-users,smtp-open-relay,pop3-capabilities,imap-capabilities",
        ports="25,110,143,465,587,993,995",
        recommended_for=["enterprise", "email"],
        risk_level="low",
        estimated_time="3-5 min",
    ),
]

ALL_SCANS = HOME_LAB_SCANS + ENTERPRISE_SCANS


@router.get(
    "/",
    response_model=List[PlaybookScan],
    summary="List all available playbook scans",
)
async def list_playbooks(
    category: Optional[str] = None,
    environment: Optional[str] = None,
    current_user: User = Depends(get_current_user),
) -> List[PlaybookScan]:
    """Get all available network scan playbooks."""
    scans = ALL_SCANS
    
    if category:
        scans = [s for s in scans if s.category.lower() == category.lower()]
    
    if environment:
        if environment.lower() == "home":
            scans = [s for s in scans if "home" in s.recommended_for or "small-office" in s.recommended_for]
        elif environment.lower() == "enterprise":
            scans = [s for s in scans if "enterprise" in s.recommended_for]
    
    return scans


@router.get(
    "/{playbook_id}",
    response_model=PlaybookScan,
    summary="Get a specific playbook",
)
async def get_playbook(
    playbook_id: str,
    current_user: User = Depends(get_current_user),
) -> PlaybookScan:
    """Get details of a specific scan playbook."""
    for scan in ALL_SCANS:
        if scan.id == playbook_id:
            return scan
    raise HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=f"Playbook '{playbook_id}' not found"
    )


@router.get(
    "/recommend/{target_type}",
    response_model=List[PlaybookScan],
    summary="Get recommended scans for a target type",
)
async def recommend_scans(
    target_type: str,
    current_user: User = Depends(get_current_user),
) -> List[PlaybookScan]:
    """Get intelligent recommendations for scans based on target type.
    
    Target types: router, server, workstation, iot, database, web, network-device
    """
    recommendations = []
    
    target_lower = target_type.lower()
    
    if target_lower in ["router", "gateway", "firewall"]:
        recommendations = [s for s in ALL_SCANS if s.id in [
            "home-router-check", "network-infrastructure", "firewall-evasion", "ssl-tls-audit"
        ]]
    elif target_lower in ["server", "linux", "windows"]:
        recommendations = [s for s in ALL_SCANS if s.id in [
            "full-port-scan", "vuln-assessment", "windows-domain", "ssl-tls-audit"
        ]]
    elif target_lower in ["iot", "smart-device", "camera"]:
        recommendations = [s for s in ALL_SCANS if s.id in [
            "iot-discovery", "quick-ping", "home-router-check"
        ]]
    elif target_lower in ["database", "db", "sql"]:
        recommendations = [s for s in ALL_SCANS if s.id in [
            "database-audit", "vuln-assessment", "ssl-tls-audit"
        ]]
    elif target_lower in ["web", "http", "website"]:
        recommendations = [s for s in ALL_SCANS if s.id in [
            "web-server-audit", "ssl-tls-audit", "vuln-assessment"
        ]]
    elif target_lower in ["nas", "storage", "file-server"]:
        recommendations = [s for s in ALL_SCANS if s.id in [
            "nas-audit", "full-port-scan", "vuln-assessment"
        ]]
    elif target_lower in ["mail", "email", "smtp"]:
        recommendations = [s for s in ALL_SCANS if s.id in [
            "mail-server-audit", "ssl-tls-audit", "dns-audit"
        ]]
    else:
        recommendations = [s for s in ALL_SCANS if s.id in [
            "quick-ping", "full-port-scan", "vuln-assessment"
        ]]
    
    return recommendations


@router.get(
    "/categories/list",
    response_model=List[str],
    summary="List all scan categories",
)
async def list_categories(
    current_user: User = Depends(get_current_user),
) -> List[str]:
    """Get all available scan categories."""
    return list(set(s.category for s in ALL_SCANS))


class ConfigDriftCheckRequest(BaseModel):
    driver: Literal["mikrotik", "netmiko"]
    host: str
    username: str
    password: str
    port: int | None = None

    # Netmiko-only options
    device_type: str | None = None
    enable_secret: str | None = None


class ConfigDriftCheckResponse(BaseModel):
    scan_id: str
    changed: bool
    old_hash: str | None
    new_hash: str
    artifact_path: str


@router.post(
    "/config_drift_check",
    response_model=ConfigDriftCheckResponse,
    summary="Check router config drift and update baseline",
)
async def config_drift_check(
    request: ConfigDriftCheckRequest,
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> ConfigDriftCheckResponse:
    if request.driver == "netmiko" and not request.device_type:
        raise HTTPException(status_code=400, detail="device_type is required for netmiko driver")

    driver = create_router_driver(
        request.driver,
        host=request.host,
        username=request.username,
        password=request.password,
        port=request.port,
        device_type=request.device_type,
        enable_secret=request.enable_secret,
    )

    config = await driver.get_config()
    config_bytes = config.encode("utf-8", errors="replace")
    new_hash = hashlib.sha256(config_bytes).hexdigest()

    effective_port = driver.port

    result = await db.execute(
        select(RouterConfigBaseline).where(
            RouterConfigBaseline.host == request.host,
            RouterConfigBaseline.driver == request.driver,
            RouterConfigBaseline.username == request.username,
            RouterConfigBaseline.port == effective_port,
        )
    )
    baseline = result.scalar_one_or_none()

    old_hash = baseline.config_hash if baseline else None
    changed = old_hash != new_hash

    now = datetime.utcnow()
    if baseline:
        baseline.config_hash = new_hash
        baseline.last_seen_at = now
    else:
        baseline = RouterConfigBaseline(
            host=request.host,
            driver=request.driver,
            username=request.username,
            port=effective_port,
            config_hash=new_hash,
            last_seen_at=now,
        )
        db.add(baseline)

    scan_id = str(uuid.uuid4())
    scans_dir = Path("data/scans")
    scans_dir.mkdir(parents=True, exist_ok=True)
    artifact_path = scans_dir / f"scan_{scan_id}.txt"

    config_lines = config.splitlines()
    preview = "\n".join(config_lines[:200])

    header_lines = [
        f"Profile: Config Drift Check",
        f"Target: {request.host}",
        f"Driver: {request.driver}",
        f"Username: {request.username}",
        f"Port: {effective_port}",
        f"Time: {now.isoformat()}Z",
        "= " * 30,
        f"Old hash: {old_hash or '(none)'}",
        f"New hash: {new_hash}",
        "",
    ]

    if changed:
        header_lines.append("Baseline updated (hash changed).")
        header_lines.append("")
        header_lines.append("Config preview (first ~200 lines):")
        header_lines.append(preview)
        header_lines.append("")
    else:
        header_lines.append("No drift detected (hash unchanged).")
        header_lines.append("")

    artifact_content = "\n".join(header_lines)
    await asyncio.to_thread(artifact_path.write_text, artifact_content, encoding="utf-8")

    job = ScanJob(
        id=scan_id,
        target=request.host,
        profile="Config Drift Check",
        arguments={
            "driver": request.driver,
            "username": request.username,
            "port": effective_port,
            "device_type": request.device_type,
        },
        status=ScanJobStatus.COMPLETED,
        result_summary={
            "changed": changed,
            "old_hash": old_hash,
            "new_hash": new_hash,
        },
        artifact_path=str(artifact_path),
        requested_by_user_id=current_user.id,
        started_at=now,
        completed_at=now,
    )
    db.add(job)

    await db.commit()

    try:
        celery_app.send_task("app.tasks.analyze_scan_results", args=[scan_id])
    except Exception:
        pass

    return ConfigDriftCheckResponse(
        scan_id=scan_id,
        changed=changed,
        old_hash=old_hash,
        new_hash=new_hash,
        artifact_path=str(artifact_path),
    )
