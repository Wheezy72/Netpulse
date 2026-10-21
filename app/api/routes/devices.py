from __future__ import annotations

import asyncio
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, get_current_user, require_compliance_role, require_scan_role
from app.models.device import Device
from app.models.user import User
from app.services.icmp import ping as icmp_ping
from app.models.device_port import DevicePort
from app.models.metric import Metric
from app.models.scan_job import ScanJob
from app.models.script_job import ScriptJob
from app.models.vulnerability import Vulnerability, VulnerabilitySeverity
from app.services.device_discovery import run_device_discovery
from app.services.device_enrichment import scan_device_ports, upsert_device_ports
from app.services.oui import is_locally_administered
from app.services.os_fingerprint import resolve_device_os

# Device and topology endpoints. In this personal deployment, they are
# available to any authenticated user.
router = APIRouter()


class DeviceOut(BaseModel):
    id: int
    hostname: Optional[str]
    ip_address: str
    mac_address: Optional[str]
    device_type: Optional[str]
    os: Optional[str] = None
    vendor: Optional[str] = None
    is_gateway: bool
    zone: Optional[str]
    last_seen: Optional[datetime]
    created_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class ScannedPortOut(BaseModel):
    """A listening port recorded by a per-device deep scan."""

    port: int
    protocol: str
    state: Optional[str] = None
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None

    class Config:
        from_attributes = True


class ScanSummary(BaseModel):
    """A scan job that targeted this device's address."""

    id: str
    profile: str
    target: str
    status: str
    created_at: datetime
    completed_at: Optional[datetime] = None


class DiscoverRequest(BaseModel):
    """Target for a discovery-only sweep."""

    target: Optional[str] = Field(
        default=None,
        max_length=255,
        description="CIDR, IP or hostname to sweep. Omit to sweep the attached subnets.",
    )
    arp_timeout: float = Field(default=2.0, ge=0.5, le=30.0)
    host_timeout: int = Field(default=60, ge=5, le=600)


class DiscoveredHostOut(BaseModel):
    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    os: Optional[str] = None
    is_gateway: bool = False
    source: str = "arp"

    class Config:
        from_attributes = True


class DiscoveryResponse(BaseModel):
    """Result of a discovery-only sweep, including why it may be empty."""

    created: int
    updated: int
    subnets: List[str]
    methods: List[str]
    skipped_restricted: List[str]
    warnings: List[str]
    hosts: List[DiscoveredHostOut]


class DeepScanResponse(BaseModel):
    device_id: int
    ip_address: str
    created: int
    updated: int
    removed: int
    ports: List[ScannedPortOut]
    warnings: List[str]
    os: Optional[str] = None
    os_confidence: Optional[str] = None


class TopologyNode(BaseModel):
    id: int
    label: str
    ip_address: str
    hostname: Optional[str]
    device_type: Optional[str]
    is_gateway: bool
    zone: Optional[str]
    vulnerability_severity: Optional[str]
    vulnerability_count: int
    last_seen: Optional[datetime]


class TopologyEdge(BaseModel):
    source: int
    target: int
    kind: str = "l3"


class TopologyResponse(BaseModel):
    nodes: List[TopologyNode]
    edges: List[TopologyEdge]


class ZoneListResponse(BaseModel):
    zones: List[str]


class VulnerabilitySummary(BaseModel):
    id: int
    title: str
    severity: str
    port: Optional[int]
    detected_at: Optional[datetime]


class ScriptJobSummary(BaseModel):
    id: int
    script_name: str
    status: str
    created_at: datetime


class MetricSummary(BaseModel):
    metric_type: str
    timestamp: datetime
    value: float
    tags: Optional[Dict[str, Any]] = None


class DeviceDetail(BaseModel):
    device: DeviceOut
    type_guess: Optional[str]
    type_confidence: Optional[float]
    vulnerability_counts: Dict[str, int] = {}
    vulnerabilities: List[VulnerabilitySummary]
    ports: List[ScannedPortOut]
    scripts: List[ScriptJobSummary]
    scans: List[ScanSummary]
    metrics: List[MetricSummary]


@router.get(
    "",
    response_model=List[DeviceOut],
    summary="List discovered devices",
    dependencies=[Depends(require_compliance_role())],
)
async def list_devices(
    db: AsyncSession = Depends(db_session),
    zone: Optional[str] = Query(None, description="Filter devices by zone label"),
) -> List[DeviceOut]:
    """Return discovered devices, optionally filtered by zone."""
    stmt = select(Device)
    if zone:
        stmt = stmt.where(Device.zone == zone)
    result = await db.execute(stmt)
    devices = result.scalars().all()
    return [DeviceOut.from_orm(d) for d in devices]


@router.post(
    "/discover",
    response_model=DiscoveryResponse,
    summary="Discover devices only (no port scanning)",
    dependencies=[Depends(require_scan_role())],
)
async def discover_devices(
    payload: DiscoverRequest,
    db: AsyncSession = Depends(db_session),
) -> DiscoveryResponse:
    """Sweep for hosts and record them in the device inventory.

    Discovery only — no port scans, no NSE scripts. Omit ``target`` to sweep the
    directly attached subnets. Restricted/fragile VLANs are refused rather than
    probed, and anything skipped is reported back in ``skipped_restricted`` so
    an empty result is never ambiguous.
    """
    try:
        outcome = await run_device_discovery(
            db,
            target=payload.target,
            arp_timeout=payload.arp_timeout,
            host_timeout=payload.host_timeout,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    return DiscoveryResponse(
        created=outcome.created,
        updated=outcome.updated,
        subnets=outcome.subnets,
        methods=outcome.methods,
        skipped_restricted=outcome.skipped_restricted,
        warnings=outcome.warnings,
        hosts=[
            DiscoveredHostOut.model_validate(host, from_attributes=True)
            for host in outcome.hosts
        ],
    )


@router.get(
    "/zones",
    response_model=ZoneListResponse,
    summary="List distinct device zones",
    dependencies=[Depends(require_compliance_role())],
)
async def list_zones(db: AsyncSession = Depends(db_session)) -> ZoneListResponse:
    """
    Return a list of distinct non-empty zone labels present in the Device table.
    """
    result = await db.execute(select(Device.zone).distinct())
    zones_raw = [row[0] for row in result.fetchall()]
    zones = sorted({z for z in zones_raw if z})
    return ZoneListResponse(zones=zones)


@router.get(
    "/topology",
    response_model=TopologyResponse,
    summary="Get a simple device topology for visualization",
    dependencies=[Depends(require_compliance_role())],
)
async def get_topology(
    db: AsyncSession = Depends(db_session),
    zone: Optional[str] = Query(None, description="Filter topology by zone label"),
) -> TopologyResponse:
    """Return a minimal topology view for the Eye panel's graph."""
    stmt = select(Device)
    if zone:
        stmt = stmt.where(Device.zone == zone)
    result = await db.execute(stmt)
    devices = result.scalars().all()

    if not devices:
        return TopologyResponse(nodes=[], edges=[])

    # Basic severity aggregation per device
    severity_rank = {
        VulnerabilitySeverity.INFO: 0,
        VulnerabilitySeverity.LOW: 1,
        VulnerabilitySeverity.MEDIUM: 2,
        VulnerabilitySeverity.HIGH: 3,
        VulnerabilitySeverity.CRITICAL: 4,
    }

    # Aggregate findings per device in one query. Reading ``d.vulnerabilities``
    # here would trigger an implicit lazy load, which async SQLAlchemy raises on.
    severity_result = await db.execute(
        select(
            Vulnerability.device_id,
            Vulnerability.severity,
            func.count(Vulnerability.id),
        ).group_by(Vulnerability.device_id, Vulnerability.severity)
    )
    severity_by_device: dict[int, dict[VulnerabilitySeverity, int]] = {}
    for owner_id, severity, count in severity_result.all():
        severity_by_device.setdefault(owner_id, {})[severity] = int(count)

    nodes: list[TopologyNode] = []

    for d in devices:
        counts = severity_by_device.get(d.id, {})
        max_sev: Optional[VulnerabilitySeverity] = (
            max(counts, key=lambda s: severity_rank.get(s, 0)) if counts else None
        )
        vuln_count = sum(counts.values())

        nodes.append(
            TopologyNode(
                id=d.id,
                label=d.hostname or d.ip_address,
                ip_address=d.ip_address,
                hostname=d.hostname,
                device_type=d.device_type,
                is_gateway=d.is_gateway,
                zone=d.zone,
                vulnerability_severity=max_sev.value if max_sev else None,
                vulnerability_count=vuln_count,
                last_seen=d.last_seen,
            )
        )

    device_ip_to_id = {d.ip_address: d.id for d in devices}
    edges: list[TopologyEdge] = []

    # Attempt to load discovered topology links from metrics
    try:
        from app.models.metric import Metric
        link_stmt = select(Metric).where(Metric.metric_type == "topology_link")
        link_result = await db.execute(link_stmt)
        link_metrics = link_result.scalars().all()
        seen_links = set()
        for lm in link_metrics:
            tags = lm.tags or {}
            src_ip = tags.get("source_ip")
            tgt_ip = tags.get("target_ip")
            if src_ip in device_ip_to_id and tgt_ip in device_ip_to_id:
                link_key = tuple(sorted([device_ip_to_id[src_ip], device_ip_to_id[tgt_ip]]))
                if link_key not in seen_links:
                    seen_links.add(link_key)
                    edges.append(
                        TopologyEdge(
                            source=device_ip_to_id[src_ip],
                            target=device_ip_to_id[tgt_ip],
                            kind=tags.get("kind", "l2"),
                        )
                    )
    except Exception:
        pass

    # Fallback to star topology if no links discovered
    if not edges:
        gateway = next((d for d in devices if d.is_gateway), devices[0])
        for d in devices:
            if d.id == gateway.id:
                continue
            edges.append(TopologyEdge(source=gateway.id, target=d.id, kind="l3"))

    return TopologyResponse(nodes=nodes, edges=edges)


def _guess_device_type(device: Device) -> tuple[Optional[str], Optional[float]]:
    """
    Heuristic type guess based on hostname, vendor and device_type.

    This is intentionally simple but useful for a personal console:
    - Hostname hints like 'iphone', 'android', 'tv', 'nas', 'printer'.
    - Vendor hints from MAC OUI (if populated).
    - Existing device_type hints (router/switch/etc.).
    """
    hostname = (device.hostname or "").lower()
    vendor = (device.vendor or "").lower()
    dtype = (device.device_type or "").lower()

    # Router / switch hints
    if any(k in dtype for k in ["router", "gateway", "firewall"]):
        return "router", 0.9
    if any(k in dtype for k in ["switch"]):
        return "switch", 0.9

    # TV / media
    tv_keywords = ["tv", "roku", "chromecast", "firetv"]
    if any(k in hostname for k in tv_keywords) or any(k in vendor for k in tv_keywords):
        return "smart-tv", 0.8

    # Phone / tablet
    phone_keywords = ["iphone", "ipad", "android", "pixel", "galaxy"]
    if any(k in hostname for k in phone_keywords) or any(k in vendor for k in ["samsung", "apple", "xiaomi", "oneplus"]):
        return "phone-tablet", 0.7

    # Printer
    if "printer" in hostname or any(k in vendor for k in ["hp", "epson", "canon", "brother"]):
        return "printer", 0.8

    # NAS / storage
    if any(k in hostname for k in ["nas", "storage"]) or any(k in vendor for k in ["synology", "qnap"]):
        return "nas", 0.8

    # Laptop/desktop hints
    if any(k in hostname for k in ["pc", "laptop", "desktop", "notebook"]) or "intel" in vendor:
        return "workstation", 0.6

    # Fallback to existing type if present
    if dtype:
        return dtype, 0.5

    return None, None


@router.get(
    "/{device_id}/detail",
    response_model=DeviceDetail,
    summary="Get detailed view of a device (vulns, scripts, metrics)",
    dependencies=[Depends(require_compliance_role())],
)
async def get_device_detail(
    device_id: int,
    db: AsyncSession = Depends(db_session),
) -> DeviceDetail:
    """Return a small bundle of information for the Device Detail drawer.

    Includes:
      - Device core fields (plus zone).
      - A simple heuristic type guess.
      - Recent vulnerabilities and script jobs.
      - A minimal metric snapshot for context.
    """
    device = await db.get(Device, device_id)
    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    # Vulnerabilities (up to 5, newest first)
    vuln_result = await db.execute(
        select(Vulnerability)
        .where(Vulnerability.device_id == device_id)
        .order_by(Vulnerability.detected_at.desc())
        .limit(5)
    )
    vulns = vuln_result.scalars().all()

    vuln_summaries = [
        VulnerabilitySummary(
            id=v.id,
            title=v.title,
            severity=v.severity.value,
            port=v.port,
            detected_at=v.detected_at,
        )
        for v in vulns
    ]

    # Recent scripts executed against this device (up to 5)
    script_result = await db.execute(
        select(ScriptJob)
        .where(ScriptJob.device_id == device_id)
        .order_by(ScriptJob.created_at.desc())
        .limit(5)
    )
    scripts = script_result.scalars().all()
    script_summaries = [
        ScriptJobSummary(
            id=s.id,
            script_name=s.script_name,
            status=s.status.value,
            created_at=s.created_at,
        )
        for s in scripts
    ]

    # Listening ports recorded by the last deep scan of this device. Queried
    # explicitly rather than through ``device.ports``: async SQLAlchemy cannot
    # lazy-load a relationship implicitly.
    port_result = await db.execute(
        select(DevicePort)
        .where(DevicePort.device_id == device_id)
        .order_by(DevicePort.protocol, DevicePort.port)
    )
    ports = [ScannedPortOut.model_validate(p, from_attributes=True) for p in port_result.scalars().all()]

    # Severity totals across all findings, not just the newest five.
    count_result = await db.execute(
        select(Vulnerability.severity, func.count(Vulnerability.id))
        .where(Vulnerability.device_id == device_id)
        .group_by(Vulnerability.severity)
    )
    vulnerability_counts = {
        (severity.value if hasattr(severity, "value") else str(severity)): int(count)
        for severity, count in count_result.all()
    }

    # Scan jobs that targeted this device's address.
    scan_result = await db.execute(
        select(ScanJob)
        .where(ScanJob.target == device.ip_address)
        .order_by(ScanJob.created_at.desc())
        .limit(5)
    )
    scans = [
        ScanSummary(
            id=job.id,
            profile=job.profile,
            target=job.target,
            status=job.status.value,
            created_at=job.created_at,
            completed_at=job.completed_at,
        )
        for job in scan_result.scalars().all()
    ]

    # Recent metrics scoped to THIS device. Previously this queried a single
    # global "internet_health" sample without any device_id filter, so every
    # device reported the same number as its own metric.
    metric_result = await db.execute(
        select(Metric)
        .where(Metric.device_id == device_id)
        .order_by(Metric.timestamp.desc())
        .limit(12)
    )
    device_metrics = metric_result.scalars().all()
    metrics: list[MetricSummary] = [
        MetricSummary(
            metric_type=m.metric_type,
            timestamp=m.timestamp,
            value=float(m.value),
            tags=m.tags or None,
        )
        for m in device_metrics
    ]

    type_guess, type_confidence = _guess_device_type(device)

    return DeviceDetail(
        device=DeviceOut.from_orm(device),
        type_guess=type_guess,
        type_confidence=type_confidence,
        vulnerability_counts=vulnerability_counts,
        vulnerabilities=vuln_summaries,
        ports=ports,
        scripts=script_summaries,
        scans=scans,
        metrics=metrics,
    )


@router.post(
    "/{device_id}/deep-scan",
    response_model=DeepScanResponse,
    summary="Scan one known device for listening ports and services",
    dependencies=[Depends(require_scan_role())],
)
async def deep_scan_device(
    device_id: int,
    db: AsyncSession = Depends(db_session),
) -> DeepScanResponse:
    """Run a targeted service/version scan against a single device.

    The opt-in second step after discovery: it fills in the ports and services
    the light sweep deliberately ignores. Results replace the device's stored
    port set, so the detail view reflects what is listening now.
    """
    device = await db.get(Device, device_id)
    if device is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Device not found",
        )

    observations, warnings = await scan_device_ports(device.ip_address)

    created = updated = removed = 0
    if observations or not warnings:
        # A clean scan that found nothing listening is a real result and should
        # clear stale rows. A scan that could not run (no nmap, restricted
        # subnet, failure) leaves the previously stored ports untouched.
        created, updated, removed = await upsert_device_ports(db, device.id, observations)

    # Operating system. nmap's stack fingerprint is the strongest answer
    # available; without nmap we fall back to the hostname, vendor and port
    # signatures already known about this host rather than guessing.
    os_label: Optional[str] = None
    os_confidence: Optional[str] = None
    try:
        os_label, os_confidence = await asyncio.to_thread(
            resolve_device_os,
            ip_address=device.ip_address,
            hostname=device.hostname,
            vendor=device.vendor,
            open_ports=[obs.port for obs in observations if obs.state == "open"],
            mac_randomised=is_locally_administered(device.mac_address),
        )
    except Exception as exc:  # noqa: BLE001 - fingerprinting must not fail the scan
        warnings.append(f"OS detection failed: {exc}")

    if os_label:
        device.os = os_label
        device.updated_at = datetime.utcnow()
        await db.commit()

    return DeepScanResponse(
        device_id=device.id,
        ip_address=device.ip_address,
        created=created,
        updated=updated,
        removed=removed,
        ports=[
            ScannedPortOut.model_validate(observation, from_attributes=True)
            for observation in observations
        ],
        warnings=warnings,
        os=os_label,
        os_confidence=os_confidence,
    )


class SwitchConfigResponse(BaseModel):
    filename: str
    size_bytes: int
    modified_at: datetime
    content_preview: Optional[str] = None


@router.get(
    "/{device_id}/configs",
    response_model=List[SwitchConfigResponse],
    summary="Get backups/configs for a specific switch/router",
    dependencies=[Depends(require_compliance_role())],
)
async def get_device_configs(
    device_id: int,
    db: AsyncSession = Depends(db_session),
) -> List[SwitchConfigResponse]:
    device = await db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")

    search_paths = [Path("/data/backups"), Path("data/backups")]
    found_files = []

    prefixes = []
    if device.hostname:
        prefixes.append(device.hostname)
    prefixes.append(device.ip_address)

    for base_path in search_paths:
        if base_path.exists() and base_path.is_dir():
            for p in base_path.glob("*.cfg"):
                name = p.name
                if any(name.startswith(f"{prefix}-") for prefix in prefixes):
                    stat = p.stat()
                    preview = ""
                    try:
                        with open(p, "r", encoding="utf-8", errors="ignore") as f:
                            preview = "".join(f.readline() for _ in range(5))
                    except Exception:
                        pass
                    found_files.append(
                        SwitchConfigResponse(
                            filename=p.name,
                            size_bytes=stat.st_size,
                            modified_at=datetime.fromtimestamp(stat.st_mtime),
                            content_preview=preview,
                        )
                    )

    found_files.sort(key=lambda x: x.modified_at, reverse=True)
    return found_files


@router.get(
    "/{device_id}/configs/{filename}",
    summary="Download/View a specific backup configuration file",
    dependencies=[Depends(require_compliance_role())],
)
async def get_device_config_content(
    device_id: int,
    filename: str,
    db: AsyncSession = Depends(db_session),
):
    device = await db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")

    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    search_paths = [Path("/data/backups"), Path("data/backups")]
    for base_path in search_paths:
        filepath = base_path / filename
        if filepath.exists() and filepath.is_file():
            return FileResponse(filepath, media_type="text/plain")

    raise HTTPException(status_code=404, detail="Configuration file not found")


# ---------------------------------------------------------------------------
# Ping status
# ---------------------------------------------------------------------------
# The dashboard's reachability panel used to derive "online" purely from the
# last_seen timestamp, which said nothing about whether the host answers now.
# This endpoint asks the hosts directly: one ICMP packet each, in parallel,
# with a short timeout so the dashboard stays responsive.

SLOW_PING_MS = 100.0
_PING_CONCURRENCY = 8


def _classify_ping(latency_ms: float | None, reachable: bool) -> str:
    if not reachable:
        return "down"
    if latency_ms is None:
        return "up"
    return "slow" if latency_ms > SLOW_PING_MS else "up"


@router.get(
    "/ping-status",
    summary="ICMP-ping the most recently seen devices and classify each answer",
)
async def get_ping_status(
    limit: int = Query(12, ge=1, le=64),
    db: AsyncSession = Depends(db_session),
    _user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Ping a slice of the inventory right now.

    Results are ordered by last_seen (most recent first) so the dashboard shows
    the devices the operator most plausibly cares about. One packet per host:
    this is a health probe, not a scan.
    """
    result = await db.execute(
        select(Device)
        .order_by(Device.last_seen.desc().nullslast(), Device.id.asc())
        .limit(limit)
    )
    devices = list(result.scalars().all())

    semaphore = asyncio.Semaphore(_PING_CONCURRENCY)

    async def _probe(device: Device) -> Dict[str, Any]:
        async with semaphore:
            outcome = await icmp_ping(device.ip_address, count=1, timeout_s=1.0)
        return {
            "id": device.id,
            "hostname": device.hostname,
            "ip_address": device.ip_address,
            "status": _classify_ping(outcome.latency_ms, outcome.reachable),
            "latency_ms": outcome.latency_ms,
            "last_seen": device.last_seen.isoformat() if device.last_seen else None,
            "error": outcome.error,
        }

    results = list(await asyncio.gather(*(_probe(device) for device in devices)))

    summary = {
        "up": sum(1 for r in results if r["status"] == "up"),
        "slow": sum(1 for r in results if r["status"] == "slow"),
        "down": sum(1 for r in results if r["status"] == "down"),
        "total": len(results),
    }

    return {
        "checked_at": datetime.utcnow().isoformat(),
        "summary": summary,
        "results": results,
    }
