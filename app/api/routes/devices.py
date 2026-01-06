from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, require_role
from app.models.device import Device
from app.models.metric import Metric
from app.models.script_job import ScriptJob
from app.models.vulnerability import Vulnerability, VulnerabilitySeverity

# Device and topology endpoints. In this personal deployment, they are
# available to any authenticated user.
router = APIRouter()


class DeviceOut(BaseModel):
    id: int
    hostname: Optional[str]
    ip_address: str
    mac_address: Optional[str]
    device_type: Optional[str]
    is_gateway: bool
    zone: Optional[str]
    last_seen: Optional[datetime]

    class Config:
        orm_mode = True


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


class DeviceDetail(BaseModel):
    device: DeviceOut
    vulnerabilities: List[VulnerabilitySummary]
    scripts: List[ScriptJobSummary]
    metrics: List[MetricSummary]


@router.get(
    "",
    response_model=List[DeviceOut],
    summary="List discovered devices",
    dependencies=[Depends(require_role())],
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


@router.get(
    "/zones",
    response_model=ZoneListResponse,
    summary="List distinct device zones",
    dependencies=[Depends(require_role())],
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
    dependencies=[Depends(require_role())],
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

    nodes: list[TopologyNode] = []

    for d in devices:
        max_sev: Optional[VulnerabilitySeverity] = None
        if d.vulnerabilities:
            max_sev = max(
                (v.severity for v in d.vulnerabilities),
                key=lambda s: severity_rank.get(s, 0),
            )
        vuln_count = len(d.vulnerabilities or [])

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

    # Simple "star" topology: connect everything to gateway if present,
    # otherwise to the first device.
    gateway = next((d for d in devices if d.is_gateway), devices[0])
    edges: list[TopologyEdge] = []

    for d in devices:
        if d.id == gateway.id:
            continue
        edges.append(TopologyEdge(source=gateway.id, target=d.id, kind="l3"))

    return TopologyResponse(nodes=nodes, edges=edges)


@router.get(
    "/{device_id}/detail",
    response_model=DeviceDetail,
    summary="Get detailed view of a device (vulns, scripts, metrics)",
    dependencies=[Depends(require_role(UserRole.VIEWER, UserRole.OPERATOR, UserRole.ADMIN))],
)
async def get_device_detail(
    device_id: int,
    db: AsyncSession = Depends(db_session),
) -> DeviceDetail:
    """Return a small bundle of information for the Device Detail drawer.

    This is intentionally compact: a handful of vulnerabilities, recent
    scripts, and a simple global metric snapshot for context.
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

    # Simple global metric snapshot for context: latest internet_health metric.
    metric_result = await db.execute(
        select(Metric)
        .where(Metric.metric_type == "internet_health")
        .order_by(Metric.timestamp.desc())
        .limit(1)
    )
    metric = metric_result.scalar_one_or_none()
    metrics: list[MetricSummary] = []
    if metric is not None:
        metrics.append(
            MetricSummary(
                metric_type=metric.metric_type,
                timestamp=metric.timestamp,
                value=float(metric.value),
            )
        )

    return DeviceDetail(
        device=DeviceOut.from_orm(device),
        vulnerabilities=vuln_summaries,
        scripts=script_summaries,
        metrics=metrics,
    )