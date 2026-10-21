"""Network insight endpoints.

Two read-mostly helpers used by the Diagnostics and Toolbox views:

* ``POST /insights/tcp-probe`` — is a host listening on a port, and how fast?
  A plain TCP connect with a bounded timeout. This is the least invasive probe
  the app has: no packet crafting, no service fingerprinting.
* ``GET /insights/health`` — a one-glance summary of fleet health, assembled
  from the device inventory and unresolved findings.

Definitions are stated explicitly rather than implied, because "healthy" and
"online" are only meaningful once they are pinned down:

* A device counts as **online** when discovery has seen it within
  ``ONLINE_WINDOW_MINUTES``. It is a recency-of-observation signal, not a live
  ping — nothing here probes the fleet.
* A finding is **critical** when its severity is critical or high, and a
  **warning** when medium. Low and info findings are recorded but do not move
  the score.
"""
from __future__ import annotations

import asyncio
import time
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, require_compliance_role, require_scan_role
from app.models.device import Device
from app.models.vulnerability import Vulnerability, VulnerabilitySeverity
from app.services.scan_policy import validate_target

router = APIRouter()

# Recency window for the "online" label. 15 minutes is a little over two
# discovery cycles, so a single missed sweep does not mark a host offline.
ONLINE_WINDOW_MINUTES = 15
DEFAULT_PROBE_TIMEOUT = 3.0
MAX_BOTTLENECKS = 5

# Ordering key: lower is worse.
SEVERITY_RANK: Dict[VulnerabilitySeverity, int] = {
    VulnerabilitySeverity.CRITICAL: 0,
    VulnerabilitySeverity.HIGH: 1,
    VulnerabilitySeverity.MEDIUM: 2,
    VulnerabilitySeverity.LOW: 3,
    VulnerabilitySeverity.INFO: 4,
}

RECOMMENDATIONS: Dict[str, str] = {
    "critical": "Patch or isolate this host: unresolved critical or high findings.",
    "high": "Patch or restrict access to the affected service.",
    "medium": "Schedule remediation for the affected service.",
}


def bucket_for_severity(severity: VulnerabilitySeverity) -> Optional[str]:
    """Map a finding severity onto one of the two health buckets."""
    if severity in (VulnerabilitySeverity.CRITICAL, VulnerabilitySeverity.HIGH):
        return "critical"
    if severity == VulnerabilitySeverity.MEDIUM:
        return "warning"
    return None


def recommendation_for(severity: VulnerabilitySeverity) -> str:
    """A one-line next step for the worst finding on a host."""
    return RECOMMENDATIONS.get(severity.value, "Review this host.")


def compute_health_score(
    *,
    critical_issues: int,
    warning_issues: int,
    offline_ratio: float,
) -> int:
    """Score 0-100 from findings and reachability.

    Deductions are deliberately capped so a single category cannot drive the
    score to zero on its own — the number stays informative instead of
    saturating.
    """
    score = 100.0
    score -= min(critical_issues * 8, 60)
    score -= min(warning_issues * 2, 20)
    score -= min(max(offline_ratio, 0.0), 1.0) * 20
    return max(0, min(100, int(round(score))))


def health_status_for(score: int) -> str:
    """Coarse label for a health score."""
    if score >= 85:
        return "healthy"
    if score >= 60:
        return "degraded"
    return "critical"


class TcpProbeRequest(BaseModel):
    host: str = Field(min_length=1, max_length=255, description="Hostname or IP address")
    port: int = Field(ge=1, le=65535)
    timeout_s: float = Field(default=DEFAULT_PROBE_TIMEOUT, ge=0.2, le=30.0)


class TcpProbeResponse(BaseModel):
    host: str
    port: int
    latency_ms: Optional[float] = None
    error: Optional[str] = None


class Bottleneck(BaseModel):
    device_id: int
    hostname: str
    ip_address: str
    device_type: str
    issues: List[str]
    severity: str
    recommendation: str


class NetworkHealth(BaseModel):
    status: str
    health_score: int
    total_devices: int
    online_devices: int
    offline_devices: int
    critical_issues: int
    warning_issues: int
    bottlenecks: List[Bottleneck]
    last_updated: str
    # Included so the UI (and anyone reading the API) can see what "online"
    # actually means rather than having to guess.
    online_window_minutes: int = ONLINE_WINDOW_MINUTES


async def _probe_tcp(host: str, port: int, timeout_s: float) -> tuple[Optional[float], Optional[str]]:
    """Open a TCP connection and time it. Never raises."""
    started = time.perf_counter()
    try:
        _reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout_s,
        )
    except asyncio.TimeoutError:
        return None, f"Timed out after {timeout_s:g}s"
    except OSError as exc:
        return None, str(exc) or exc.__class__.__name__
    except Exception as exc:  # noqa: BLE001 - reported to the caller, not raised
        return None, str(exc) or exc.__class__.__name__

    latency_ms = round((time.perf_counter() - started) * 1000, 2)
    writer.close()
    with suppress(Exception):
        await writer.wait_closed()
    return latency_ms, None


@router.post(
    "/tcp-probe",
    response_model=TcpProbeResponse,
    summary="Check whether a host is listening on a port",
    dependencies=[Depends(require_scan_role())],
)
async def tcp_probe(payload: TcpProbeRequest) -> TcpProbeResponse:
    """Time a single TCP connection attempt.

    A closed or filtered port is a normal answer, so failures come back as
    ``error`` with ``latency_ms: null`` rather than as an HTTP error. Only a
    malformed host is rejected outright.
    """
    host = payload.host.strip()
    if not validate_target(host) or "/" in host:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid host: supply a hostname or IP address",
        )

    latency_ms, error = await _probe_tcp(host, payload.port, payload.timeout_s)
    return TcpProbeResponse(host=host, port=payload.port, latency_ms=latency_ms, error=error)


@router.get(
    "/health",
    response_model=NetworkHealth,
    summary="Summarise fleet health from inventory and findings",
    dependencies=[Depends(require_compliance_role())],
)
async def network_health(db: AsyncSession = Depends(db_session)) -> NetworkHealth:
    """Fleet-level health summary.

    Read-only: it aggregates what discovery and scanning already recorded and
    probes nothing, so it is safe to poll.
    """
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(minutes=ONLINE_WINDOW_MINUTES)

    total_devices = int(
        (await db.execute(select(func.count()).select_from(Device))).scalar_one()
    )
    online_devices = int(
        (
            await db.execute(
                select(func.count())
                .select_from(Device)
                .where(Device.last_seen.is_not(None), Device.last_seen >= cutoff)
            )
        ).scalar_one()
    )
    offline_devices = max(total_devices - online_devices, 0)

    severity_rows = (
        await db.execute(
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .where(Vulnerability.is_resolved.is_(False))
            .group_by(Vulnerability.severity)
        )
    ).all()

    critical_issues = 0
    warning_issues = 0
    for severity, count in severity_rows:
        bucket = bucket_for_severity(severity)
        if bucket == "critical":
            critical_issues += int(count)
        elif bucket == "warning":
            warning_issues += int(count)

    # Explicit join rather than a relationship walk: async SQLAlchemy cannot
    # lazy-load, and this keeps it to one query.
    finding_rows = (
        await db.execute(
            select(Vulnerability, Device)
            .join(Device, Vulnerability.device_id == Device.id)
            .where(Vulnerability.is_resolved.is_(False))
            .limit(300)
        )
    ).all()

    grouped: Dict[int, Dict[str, Any]] = {}
    for vuln, device in finding_rows:
        if bucket_for_severity(vuln.severity) is None:
            continue
        entry = grouped.setdefault(
            device.id,
            {"device": device, "titles": [], "worst": vuln.severity, "count": 0},
        )
        entry["count"] += 1
        if len(entry["titles"]) < 3:
            entry["titles"].append(vuln.title)
        if SEVERITY_RANK[vuln.severity] < SEVERITY_RANK[entry["worst"]]:
            entry["worst"] = vuln.severity

    ordered = sorted(
        grouped.values(),
        key=lambda item: (SEVERITY_RANK[item["worst"]], -item["count"]),
    )

    bottlenecks = [
        Bottleneck(
            device_id=entry["device"].id,
            hostname=entry["device"].hostname or "",
            ip_address=entry["device"].ip_address,
            device_type=entry["device"].device_type or "unknown",
            issues=list(entry["titles"]),
            severity=entry["worst"].value,
            recommendation=recommendation_for(entry["worst"]),
        )
        for entry in ordered[:MAX_BOTTLENECKS]
    ]

    offline_ratio = (offline_devices / total_devices) if total_devices else 0.0
    score = compute_health_score(
        critical_issues=critical_issues,
        warning_issues=warning_issues,
        offline_ratio=offline_ratio,
    )

    return NetworkHealth(
        status=health_status_for(score),
        health_score=score,
        total_devices=total_devices,
        online_devices=online_devices,
        offline_devices=offline_devices,
        critical_issues=critical_issues,
        warning_issues=warning_issues,
        bottlenecks=bottlenecks,
        last_updated=now.isoformat(),
    )
