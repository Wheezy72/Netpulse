from __future__ import annotations

"""
Metrics-related API endpoints.

Exposes:
- internet_health_recent: time-series data for aggregate Internet Health.
- pulse_latest: latest per-target latency/jitter/loss snapshot for the Pulse panel.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, require_role
from app.core.config import settings
from app.models.metric import Metric
from app.models.user import UserRole

router = APIRouter()


class MetricPoint(BaseModel):
    timestamp: datetime
    value: float


class InternetHealthResponse(BaseModel):
    points: List[MetricPoint]


class PulseTargetSummary(BaseModel):
    target: str
    label: str
    latency_ms: Optional[float] = None
    jitter_ms: Optional[float] = None
    packet_loss_pct: Optional[float] = None


class PulseSummaryResponse(BaseModel):
    targets: List[PulseTargetSummary]


@router.get(
    "/internet-health-recent",
    response_model=InternetHealthResponse,
    summary="Return recent Internet Health metrics for the Pulse panel",
    dependencies=[Depends(require_role(UserRole.VIEWER, UserRole.OPERATOR, UserRole.ADMIN))],
)
async def internet_health_recent(
    db: AsyncSession = Depends(db_session),
    limit: int = 50,
) -> InternetHealthResponse:
    """Return the most recent Internet Health values (0–100)."""
    if limit <= 0 or limit > 500:
        limit = 50

    result = await db.execute(
        select(Metric)
        .where(Metric.metric_type == "internet_health")
        .order_by(Metric.timestamp.desc())
        .limit(limit)
    )
    rows = list(result.scalars().all())
    rows.reverse()

    points = [
        MetricPoint(timestamp=m.timestamp, value=float(m.value))
        for m in rows
    ]
    return InternetHealthResponse(points=points)


@router.get(
    "/pulse-latest",
    response_model=PulseSummaryResponse,
    summary="Return latest per-target latency/jitter/loss values for the Pulse panel",
    dependencies=[Depends(require_role(UserRole.VIEWER, UserRole.OPERATOR, UserRole.ADMIN))],
)
async def pulse_latest(
    db: AsyncSession = Depends(db_session),
) -> PulseSummaryResponse:
    """
    Return the latest latency, jitter and packet loss metrics per configured Pulse target.

    The metrics are derived from Metric rows with metric_type in:
      - latency_ms
      - jitter_ms
      - packet_loss_pct

    and tags containing {"target": "<ip>"}.
    """
    metric_types = {"latency_ms", "jitter_ms", "packet_loss_pct"}
    now = datetime.utcnow()
    window_start = now - timedelta(minutes=15)

    result = await db.execute(
        select(Metric)
        .where(
            Metric.metric_type.in_(metric_types),
            Metric.timestamp >= window_start,
        )
        .order_by(Metric.timestamp.desc())
    )
    rows = list(result.scalars().all())

    # Latest metric per (target, metric_type)
    latest: Dict[str, Dict[str, float]] = {}

    for m in rows:
        tags = m.tags or {}
        target = tags.get("target")
        if not target:
            continue
        per_target = latest.setdefault(target, {})
        if m.metric_type not in per_target:
            per_target[m.metric_type] = float(m.value)

    def _label_for_target(ip: str) -> str:
        if ip == settings.pulse_gateway_ip:
            return "Gateway"
        if ip == settings.pulse_isp_ip:
            return "ISP Edge"
        if ip == settings.pulse_cloudflare_ip:
            return "Cloudflare"
        return ip

    summaries: List[PulseTargetSummary] = []

    for target, metrics in latest.items():
        summaries.append(
            PulseTargetSummary(
                target=target,
                label=_label_for_target(target),
                latency_ms=metrics.get("latency_ms"),
                jitter_ms=metrics.get("jitter_ms"),
                packet_loss_pct=metrics.get("packet_loss_pct"),
            )
        )

    # Sort by label to keep display stable
    summaries.sort(key=lambda s: s.label.lower())
    return PulseSummaryResponse(targets=summaries)