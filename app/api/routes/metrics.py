from __future__ import annotations

from datetime import datetime
from typing import List

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, require_role
from app.models.metric import Metric
from app.models.user import UserRole

router = APIRouter()


class MetricPoint(BaseModel):
    timestamp: datetime
    value: float


class InternetHealthResponse(BaseModel):
    points: List[MetricPoint]


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
    # Return oldest first so charts render left-to-right in time
    rows.reverse()

    points = [
        MetricPoint(timestamp=m.timestamp, value=float(m.value))
        for m in rows
    ]
    return InternetHealthResponse(points=points)