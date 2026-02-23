from __future__ import annotations

import asyncio
import ipaddress
import re
from datetime import datetime, timedelta
from typing import List, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import delete, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, require_admin, require_role

from app.models.uptime import UptimeCheck, UptimeTarget

router = APIRouter(prefix="/uptime", tags=["uptime"])

PING_TARGET_PATTERN = re.compile(
    r"^(?=.{1,255}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


def _validate_ping_target(target: str) -> bool:
    if not target or len(target) > 255:
        return False
    if target.startswith("-"):
        return False
    if any(ch.isspace() for ch in target):
        return False

    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return bool(PING_TARGET_PATTERN.match(target))


class UptimeTargetCreate(BaseModel):
    name: str
    target: str
    check_type: str = "ping"
    interval_seconds: int = 60


class UptimeTargetResponse(BaseModel):
    id: int
    name: str
    target: str
    check_type: str
    interval_seconds: int
    is_active: bool
    last_status: Optional[str] = None
    last_checked_at: Optional[str] = None
    last_latency_ms: Optional[float] = None
    consecutive_failures: int = 0

    class Config:
        from_attributes = True


class UptimeCheckResponse(BaseModel):
    id: int
    target_id: int
    timestamp: str
    status: str
    latency_ms: Optional[float] = None
    status_code: Optional[int] = None
    error_message: Optional[str] = None

    class Config:
        from_attributes = True


class UptimeSummary(BaseModel):
    total_targets: int
    targets_up: int
    targets_down: int
    targets_degraded: int
    targets: List[UptimeTargetResponse]


@router.get(
    "",
    response_model=UptimeSummary,
    dependencies=[Depends(require_role())],
)
async def get_uptime_summary(db: AsyncSession = Depends(db_session)) -> UptimeSummary:
    result = await db.execute(select(UptimeTarget).order_by(UptimeTarget.name))
    targets = list(result.scalars().all())

    target_responses = []
    up = down = degraded = 0
    for t in targets:
        status = t.last_status or "unknown"
        if status == "up":
            up += 1
        elif status == "down":
            down += 1
        elif status == "degraded":
            degraded += 1
        target_responses.append(UptimeTargetResponse(
            id=t.id,
            name=t.name,
            target=t.target,
            check_type=t.check_type,
            interval_seconds=t.interval_seconds,
            is_active=t.is_active,
            last_status=t.last_status,
            last_checked_at=t.last_checked_at.isoformat() if t.last_checked_at else None,
            last_latency_ms=t.last_latency_ms,
            consecutive_failures=t.consecutive_failures,
        ))

    return UptimeSummary(
        total_targets=len(targets),
        targets_up=up,
        targets_down=down,
        targets_degraded=degraded,
        targets=target_responses,
    )


@router.post(
    "",
    response_model=UptimeTargetResponse,
    dependencies=[Depends(require_admin)],
)
async def create_uptime_target(
    body: UptimeTargetCreate,
    db: AsyncSession = Depends(db_session),
) -> UptimeTargetResponse:
    if body.check_type not in ("ping", "http"):
        raise HTTPException(status_code=400, detail="check_type must be 'ping' or 'http'")
    if body.interval_seconds < 10:
        raise HTTPException(status_code=400, detail="interval_seconds must be >= 10")
    if body.check_type == "ping" and not _validate_ping_target(body.target):
        raise HTTPException(status_code=400, detail="Invalid ping target")

    target = UptimeTarget(
        name=body.name,
        target=body.target,
        check_type=body.check_type,
        interval_seconds=body.interval_seconds,
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)

    return UptimeTargetResponse(
        id=target.id,
        name=target.name,
        target=target.target,
        check_type=target.check_type,
        interval_seconds=target.interval_seconds,
        is_active=target.is_active,
        last_status=target.last_status,
        last_checked_at=None,
        last_latency_ms=target.last_latency_ms,
        consecutive_failures=target.consecutive_failures,
    )


@router.delete(
    "/{target_id}",
    dependencies=[Depends(require_admin)],
)
async def delete_uptime_target(
    target_id: int,
    db: AsyncSession = Depends(db_session),
) -> dict:
    await db.execute(delete(UptimeCheck).where(UptimeCheck.target_id == target_id))
    result = await db.execute(delete(UptimeTarget).where(UptimeTarget.id == target_id))
    await db.commit()
    if result.rowcount == 0:
        raise HTTPException(status_code=404, detail="Target not found")
    return {"status": "deleted"}


@router.get(
    "/{target_id}/history",
    response_model=List[UptimeCheckResponse],
    dependencies=[Depends(require_role())],
)
async def get_uptime_history(
    target_id: int,
    limit: int = 100,
    db: AsyncSession = Depends(db_session),
) -> List[UptimeCheckResponse]:
    result = await db.execute(
        select(UptimeCheck)
        .where(UptimeCheck.target_id == target_id)
        .order_by(UptimeCheck.timestamp.desc())
        .limit(min(limit, 500))
    )
    checks = list(result.scalars().all())
    return [
        UptimeCheckResponse(
            id=c.id,
            target_id=c.target_id,
            timestamp=c.timestamp.isoformat(),
            status=c.status,
            latency_ms=c.latency_ms,
            status_code=c.status_code,
            error_message=c.error_message,
        )
        for c in checks
    ]


@router.post(
    "/{target_id}/check",
    response_model=UptimeCheckResponse,
    dependencies=[Depends(require_admin)],
)
async def run_manual_check(
    target_id: int,
    db: AsyncSession = Depends(db_session),
) -> UptimeCheckResponse:
    result = await db.execute(select(UptimeTarget).where(UptimeTarget.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    check = await _perform_check(target)
    db.add(check)

    target.last_status = check.status
    target.last_checked_at = check.timestamp
    target.last_latency_ms = check.latency_ms
    if check.status == "up":
        target.consecutive_failures = 0
    else:
        target.consecutive_failures += 1

    await db.commit()
    await db.refresh(check)

    return UptimeCheckResponse(
        id=check.id,
        target_id=check.target_id,
        timestamp=check.timestamp.isoformat(),
        status=check.status,
        latency_ms=check.latency_ms,
        status_code=check.status_code,
        error_message=check.error_message,
    )


async def _perform_check(target: UptimeTarget) -> UptimeCheck:
    now = datetime.utcnow()

    if target.check_type == "http":
        return await _http_check(target, now)
    else:
        return await _ping_check(target, now)


async def _ping_check(target: UptimeTarget, now: datetime) -> UptimeCheck:
    if not _validate_ping_target(target.target):
        return UptimeCheck(
            target_id=target.id,
            timestamp=now,
            status="down",
            error_message="Invalid ping target",
        )

    try:
        process = await asyncio.create_subprocess_exec(
            "ping", "-c", "3", "-W", "2", target.target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await asyncio.wait_for(process.communicate(), timeout=10)

        if process.returncode != 0:
            return UptimeCheck(
                target_id=target.id,
                timestamp=now,
                status="down",
                error_message="Ping failed (no response)",
            )

        latencies = []
        for line in stdout.decode().splitlines():
            if "time=" in line:
                try:
                    time_part = line.split("time=")[1]
                    ms_str = time_part.split()[0]
                    latencies.append(float(ms_str))
                except (IndexError, ValueError):
                    continue

        avg_latency = sum(latencies) / len(latencies) if latencies else None
        status = "up"
        if avg_latency and avg_latency > 200:
            status = "degraded"

        return UptimeCheck(
            target_id=target.id,
            timestamp=now,
            status=status,
            latency_ms=avg_latency,
        )
    except asyncio.TimeoutError:
        return UptimeCheck(
            target_id=target.id,
            timestamp=now,
            status="down",
            error_message="Ping timed out",
        )
    except Exception as e:
        return UptimeCheck(
            target_id=target.id,
            timestamp=now,
            status="down",
            error_message=str(e)[:500],
        )


async def _http_check(target: UptimeTarget, now: datetime) -> UptimeCheck:
    url = target.target
    if not url.startswith("http"):
        url = f"http://{url}"

    try:
        async with httpx.AsyncClient(timeout=10.0, verify=False) as client:
            import time
            start = time.monotonic()
            response = await client.get(url, follow_redirects=True)
            elapsed = (time.monotonic() - start) * 1000

            status = "up"
            if response.status_code >= 500:
                status = "down"
            elif response.status_code >= 400:
                status = "degraded"
            elif elapsed > 2000:
                status = "degraded"

            return UptimeCheck(
                target_id=target.id,
                timestamp=now,
                status=status,
                latency_ms=round(elapsed, 1),
                status_code=response.status_code,
            )
    except Exception as e:
        return UptimeCheck(
            target_id=target.id,
            timestamp=now,
            status="down",
            error_message=str(e)[:500],
        )
