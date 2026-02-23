from __future__ import annotations

"""WebSocket endpoints for live streams.

Provides:
- /api/ws/scripts/{job_id}: stream ScriptJob logs as JSON events.
- /api/ws/scans/{scan_id}: stream Nmap scan output as plain text frames (xterm).
- /api/ws/metrics: stream real-time dashboard metrics as JSON.
"""

import asyncio
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.db.session import async_session_factory
from app.models.metric import Metric
from app.models.scan_job import ScanJob, ScanJobStatus
from app.models.script_job import ScriptJob, ScriptJobStatus
from app.models.user import User

router = APIRouter()

metrics_clients: Set[WebSocket] = set()


async def _get_user_from_token(token: str, db: AsyncSession) -> User | None:
    """Decode a JWT and return the associated User, or None if invalid."""
    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
        )
    except JWTError:
        return None

    email = payload.get("sub")
    if not email:
        return None

    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


@router.websocket("/scripts/{job_id}")
async def websocket_script_logs(websocket: WebSocket, job_id: int) -> None:
    """Stream ScriptJob logs and status over WebSocket (JSON events)."""

    await websocket.accept()

    token = websocket.query_params.get("token")
    if not token:
        await websocket.send_json({"event": "error", "message": "Missing token"})
        await websocket.close(code=4401)
        return

    async with async_session_factory() as db:
        user = await _get_user_from_token(token, db)
        if user is None or not user.is_active:
            await websocket.send_json({"event": "error", "message": "Unauthorized"})
            await websocket.close(code=4401)
            return

        try:
            last_len = 0
            while True:
                result = await db.execute(select(ScriptJob).where(ScriptJob.id == job_id))
                job = result.scalar_one_or_none()
                if job is None:
                    await websocket.send_json(
                        {"event": "error", "message": "Script job not found"}
                    )
                    await websocket.close(code=4404)
                    return

                logs = job.logs or ""
                if len(logs) > last_len:
                    new_segment = logs[last_len:]
                    last_len = len(logs)
                    for line in new_segment.splitlines():
                        if line.strip():
                            await websocket.send_json(
                                {
                                    "event": "log",
                                    "message": line,
                                    "status": job.status.value,
                                }
                            )

                if job.status in {ScriptJobStatus.SUCCESS, ScriptJobStatus.FAILED}:
                    await websocket.send_json(
                        {"event": "complete", "status": job.status.value}
                    )
                    await websocket.close(code=1000)
                    return

                # End the read-only transaction so we see updates on the next poll.
                await db.rollback()
                await asyncio.sleep(1)
        except WebSocketDisconnect:
            return
        except Exception as exc:  # noqa: BLE001
            await websocket.send_json(
                {"event": "error", "message": f"Unexpected error: {exc!r}"}
            )
            await websocket.close(code=1011)


@router.websocket("/scans/{scan_id}")
async def websocket_scan_output(websocket: WebSocket, scan_id: str) -> None:
    """Stream scan output as raw text frames suitable for xterm.js."""

    await websocket.accept()

    token = websocket.query_params.get("token")
    if not token:
        await websocket.send_text("[error] Missing token\n")
        await websocket.close(code=4401)
        return

    async with async_session_factory() as db:
        user = await _get_user_from_token(token, db)
        if user is None or not user.is_active:
            await websocket.send_text("[error] Unauthorized\n")
            await websocket.close(code=4401)
            return

        result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
        job = result.scalar_one_or_none()
        if job is None:
            await websocket.send_text("[error] Scan job not found\n")
            await websocket.close(code=4404)
            return

        artifact_path = Path(job.artifact_path or f"data/scans/scan_{scan_id}.txt")
        last_pos = 0

        try:
            while True:
                result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
                job = result.scalar_one_or_none()
                if job is None:
                    await websocket.send_text("[error] Scan job not found\n")
                    await websocket.close(code=4404)
                    return

                if job.artifact_path:
                    artifact_path = Path(job.artifact_path)

                if artifact_path.exists() and artifact_path.is_file():
                    with artifact_path.open("rb") as f:
                        f.seek(last_pos)
                        data = f.read()
                        last_pos = f.tell()
                    if data:
                        await websocket.send_text(data.decode(errors="replace"))

                if job.status in {ScanJobStatus.COMPLETED, ScanJobStatus.FAILED}:
                    # Flush once more and then close.
                    if artifact_path.exists() and artifact_path.is_file():
                        with artifact_path.open("rb") as f:
                            f.seek(last_pos)
                            data = f.read()
                            last_pos = f.tell()
                        if data:
                            await websocket.send_text(data.decode(errors="replace"))

                    await websocket.close(code=1000)
                    return

                # End the read-only transaction so we see updates on the next poll.
                await db.rollback()
                await asyncio.sleep(0.35)
        except WebSocketDisconnect:
            return
        except Exception as exc:  # noqa: BLE001
            try:
                await websocket.send_text(f"\n[ws-error] {exc!r}\n")
            finally:
                await websocket.close(code=1011)


@router.websocket("/metrics")
async def websocket_metrics(websocket: WebSocket) -> None:
    """Stream real-time dashboard metrics over WebSocket."""

    await websocket.accept()

    token = websocket.query_params.get("token")
    if not token:
        await websocket.send_json({"event": "error", "message": "Missing token"})
        await websocket.close(code=4401)
        return

    async with async_session_factory() as db:
        user = await _get_user_from_token(token, db)
        if user is None or not user.is_active:
            await websocket.send_json({"event": "error", "message": "Unauthorized"})
            await websocket.close(code=4401)
            return

    metrics_clients.add(websocket)

    def _isoformat_utc_z(ts: datetime) -> str:
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        else:
            ts = ts.astimezone(timezone.utc)
        return ts.isoformat().replace("+00:00", "Z")

    metric_types = {"latency_ms", "jitter_ms", "packet_loss_pct"}
    last_sent_timestamp: datetime | None = None

    def _mean(values: list[float]) -> float | None:
        if not values:
            return None
        return sum(values) / len(values)

    try:
        while True:
            internet_health: float | None = None
            snapshot_ts: datetime | None = None
            rows: list[Metric] = []

            async with async_session_factory() as db:
                health_result = await db.execute(
                    select(Metric)
                    .where(Metric.metric_type == "internet_health")
                    .order_by(Metric.timestamp.desc())
                    .limit(1)
                )
                health_metric = health_result.scalar_one_or_none()

                if health_metric is not None:
                    snapshot_ts = health_metric.timestamp

                    if last_sent_timestamp is None or snapshot_ts > last_sent_timestamp:
                        internet_health = float(health_metric.value)

                        result = await db.execute(
                            select(Metric).where(
                                Metric.metric_type.in_(metric_types),
                                Metric.timestamp == snapshot_ts,
                            )
                        )
                        rows = list(result.scalars().all())

                        if not rows:
                            window_start = snapshot_ts - timedelta(minutes=15)
                            fallback_result = await db.execute(
                                select(Metric)
                                .where(
                                    Metric.metric_type.in_(metric_types),
                                    Metric.timestamp >= window_start,
                                    Metric.timestamp <= snapshot_ts,
                                )
                                .order_by(Metric.timestamp.desc())
                            )
                            rows = list(fallback_result.scalars().all())

            if snapshot_ts is None or internet_health is None:
                await asyncio.sleep(3)
                continue

            latest_by_target_and_type: dict[tuple[str, str], float] = {}

            # Rows are ordered newest-first in the fallback path. Keep the first occurrence
            # to represent "latest" per (target, metric_type).
            for m in rows:
                tags = m.tags or {}
                target = tags.get("target")
                if not target:
                    continue
                key = (target, m.metric_type)
                if key not in latest_by_target_and_type:
                    latest_by_target_and_type[key] = float(m.value)

            latency_values: list[float] = []
            jitter_values: list[float] = []
            loss_values: list[float] = []

            for (_, metric_type), value in latest_by_target_and_type.items():
                if metric_type == "latency_ms":
                    latency_values.append(value)
                elif metric_type == "jitter_ms":
                    jitter_values.append(value)
                elif metric_type == "packet_loss_pct":
                    loss_values.append(value)

            latency = _mean(latency_values)
            jitter = _mean(jitter_values)
            packet_loss = _mean(loss_values)

            metrics = {
                "event": "metrics",
                "data": {
                    "internet_health": round(internet_health, 1),
                    "latency_ms": round(latency, 2) if latency is not None else None,
                    "jitter_ms": round(jitter, 2) if jitter is not None else None,
                    "packet_loss_pct": round(packet_loss, 2)
                    if packet_loss is not None
                    else None,
                    "timestamp": _isoformat_utc_z(snapshot_ts),
                },
            }

            await websocket.send_json(metrics)
            last_sent_timestamp = snapshot_ts
            await asyncio.sleep(3)

    except WebSocketDisconnect:
        metrics_clients.discard(websocket)
    except Exception:
        metrics_clients.discard(websocket)
        await websocket.close(code=1011)