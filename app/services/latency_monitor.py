from __future__ import annotations

"""
Latency and Internet Health monitoring.

This module:
- pings a small set of targets,
- calculates latency, jitter, and packet loss,
- derives an Internet Health score,
- persists everything as Metric rows for the Pulse dashboard.
"""

import asyncio
import statistics
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, List, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.metric import Metric
from app.services.alerts import send_system_alert


@dataclass
class PingResult:
    target: str
    latencies_ms: List[float]
    packet_loss_pct: float


async def _ping_target(target: str, count: int = 3, timeout: int = 2) -> PingResult:
    """Ping a target using the system ping command.

    This implementation is intentionally simple and portable.
    It parses the output of the `ping` utility and extracts per-packet RTTs.
    """
    # Use -c on Unix-like systems (assumed for containerized deployment)
    process = await asyncio.create_subprocess_exec(
        "ping",
        "-c",
        str(count),
        "-W",
        str(timeout),
        target,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await process.communicate()
    if process.returncode != 0:
        # Treat as 100% packet loss
        return PingResult(target=target, latencies_ms=[], packet_loss_pct=100.0)

    latencies: List[float] = []
    sent = 0
    received = 0

    for line in stdout.decode().splitlines():
        if "bytes from" in line and "time=" in line:
            sent += 1
            try:
                # Example: "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms"
                time_part = line.split("time=")[1]
                ms_str = time_part.split()[0]
                latencies.append(float(ms_str))
                received += 1
            except (IndexError, ValueError):
                continue

    if sent == 0:
        packet_loss_pct = 100.0
    else:
        packet_loss_pct = ((sent - received) / sent) * 100.0

    return PingResult(target=target, latencies_ms=latencies, packet_loss_pct=packet_loss_pct)


def _calculate_jitter(latencies: Iterable[float]) -> float:
    """Compute jitter as the mean absolute difference between consecutive RTTs."""
    lat_list = list(latencies)
    if len(lat_list) < 2:
        return 0.0
    diffs = [abs(b - a) for a, b in zip(lat_list, lat_list[1:])]
    return float(statistics.mean(diffs))


def _internet_health_score(
    avg_latency_ms: float,
    jitter_ms: float,
    packet_loss_pct: float,
) -> float:
    """Heuristic Internet Health score in the range [0, 100]."""
    score = 100.0

    # Latency penalty
    if avg_latency_ms > 30:
        score -= (avg_latency_ms - 30) * 0.5
    if avg_latency_ms > 100:
        score -= (avg_latency_ms - 100) * 0.5

    # Jitter penalty
    if jitter_ms > 10:
        score -= (jitter_ms - 10) * 0.7

    # Packet loss penalty (very strong signal)
    score -= packet_loss_pct * 2.0

    return max(0.0, min(100.0, score))


async def monitor_latency(db: AsyncSession) -> None:
    """Run latency measurements and persist metrics.

    This is the core of the Pulse module and is invoked by a Celery task.
    """
    timestamp = datetime.utcnow()
    ping_tasks = [_ping_target(target) for target in settings.pulse_targets]
    results: List[PingResult] = await asyncio.gather(*ping_tasks)

    # Store per-target metrics
    for result in results:
        if result.latencies_ms:
            avg_latency = float(statistics.mean(result.latencies_ms))
            jitter = _calculate_jitter(result.latencies_ms)
        else:
            avg_latency = 0.0
            jitter = 0.0

        metrics = [
            Metric(
                device_id=None,
                timestamp=timestamp,
                metric_type="latency_ms",
                value=avg_latency,
                tags={"target": result.target},
            ),
            Metric(
                device_id=None,
                timestamp=timestamp,
                metric_type="jitter_ms",
                value=jitter,
                tags={"target": result.target},
            ),
            Metric(
                device_id=None,
                timestamp=timestamp,
                metric_type="packet_loss_pct",
                value=result.packet_loss_pct,
                tags={"target": result.target},
            ),
        ]
        db.add_all(metrics)

    # Compute aggregated Internet Health score based on all targets
    lat_values: List[float] = []
    jit_values: List[float] = []
    loss_values: List[float] = []

    for result in results:
        if result.latencies_ms:
            lat_values.append(float(statistics.mean(result.latencies_ms)))
            jit_values.append(_calculate_jitter(result.latencies_ms))
        loss_values.append(result.packet_loss_pct)

    if lat_values:
        avg_latency_all = float(statistics.mean(lat_values))
    else:
        avg_latency_all = 0.0
    if jit_values:
        jitter_all = float(statistics.mean(jit_values))
    else:
        jitter_all = 0.0
    if loss_values:
        packet_loss_all = float(statistics.mean(loss_values))
    else:
        packet_loss_all = 0.0

    health_score = _internet_health_score(avg_latency_all, jitter_all, packet_loss_all)

    # Check previous Internet Health to detect a degradation event
    prev_result = await db.execute(
        select(Metric)
        .where(Metric.metric_type == "internet_health")
        .order_by(Metric.timestamp.desc())
        .limit(1)
    )
    prev_metric = prev_result.scalar_one_or_none()
    prev_value = float(prev_metric.value) if prev_metric is not None else None

    db.add(
        Metric(
            device_id=None,
            timestamp=timestamp,
            metric_type="internet_health",
            value=health_score,
            tags={},
        )
    )

    # If health drops below the configured threshold and was previously above it,
    # send a one-shot alert describing the current state.
    if health_score < settings.health_alert_threshold and (
        prev_value is None or prev_value >= settings.health_alert_threshold
    ):
        lines = [
            f"Internet Health degraded to {health_score:.1f}%",
            f"Average latency: {avg_latency_all:.1f} ms",
            f"Average jitter: {jitter_all:.1f} ms",
            f"Average packet loss: {packet_loss_all:.1f}%",
            "",
            "Per-target snapshot:",
        ]
        for result in results:
            if result.latencies_ms:
                avg_lat = float(statistics.mean(result.latencies_ms))
                jit = _calculate_jitter(result.latencies_ms)
            else:
                avg_lat = 0.0
                jit = 0.0

            label = result.target
            if result.target == settings.pulse_gateway_ip:
                label = f"{result.target} (Gateway)"
            elif result.target == settings.pulse_isp_ip:
                label = f"{result.target} (ISP Edge)"
            elif result.target == settings.pulse_cloudflare_ip:
                label = f"{result.target} (Cloudflare)"

            lines.append(
                f"- {label}: {avg_lat:.1f} ms, jitter {jit:.1f} ms, loss {result.packet_loss_pct:.1f}%"
            )

        subject = f"[NetPulse] Internet Health degraded ({health_score:.1f}%)"
        body = "\n".join(lines)
        await send_system_alert(subject, body, event_type="health")

    await db.commit()