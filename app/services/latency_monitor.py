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
from typing import Iterable, List

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


async def _ping_target(target: str, count: int = 15, timeout: int = 1) -> PingResult:
    """Ping a target using the system ping command.

    Notes
    -----
    - We default to a higher ping count (>=15) to stabilize packet loss and jitter.
    - We do **not** treat non-zero ping exit codes as total failure: on Linux, ping
      returns non-zero on partial loss.
    """

    try:
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
        stdout_b, _stderr_b = await process.communicate()
    except Exception:
        return PingResult(target=target, latencies_ms=[], packet_loss_pct=100.0)

    stdout = stdout_b.decode(errors="replace")

    latencies: List[float] = []
    for line in stdout.splitlines():
        if "bytes from" in line and "time=" in line:
            try:
                # Example: "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=12.3 ms"
                time_part = line.split("time=", 1)[1]
                ms_str = time_part.split()[0]
                latencies.append(float(ms_str))
            except (IndexError, ValueError):
                continue

    # Prefer summary line parsing for tx/rx/loss.
    sent = None
    received = None
    loss_pct = None
    for line in stdout.splitlines():
        if "packets transmitted" in line and "packet loss" in line:
            # e.g. "15 packets transmitted, 14 received, 6% packet loss, time 14014ms"
            try:
                tx_part = line.split("packets transmitted", 1)[0].strip()
                tx = int(tx_part.split()[-1])
                after_tx = line.split("packets transmitted", 1)[1]
                rx_part = after_tx.split("received", 1)[0]
                rx = int(rx_part.replace(",", " ").split()[-1])

                loss_str = line.split("packet loss", 1)[0].split(",")[-1]
                loss = float(loss_str.strip().replace("%", ""))

                sent, received, loss_pct = tx, rx, loss
                break
            except Exception:
                # Fall back below.
                pass

    if sent is None:
        sent = count
    if received is None:
        received = len(latencies)

    if loss_pct is None:
        if sent <= 0:
            loss_pct = 100.0
        else:
            loss_pct = max(0.0, min(100.0, ((sent - received) / sent) * 100.0))

    return PingResult(target=target, latencies_ms=latencies, packet_loss_pct=float(loss_pct))


def _calculate_jitter(latencies: Iterable[float]) -> float:
    """Compute jitter as the mean absolute difference between consecutive RTTs."""
    lat_list = list(latencies)
    if len(lat_list) < 2:
        return 0.0
    diffs = [abs(b - a) for a, b in zip(lat_list, lat_list[1:])]
    return float(statistics.mean(diffs))


def _internet_health_score(
    wan_latency_ms: float,
    wan_jitter_ms: float,
    wan_packet_loss_pct: float,
) -> float:
    """Heuristic Internet Health score in the range [0, 100].

    Design goals
    ------------
    - Penalize **WAN** conditions only (latency/jitter/loss to ISP + Cloudflare).
    - Avoid extreme drops from a single lost packet.
    - Keep the score intuitive: loss hurts most, then latency, then jitter.
    """

    # Latency penalty: starts above 30ms and caps.
    lat_pen = 0.0
    if wan_latency_ms > 30:
        lat_pen = min(40.0, (wan_latency_ms - 30.0) * 0.35)

    # Jitter penalty: starts above 5ms and caps.
    jit_pen = 0.0
    if wan_jitter_ms > 5:
        jit_pen = min(25.0, (wan_jitter_ms - 5.0) * 1.0)

    # Loss penalty: nonlinear ramp so small loss doesn't instantly tank the score.
    loss = max(0.0, min(100.0, wan_packet_loss_pct)) / 100.0
    loss_pen = 70.0 * (loss**0.6)

    score = 100.0 - (lat_pen + jit_pen + loss_pen)
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
            # Median is less sensitive to single outliers and makes graphs less spiky.
            avg_latency = float(statistics.median(result.latencies_ms))
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

    # Compute aggregated Internet Health score based on WAN targets only.
    # (We do not average gateway latency into WAN health.)
    wan_targets = {settings.pulse_isp_ip, settings.pulse_cloudflare_ip}

    wan_lat_values: List[float] = []
    wan_jit_values: List[float] = []
    wan_loss_values: List[float] = []

    for result in results:
        if result.target not in wan_targets:
            continue

        if result.latencies_ms:
            # Median is more stable than mean and reduces spikiness.
            wan_lat_values.append(float(statistics.median(result.latencies_ms)))
            wan_jit_values.append(_calculate_jitter(result.latencies_ms))
        wan_loss_values.append(result.packet_loss_pct)

    avg_wan_latency = float(statistics.mean(wan_lat_values)) if wan_lat_values else 0.0
    avg_wan_jitter = float(statistics.mean(wan_jit_values)) if wan_jit_values else 0.0
    # Use worst-of for loss: if either WAN target is dropping packets, health should degrade.
    wan_packet_loss = float(max(wan_loss_values)) if wan_loss_values else 0.0

    health_score = _internet_health_score(avg_wan_latency, avg_wan_jitter, wan_packet_loss)

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
            f"WAN latency (avg): {avg_wan_latency:.1f} ms",
            f"WAN jitter (avg): {avg_wan_jitter:.1f} ms",
            f"WAN packet loss (worst-of): {wan_packet_loss:.1f}%",
            "",
            "Per-target snapshot:",
        ]
        for result in results:
            if result.latencies_ms:
                avg_lat = float(statistics.median(result.latencies_ms))
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