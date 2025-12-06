from __future__ import annotations

"""
Prebuilt script: wan_health_pdf_report.py

Generates a human-readable WAN health PDF report under /data/reports.

The report is designed to be useful for both technical and non-technical
readers, with:

- A clear title and date range.
- A summary of Internet Health (min/avg/max, samples).
- Per-target connectivity metrics (latency, jitter, packet loss).
- A snapshot of high/critical vulnerabilities.
- Plain-language recommendations based on the observed data.
"""

from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Tuple

from fpdf import FPDF  # type: ignore[import]

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.device import Device
from app.models.metric import Metric
from app.models.vulnerability import Vulnerability, VulnerabilitySeverity
from app.services.alerts import send_system_alert


def _classify_health(score: float) -> str:
    if score >= 80:
        return "Good"
    if score >= 50:
        return "Degraded"
    return "Poor"


def _classify_loss(loss: float) -> str:
    if loss < 1:
        return "Low loss"
    if loss < 5:
        return "Moderate loss"
    return "High loss"


def _classify_latency(latency: float) -> str:
    if latency < 30:
        return "Fast"
    if latency < 80:
        return "Acceptable"
    return "Slow"


def _short_target_label(target: str) -> str:
    if target == settings.pulse_gateway_ip:
        return "Gateway"
    if target == settings.pulse_isp_ip:
        return "ISP Edge"
    if target == settings.pulse_cloudflare_ip:
        return "Cloudflare"
    return target


async def _load_internet_health(
    db: AsyncSession,
    window_start: datetime,
    window_end: datetime,
) -> Tuple[List[Tuple[datetime, float]], Dict[str, float]]:
    sql = (
        select(Metric.timestamp, Metric.value)
        .where(
            Metric.metric_type == "internet_health",
            Metric.timestamp >= window_start,
            Metric.timestamp <= window_end,
        )
        .order_by(Metric.timestamp.asc())
    )
    result = await db.execute(sql)
    rows = result.fetchall()

    points: List[Tuple[datetime, float]] = []
    for ts, val in rows:
        points.append((ts, float(val)))

    if not points:
        summary = {
            "status": "empty",
            "samples": 0,
            "min": 0.0,
            "max": 0.0,
            "avg": 0.0,
        }
        return points, summary

    values = [v for _, v in points]
    summary = {
        "status": "ok",
        "samples": len(values),
        "min": min(values),
        "max": max(values),
        "avg": sum(values) / len(values),
    }
    return points, summary


async def _load_pulse_targets(
    db: AsyncSession,
    window_start: datetime,
    window_end: datetime,
) -> List[Dict[str, Any]]:
    targets = settings.pulse_targets
    out: List[Dict[str, Any]] = []

    for t in targets:
        # Aggregate simple avg latency/jitter/loss for the window.
        sql = (
            select(Metric.metric_type, Metric.value)
            .where(
                Metric.timestamp >= window_start,
                Metric.timestamp <= window_end,
                Metric.tags["target"].as_string() == t,  # type: ignore[index]
                Metric.metric_type.in_(
                    ["latency_ms", "jitter_ms", "packet_loss_pct"]
                ),
            )
        )
        result = await db.execute(sql)
        rows = result.fetchall()
        if not rows:
            out.append(
                {
                    "target": t,
                    "label": _short_target_label(t),
                    "latency_ms": None,
                    "jitter_ms": None,
                    "packet_loss_pct": None,
                }
            )
            continue

        lat_vals: List[float] = []
        jit_vals: List[float] = []
        loss_vals: List[float] = []

        for metric_type, value in rows:
            v = float(value)
            if metric_type == "latency_ms":
                lat_vals.append(v)
            elif metric_type == "jitter_ms":
                jit_vals.append(v)
            elif metric_type == "packet_loss_pct":
                loss_vals.append(v)

        def _avg(xs: List[float]) -> float | None:
            return sum(xs) / len(xs) if xs else None

        out.append(
            {
                "target": t,
                "label": _short_target_label(t),
                "latency_ms": _avg(lat_vals),
                "jitter_ms": _avg(jit_vals),
                "packet_loss_pct": _avg(loss_vals),
            }
        )

    return out


async def _load_vulnerability_snapshot(
    db: AsyncSession,
) -> List[Tuple[Vulnerability, Device]]:
    stmt = (
        select(Vulnerability, Device)
        .join(Device, Vulnerability.device_id == Device.id)
        .where(
            Vulnerability.is_resolved.is_(False),
            Vulnerability.severity.in_(
                [VulnerabilitySeverity.HIGH, VulnerabilitySeverity.CRITICAL]
            ),
        )
        .order_by(Vulnerability.severity.desc(), Vulnerability.detected_at.desc())
        .limit(20)
    )
    result = await db.execute(stmt)
    return result.fetchall()


def _build_recommendations(
    health_summary: Dict[str, float],
    per_target: List[Dict[str, Any]],
    vulns: List[Tuple[Vulnerability, Device]],
) -> List[str]:
    recs: List[str] = []

    avg_health = health_summary.get("avg", 0.0)
    min_health = health_summary.get("min", 0.0)

    if health_summary.get("samples", 0) == 0:
        recs.append(
            "No Internet Health data was available. Check that the latency "
            "monitoring task is running and that the worker can reach the configured targets."
        )
        return recs

    if avg_health < 80 or min_health < 60:
        recs.append(
            "Investigate WAN performance. Health scores are below ideal levels; "
            "check for congestion, unstable links, or misconfigured QoS."
        )

    for t in per_target:
        if t["latency_ms"] is None:
            recs.append(
                f"No measurements for {t['label']} ({t['target']}). Confirm the host is reachable "
                "and permitted by firewall rules."
            )
            continue

        if t["packet_loss_pct"] and t["packet_loss_pct"] > 3:
            recs.append(
                f"Packet loss to {t['label']} is above 3%. Examine physical links, Wi‑Fi quality, "
                "and ISP side issues."
            )
        if t["latency_ms"] and t["latency_ms"] > 80:
            recs.append(
                f"Latency to {t['label']} frequently exceeds 80 ms. Consider checking routing, "
                "peering, or local load."
            )

    if vulns:
        recs.append(
            "Address the listed high/critical vulnerabilities, starting with devices that are "
            "exposed to the internet or act as gateways."
        )

    if not recs:
        recs.append(
            "No major issues detected. Continue to monitor regularly and keep device firmware "
            "and configurations up to date."
        )

    return recs


class _ReportPDF(FPDF):
    def header(self) -> None:  # type: ignore[override]
        self.set_font("Helvetica", "B", 12)
        self.cell(0, 8, "NetPulse WAN Health Report", border=0, ln=1)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(100, 100, 100)
        self.cell(0, 4, "Generated by NetPulse Enterprise (built by wheezy72 & Genie)", ln=1)
        self.ln(2)
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)
        self.set_text_color(0, 0, 0)

    def footer(self) -> None:  # type: ignore[override]
        self.set_y(-12)
        self.set_font("Helvetica", "I", 8)
        self.set_text_color(120, 120, 120)
        self.cell(0, 10, f"Page {self.page_no()}", align="C")


async def run(ctx: Any) -> dict:
    """
    Generate a WAN health PDF report for the last 24 hours.

    The PDF is saved under /data/reports and the path is returned in the
    structured result. A short alert is also sent indicating where the
    report is stored.
    """
    ctx.logger("wan_health_pdf_report: starting")

    db: AsyncSession = ctx.db  # type: ignore[assignment]

    now = datetime.utcnow()
    window_end = now
    window_start = now - timedelta(hours=24)

    # Load metrics and vulnerabilities.
    points, health_summary = await _load_internet_health(db, window_start, window_end)
    per_target = await _load_pulse_targets(db, window_start, window_end)
    vulns = await _load_vulnerability_snapshot(db)

    recommendations = _build_recommendations(health_summary, per_target, vulns)

    reports_dir = Path("/data/reports")
    reports_dir.mkdir(parents=True, exist_ok=True)

    ts = now.strftime("%Y%m%d-%H%M%S")
    path = reports_dir / f"wan_health_{ts}.pdf"

    # Build PDF
    pdf = _ReportPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()

    # Title + date range
    pdf.set_font("Helvetica", "B", 16)
    pdf.cell(0, 10, "WAN Health Overview", ln=1)
    pdf.set_font("Helvetica", "", 10)
    pdf.set_text_color(80, 80, 80)
    pdf.cell(
        0,
        6,
        f"Period: {window_start.isoformat(timespec='minutes')} to {window_end.isoformat(timespec='minutes')}",
        ln=1,
    )
    pdf.ln(2)

    # Summary
    pdf.set_text_color(0, 0, 0)
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "1. Summary (for all readers)", ln=1)
    pdf.set_font("Helvetica", "", 10)

    if health_summary["status"] == "empty":
        pdf.multi_cell(
            0,
            5,
            "No Internet Health data was available for the selected period. "
            "Ensure the monitoring tasks are running and targets are reachable.",
        )
    else:
        avg = health_summary["avg"]
        min_h = health_summary["min"]
        max_h = health_summary["max"]
        samples = int(health_summary["samples"])
        classification = _classify_health(avg)

        pdf.multi_cell(
            0,
            5,
            f"Internet Health over the last 24 hours was classified as {classification}. "
            f"The average score was {avg:.1f}%, ranging from {min_h:.1f}% to {max_h:.1f}% "
            f"across {samples} measurements.",
        )

    pdf.ln(4)

    # Per-target connectivity
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "2. Connectivity by Target", ln=1)
    pdf.set_font("Helvetica", "", 10)

    if not per_target:
        pdf.multi_cell(
            0,
            5,
            "No per-target measurements were recorded. Check that Pulse targets are "
            "configured in the backend settings.",
        )
    else:
        for t in per_target:
            label = t["label"]
            latency = t["latency_ms"]
            jitter = t["jitter_ms"]
            loss = t["packet_loss_pct"]

            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, f"- {label} ({t['target']})", ln=1)
            pdf.set_font("Helvetica", "", 10)

            if latency is None:
                pdf.multi_cell(
                    0,
                    5,
                    "  No data collected. The host may have been unreachable or blocked.",
                )
                continue

            summary_line = (
                f"  Latency: {latency:.1f} ms ({_classify_latency(latency)}), "
                f"jitter: {jitter:.1f} ms, "
                f"packet loss: {loss:.1f}% ({_classify_loss(loss or 0.0)})."
            )
            pdf.multi_cell(0, 5, summary_line)

        pdf.ln(2)

    # Vulnerabilities snapshot
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "3. Devices & Vulnerabilities", ln=1)
    pdf.set_font("Helvetica", "", 10)

    if not vulns:
        pdf.multi_cell(
            0,
            5,
            "No unresolved high or critical vulnerabilities were recorded for this period.",
        )
    else:
        pdf.multi_cell(
            0,
            5,
            "The following devices currently have unresolved high or critical vulnerabilities. "
            "Address these findings before exposing hosts to untrusted networks.",
        )
        pdf.ln(2)
        for vuln, device in vulns:
            dev_label = device.hostname or device.ip_address
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(
                0,
                6,
                f"- {dev_label} ({device.ip_address}) – {vuln.severity.value.upper()}",
                ln=1,
            )
            pdf.set_font("Helvetica", "", 10)
            pdf.multi_cell(
                0,
                5,
                f"  {vuln.title} (source: {vuln.source})",
            )

        pdf.ln(2)

    # Recommendations
    pdf.set_font("Helvetica", "B", 12)
    pdf.cell(0, 8, "4. Recommendations", ln=1)
    pdf.set_font("Helvetica", "", 10)

    for rec in recommendations:
        pdf.multi_cell(0, 5, f"- {rec}")
        pdf.ln(1)

    pdf.ln(2)
    pdf.set_font("Helvetica", "I", 9)
    pdf.set_text_color(90, 90, 90)
    pdf.multi_cell(
        0,
        4,
        "Technical note: metrics are derived from periodic ICMP pings to configured "
        "Pulse targets and stored as time-series data in TimescaleDB.",
    )

    pdf.output(str(path))
    ctx.logger(f"wan_health_pdf_report: wrote report to {path}")

    # Notify via alert channels.
    subject = "[NetPulse] WAN health PDF report ready"
    body = (
        f"Status: {health_summary.get('status', 'unknown')} "
        f"| samples: {health_summary.get('samples', 0)}\n"
        f"Report file: {path}"
    )
    await send_system_alert(subject, body, event_type="report")

    return {
        "status": health_summary.get("status", "unknown"),
        "path": str(path),
        "samples": health_summary.get("samples", 0),
    }