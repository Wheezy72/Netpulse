from __future__ import annotations

"""
Alerting utilities.

Handles:
- Email alerts via SMTP.
- Periodic scanning of new high/critical vulnerabilities to trigger alerts.
- Generic system alerts (e.g. scan completion, reports, health degradation).
"""

import asyncio
import smtplib
from email.message import EmailMessage
from typing import List, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.device import Device
from app.models.vulnerability import Vulnerability, VulnerabilitySeverity


def _build_vulnerability_subject(device: Device, vuln: Vulnerability) -> str:
    label = device.hostname or device.ip_address
    return f"[NetPulse] {vuln.severity.value.upper()} vulnerability on {label}"


def _build_vulnerability_body(device: Device, vuln: Vulnerability) -> str:
    lines = [
        f"Device: {device.hostname or device.ip_address}",
        f"Severity: {vuln.severity.value}",
        f"Source: {vuln.source}",
        f"Title: {vuln.title}",
        "",
        vuln.description or "",
    ]
    if vuln.port:
        lines.append(f"Port: {vuln.port}/{vuln.protocol or 'tcp'}")
    if vuln.cve_id:
        lines.append(f"CVE: {vuln.cve_id}")
    lines.append("")
    lines.append(f"Detected at: {vuln.detected_at.isoformat()}")
    return "\n".join(lines)


def _send_email_sync(subject: str, body: str) -> None:
    """Send an email using basic SMTP settings."""
    if not settings.enable_email_alerts:
        return
    if not (
        settings.smtp_host
        and settings.alert_email_from
        and settings.alert_email_to
    ):
        return

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.alert_email_from
    msg["To"] = settings.alert_email_to
    msg.set_content(body)

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=10) as server:
        server.starttls()
        if settings.smtp_username and settings.smtp_password:
            server.login(settings.smtp_username, settings.smtp_password)
        server.send_message(msg)


async def send_email_alert(subject: str, body: str) -> None:
    """Async wrapper around SMTP send."""
    await asyncio.to_thread(_send_email_sync, subject, body)


async def send_system_alert(
    subject: str,
    body: str,
    *,
    event_type: str | None = None,
    channel: str | None = None,
    device_name: str | None = None,
    device_ip: str | None = None,
    device_mac: str | None = None,
    segment_name: str | None = None,
    severity: str | None = None,
) -> None:
    """
    Send a generic system alert via email.

    Parameters
    ----------
    subject:
        Human-readable subject line (used as email subject).
    body:
        Detailed body text.
    event_type:
        Logical event type, e.g. "vuln", "scan", "report", "health", "device".
        Kept for call-site compatibility; routing is email-only.
    channel:
        Optional channel hint. "none" suppresses the alert entirely; any other
        value (including legacy values) results in the email alert.
    device_name, device_ip, device_mac, segment_name, severity:
        Optional device/context values kept for call-site compatibility.
    """
    if (channel or "").lower() == "none":
        return

    await send_email_alert(subject, body)


async def process_vulnerability_alerts(db: AsyncSession) -> None:
    """
    Look for new high/critical vulnerabilities and send alerts.

    A vulnerability is considered "new" if:
      - is_resolved is False, and
      - alert_sent is False, and
      - severity is HIGH or CRITICAL.
    """
    stmt = (
        select(Vulnerability, Device)
        .join(Device, Vulnerability.device_id == Device.id)
        .where(
            Vulnerability.is_resolved.is_(False),
            Vulnerability.alert_sent.is_(False),
            Vulnerability.severity.in_(
                [VulnerabilitySeverity.HIGH, VulnerabilitySeverity.CRITICAL]
            ),
        )
        .order_by(Vulnerability.detected_at.desc())
    )
    result = await db.execute(stmt)
    rows: List[Tuple[Vulnerability, Device]] = result.all()

    if not rows:
        return

    for vuln, device in rows:
        subject = _build_vulnerability_subject(device, vuln)
        body = _build_vulnerability_body(device, vuln)

        await send_system_alert(
            subject,
            body,
            event_type="vuln",
            device_name=device.hostname or device.ip_address,
            device_ip=device.ip_address,
            device_mac=device.mac_address,
            segment_name=device.zone or "Default",
            severity=vuln.severity.value.upper() if vuln.severity else None,
        )

        vuln.alert_sent = True

    await db.commit()
