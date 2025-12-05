from __future__ import annotations

"""
Alerting utilities.

Handles:
- Email alerts via SMTP.
- WhatsApp (or similar) alerts via a generic HTTP webhook.
- Periodic scanning of new high/critical vulnerabilities to trigger alerts.
- Generic system alerts (e.g. scan completion, reports).
"""

import asyncio
import json
import smtplib
from email.message import EmailMessage
from typing import Any, Iterable, List, Tuple
from urllib.request import Request, urlopen

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

    host = settings.smtp_host
    port = settings.smtp_port
    username = settings.smtp_username
    password = settings.smtp_password

    with smtplib.SMTP(host, port, timeout=10) as server:
        server.starttls()
        if username and password:
            server.login(username, password)
        server.send_message(msg)


async def send_email_alert(subject: str, body: str) -> None:
    """Async wrapper around SMTP send."""
    await asyncio.to_thread(_send_email_sync, subject, body)


def _send_whatsapp_sync(message: str) -> None:
    """
    Send a WhatsApp-style alert via a generic HTTP webhook.

    This is intentionally generic; in a real deployment you would point this
    at your provider (e.g. Twilio, Vonage) and adjust the payload accordingly.
    """
    if not settings.enable_whatsapp_alerts:
        return
    if not (
        settings.whatsapp_api_url
        and settings.whatsapp_api_token
        and settings.whatsapp_recipient
    ):
        return

    payload = {
        "to": settings.whatsapp_recipient,
        "message": message,
    }
    data = json.dumps(payload).encode("utf-8")
    req = Request(
        settings.whatsapp_api_url,
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {settings.whatsapp_api_token}",
        },
        method="POST",
    )
    # Best-effort; errors are swallowed to avoid interfering with core workflows.
    try:
        with urlopen(req, timeout=10) as resp:  # noqa: S310
            resp.read()
    except Exception:
        # In production you would log this somewhere central.
        return


async def send_whatsapp_alert(message: str) -> None:
    """Async wrapper around generic WhatsApp/webhook send."""
    await asyncio.to_thread(_send_whatsapp_sync, message)


async def send_system_alert(subject: str, body: str) -> None:
    """
    Send a generic system alert via all configured channels.

    Used for events such as scan completion or report generation.
    """
    await asyncio.gather(
        send_email_alert(subject, body),
        send_whatsapp_alert(subject + "\n\n" + body),
    )


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

        await send_email_alert(subject, body)
        await send_whatsapp_alert(subject + "\n\n" + body)

        vuln.alert_sent = True

    await db.commit()