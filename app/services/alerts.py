from __future__ import annotations

"""
Alerting utilities.

Handles:
- Email alerts via SMTP.
- Periodic scanning of new high/critical vulnerabilities to trigger alerts.
- Generic system alerts (e.g. scan completion, reports, health degradation).
"""

import asyncio
import logging
import smtplib
import ssl
from email.message import EmailMessage
from typing import List, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.device import Device
from app.models.vulnerability import Vulnerability, VulnerabilitySeverity

logger = logging.getLogger("netpulse.alerts")


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


def smtp_security_mode(port: int, configured: str | None = None) -> str:
    """How to secure the SMTP connection: ``ssl``, ``starttls`` or ``none``.

    The old code called ``starttls()`` unconditionally, which failed on the two
    setups people actually use besides a provider on 587: port 465 (implicit
    TLS) and a local relay on 25 that does not offer STARTTLS at all.
    """
    value = (configured if configured is not None else settings.smtp_security) or "auto"
    value = value.strip().lower()
    if value in {"ssl", "starttls", "none"}:
        return value
    return "ssl" if port == 465 else "starttls"


def _send_email_sync(subject: str, body: str) -> bool:
    """Send one alert email. Returns whether it actually went out.

    Never raises: alerting runs inside background ticks and request handlers,
    where an unreachable mail server used to surface as a failure and left the
    vulnerability unmarked, retrying the same mail every few minutes. Failures
    are logged once, with the reason, so ``logs/api.log`` answers "did it send".
    """
    if not settings.enable_email_alerts:
        logger.debug("Email alert skipped: ENABLE_EMAIL_ALERTS is false")
        return False

    missing = [
        name
        for name, value in (
            ("SMTP_HOST", settings.smtp_host),
            ("ALERT_EMAIL_FROM", settings.alert_email_from),
            ("ALERT_EMAIL_TO", settings.alert_email_to),
        )
        if not value
    ]
    if missing:
        logger.warning("Email alert skipped: %s missing in .env", ", ".join(missing))
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.alert_email_from
    msg["To"] = settings.alert_email_to
    msg.set_content(body)

    host = settings.smtp_host
    port = settings.smtp_port
    security = smtp_security_mode(port)
    explicit = (settings.smtp_security or "auto").strip().lower() == "starttls"

    try:
        if security == "ssl":
            server: smtplib.SMTP = smtplib.SMTP_SSL(
                host, port, timeout=10, context=ssl.create_default_context()
            )
        else:
            server = smtplib.SMTP(host, port, timeout=10)

        with server:
            if security == "starttls":
                try:
                    server.starttls(context=ssl.create_default_context())
                    server.ehlo()
                except smtplib.SMTPNotSupportedError:
                    if explicit:
                        raise
                    logger.debug(
                        "SMTP server %s:%s does not offer STARTTLS; sending unencrypted",
                        host,
                        port,
                    )
            if settings.smtp_username and settings.smtp_password:
                server.login(settings.smtp_username, settings.smtp_password)
            server.send_message(msg)
    except Exception as exc:
        logger.warning(
            "Email alert not sent (%s:%s, security=%s): %s",
            host,
            port,
            security,
            exc,
        )
        return False

    logger.info("Email alert sent to %s via %s:%s (%s)", settings.alert_email_to, host, port, security)
    return True


async def send_email_alert(subject: str, body: str) -> bool:
    """Async wrapper around the SMTP send; returns whether it was delivered."""
    try:
        return await asyncio.to_thread(_send_email_sync, subject, body)
    except Exception as exc:  # defensive: alerting must never break a caller
        logger.warning("Email alert failed: %s", exc)
        return False


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
) -> bool:
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

    Returns whether an email actually went out.
    """
    if (channel or "").lower() == "none":
        return False

    return await send_email_alert(subject, body)


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

        delivered = await send_system_alert(
            subject,
            body,
            event_type="vuln",
            device_name=device.hostname or device.ip_address,
            device_ip=device.ip_address,
            device_mac=device.mac_address,
            segment_name=device.zone or "Default",
            severity=vuln.severity.value.upper() if vuln.severity else None,
        )

        # Marked as alerted when emailing is off (so turning it on later does
        # not dump years of history at once) or when the mail was accepted. A
        # failure leaves the flag alone so the next tick retries it.
        if delivered or not settings.enable_email_alerts:
            vuln.alert_sent = True

    await db.commit()
