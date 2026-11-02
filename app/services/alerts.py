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
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from typing import List, Sequence, Tuple

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.clock import utcnow
from app.models.device import Device
from app.models.metric import Metric
from app.models.user import User
from app.models.user_settings import UserSettings
from app.models.vulnerability import Vulnerability, VulnerabilitySeverity
from app.services.alert_policy import AlertPolicy, load_alert_policy

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


def _send_email_sync(
    subject: str,
    body: str,
    recipients: Sequence[str] | None = None,
) -> bool:
    """Send one alert email. Returns whether it actually went out.

    Never raises: alerting runs inside background ticks and request handlers,
    where an unreachable mail server used to surface as a failure and left the
    vulnerability unmarked, retrying the same mail every few minutes. Failures
    are logged once, with the reason, so ``logs/api.log`` answers "did it send".
    """
    if not settings.enable_email_alerts:
        logger.debug("Email alert skipped: ENABLE_EMAIL_ALERTS is false")
        return False

    # The recipient list is decided by the caller (the notification policy),
    # with ALERT_EMAIL_TO as the fallback, so an account's own address in
    # Settings -> Notifications is honoured instead of being ignored.
    to = [address for address in (recipients or [settings.alert_email_to]) if address]
    missing = [
        name
        for name, value in (
            ("SMTP_HOST", settings.smtp_host),
            ("ALERT_EMAIL_FROM", settings.alert_email_from),
        )
        if not value
    ]
    if not to:
        missing.append("ALERT_EMAIL_TO or a notification address")
    if missing:
        logger.warning("Email alert skipped: %s missing in .env", ", ".join(missing))
        return False

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = settings.alert_email_from
    msg["To"] = ", ".join(to)
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

    logger.info("Email alert sent to %s via %s:%s (%s)", ", ".join(to), host, port, security)
    return True


async def send_email_alert(
    subject: str,
    body: str,
    *,
    recipients: Sequence[str] | None = None,
) -> bool:
    """Async wrapper around the SMTP send; returns whether it was delivered."""
    try:
        return await asyncio.to_thread(_send_email_sync, subject, body, recipients)
    except Exception as exc:  # defensive: alerting must never break a caller
        logger.warning("Email alert failed: %s", exc)
        return False


async def send_system_alert(
    subject: str,
    body: str,
    *,
    event_type: str | None = None,
    channel: str | None = None,
    recipients: Sequence[str] | None = None,
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

    Returns whether an email actually went out.
    """
    if (channel or "").lower() == "none":
        return False

    # Only pass recipients when the caller resolved a policy; otherwise leave
    # the send on its env default (ALERT_EMAIL_TO).
    if recipients:
        return await send_email_alert(subject, body, recipients=recipients)
    return await send_email_alert(subject, body)


def _alertable_severities(policy: AlertPolicy) -> List[VulnerabilitySeverity]:
    """Which severities the account settings asked for.

    CRITICAL is the "fire instantly" switch. Everything else — HIGH included —
    is the warning switch: a high finding is bad, but the panel draws the line
    at CVSS >= 9.0 for the instant alert.
    """
    severities: List[VulnerabilitySeverity] = []
    if policy.notify_critical:
        severities.append(VulnerabilitySeverity.CRITICAL)
    if policy.notify_warning:
        severities.extend(
            [
                VulnerabilitySeverity.HIGH,
                VulnerabilitySeverity.MEDIUM,
                VulnerabilitySeverity.LOW,
            ]
        )
    return severities


async def process_vulnerability_alerts(
    db: AsyncSession,
    policy: AlertPolicy | None = None,
) -> None:
    """Send one alert per new finding the notification policy asked for.

    A vulnerability is "new" when it is unresolved and has not been alerted on.
    The four switches in Settings → Notifications decide which severities are
    eligible; ``email_enabled`` decides whether anything is sent at all.
    """
    policy = policy or await load_alert_policy(db)
    severities = _alertable_severities(policy)

    stmt = (
        select(Vulnerability, Device)
        .join(Device, Vulnerability.device_id == Device.id)
        .where(
            Vulnerability.is_resolved.is_(False),
            Vulnerability.alert_sent.is_(False),
        )
        .order_by(Vulnerability.detected_at.desc())
    )
    if severities:
        stmt = stmt.where(Vulnerability.severity.in_(severities))

    rows: List[Tuple[Vulnerability, Device]] = (await db.execute(stmt)).all()

    if not rows:
        return

    can_send = bool(severities) and policy.enabled and settings.enable_email_alerts

    for vuln, device in rows:
        if not can_send:
            # Nothing can go out right now. Mark these so switching alerts on
            # later does not dump the whole history into somebody's inbox.
            vuln.alert_sent = True
            continue

        subject = _build_vulnerability_subject(device, vuln)
        body = _build_vulnerability_body(device, vuln)

        delivered = await send_system_alert(
            subject,
            body,
            event_type="vuln",
            recipients=policy.recipients,
        )

        # A failed send leaves the flag alone so the next tick retries it.
        if delivered:
            vuln.alert_sent = True

    await db.commit()


def _as_aware(value: datetime | None) -> datetime | None:
    """Timezone-aware view of a timestamp.

    PostgreSQL hands back aware datetimes and SQLite naive ones; comparing the
    two raises, and offline detection must not depend on the backend.
    """
    if value is None:
        return None
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


async def process_device_down_alerts(
    db: AsyncSession,
    policy: AlertPolicy | None = None,
) -> int:
    """Email once when a host that used to answer stops answering.

    Offline is derived from ``last_seen``: discovery refreshes it for every host
    it can still reach, so a row that has not been refreshed for
    DEVICE_OFFLINE_MINUTES is the signal. The flag on the row keeps a host that
    stays down from mailing on every sweep, and is cleared as soon as it is
    seen again. Newly offline hosts are batched into one mail, so a switch
    reboot does not become forty separate alerts.

    Two guards keep this from crying wolf, which is worse than not alerting:

    * discovery is what refreshes ``last_seen``, so with the in-process
      scheduler off nothing is refreshing it and every host would look down;
    * on the first sweep after a restart, rows that were already stale are
      marked as reported instead of mailed. A console that was off overnight
      must not open with an inbox full of outages that predate it.
    """
    policy = policy or await load_alert_policy(db)

    # Nothing refreshes last_seen when the in-process scheduler is disabled, so
    # "offline" would just mean "stale". Stay silent rather than mislead.
    if not settings.enable_scheduled_tasks:
        logger.debug("Offline detection skipped: the in-process scheduler is off")
        return 0

    cutoff = utcnow() - timedelta(minutes=max(1, settings.device_offline_minutes))
    # Inventory that has been stale for hours predates this process: it is not
    # an outage that just happened, so it is not worth a mail.
    stale_floor = cutoff - timedelta(minutes=max(1, settings.device_offline_minutes) * 19)
    devices = (
        await db.execute(select(Device).where(Device.last_seen.is_not(None)))
    ).scalars().all()

    global _offline_baseline_done

    newly_down: List[Device] = []
    for device in devices:
        seen = _as_aware(device.last_seen)
        if seen is not None and seen >= cutoff:
            device.offline_alert_sent = False
        elif seen is not None and seen < stale_floor:
            continue
        elif not _offline_baseline_done:
            # First sweep since start: remember that this host was already down
            # instead of reporting it as a new outage.
            device.offline_alert_sent = True
        elif not device.offline_alert_sent:
            newly_down.append(device)

    _offline_baseline_done = True

    if not newly_down or not (policy.enabled and policy.notify_device_down):
        await db.commit()
        return 0

    lines = [f"{len(newly_down)} host(s) stopped answering on the monitored network:", ""]
    for device in newly_down[:50]:
        seen = _as_aware(device.last_seen)
        label = device.hostname or device.ip_address
        lines.append(
            f"- {label} ({device.ip_address}) last seen "
            f"{seen.isoformat() if seen else 'never'}"
        )
    if len(newly_down) > 50:
        lines.append(f"... and {len(newly_down) - 50} more")

    delivered = await send_system_alert(
        f"[NetPulse] {len(newly_down)} host(s) offline",
        "\n".join(lines),
        event_type="device",
        recipients=policy.recipients,
    )
    if delivered:
        for device in newly_down:
            device.offline_alert_sent = True

    await db.commit()
    return len(newly_down) if delivered else 0


async def _digest_message(db: AsyncSession) -> tuple[str, str]:
    """Build the daily summary once, so every subscriber gets the same numbers."""
    now = utcnow()
    seen_cutoff = now - timedelta(minutes=max(1, settings.device_offline_minutes))
    day_ago = now - timedelta(hours=24)

    total = (await db.execute(select(func.count(Device.id)))).scalar_one()
    online = (
        await db.execute(
            select(func.count(Device.id)).where(
                Device.last_seen.is_not(None),
                Device.last_seen >= seen_cutoff,
            )
        )
    ).scalar_one()
    new_devices = (
        await db.execute(
            select(func.count(Device.id)).where(Device.created_at >= day_ago)
        )
    ).scalar_one()

    severity_rows = (
        await db.execute(
            select(Vulnerability.severity, func.count(Vulnerability.id))
            .where(Vulnerability.is_resolved.is_(False))
            .group_by(Vulnerability.severity)
        )
    ).all()
    counts = {
        (severity.value if hasattr(severity, "value") else str(severity)): int(count)
        for severity, count in severity_rows
    }

    health = (
        await db.execute(
            select(Metric.value)
            .where(Metric.metric_type == "internet_health")
            .order_by(Metric.timestamp.desc())
            .limit(1)
        )
    ).scalar_one_or_none()

    lines = [
        "Daily network summary",
        "",
        f"Devices: {total} known, {online} answering now, {new_devices} new in 24h",
        f"Open vulnerabilities: {sum(counts.values())}",
    ]
    for name in ("critical", "high", "medium", "low", "info"):
        if counts.get(name):
            lines.append(f"  - {name}: {counts[name]}")
    lines.append(
        "Internet health: "
        + (f"{float(health):.1f}%" if health is not None else "no sample yet")
    )

    return "[NetPulse] Daily console digest", "\n".join(lines)


async def process_daily_digest(db: AsyncSession) -> int:
    """Send each subscribed account at most one summary per day.

    The marker lives in the account's notification blob (like the scheduler's
    last_run), so no extra table or migration is needed and the panel can show
    the same state it stores.
    """
    if datetime.now().hour < settings.digest_hour:
        return 0

    rows = (
        await db.execute(
            select(User, UserSettings)
            .join(UserSettings, UserSettings.user_id == User.id)
            .where(User.is_active.is_(True))
        )
    ).all()

    today = datetime.now().date().isoformat()
    subject, body = await _digest_message(db)
    sent = 0

    for _user, row in rows:
        blob = dict(row.notification_settings or {})
        if not blob.get("email_enabled") or not blob.get("daily_digest"):
            continue
        if blob.get("digest_last_sent") == today:
            continue

        address = (blob.get("email_address") or settings.alert_email_to or "").strip()
        if not address:
            continue

        if not await send_email_alert(subject, body, recipients=[address]):
            continue

        blob["digest_last_sent"] = today
        row.notification_settings = blob
        sent += 1

    await db.commit()
    return sent
