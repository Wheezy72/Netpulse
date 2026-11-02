"""Which alerts fire, and who receives them.

Settings → Notifications writes a per-account JSON blob that nothing used to
read: every HIGH/CRITICAL finding was mailed to ALERT_EMAIL_TO from `.env`
regardless of the four switches. This module is that reader.

The panel is per account, so the effective policy is the union of the accounts
that asked for mail: if any enabled account has the critical switch on, critical
findings fire, and every enabled account (with its own address, or
ALERT_EMAIL_TO as fallback) receives them. An install where nobody has ever
opened the panel keeps the old env-driven behaviour, so upgrading does not
silently stop alerts.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Sequence

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.user import User
from app.models.user_settings import UserSettings


@dataclass(frozen=True)
class AlertPolicy:
    """The resolved answer to "does this alert go out, and to whom?"."""

    enabled: bool
    recipients: tuple[str, ...]
    notify_critical: bool
    notify_warning: bool
    notify_device_down: bool
    daily_digest: bool


def merge_policy(
    rows: Sequence[Any],
    *,
    env_enabled: bool,
    env_recipient: str | None,
) -> AlertPolicy:
    """Fold the per-account blobs into one policy. Pure and testable."""
    blobs = [row for row in rows if isinstance(row, dict)]
    env_to = (env_recipient or "").strip()

    if not blobs:
        # Nobody has configured notifications: behave exactly like before the
        # panel existed, so an upgrade cannot silently mute an alerting install.
        return AlertPolicy(
            enabled=env_enabled,
            recipients=(env_to,) if env_to else (),
            notify_critical=True,
            notify_warning=False,
            notify_device_down=True,
            daily_digest=False,
        )

    enabled_blobs = [blob for blob in blobs if blob.get("email_enabled")]
    if not enabled_blobs:
        return AlertPolicy(False, (), False, False, False, False)

    recipients: list[str] = []
    for blob in enabled_blobs:
        address = (blob.get("email_address") or "").strip() or env_to
        if address and address not in recipients:
            recipients.append(address)

    return AlertPolicy(
        enabled=bool(recipients),
        recipients=tuple(recipients),
        notify_critical=any(bool(blob.get("alert_on_critical")) for blob in enabled_blobs),
        notify_warning=any(bool(blob.get("alert_on_warning")) for blob in enabled_blobs),
        notify_device_down=any(bool(blob.get("alert_on_device_down")) for blob in enabled_blobs),
        daily_digest=any(bool(blob.get("daily_digest")) for blob in enabled_blobs),
    )


async def load_alert_policy(db: AsyncSession) -> AlertPolicy:
    """Read every active account's notification settings into one policy."""
    result = await db.execute(
        select(UserSettings.notification_settings)
        .join(User, User.id == UserSettings.user_id)
        .where(User.is_active.is_(True))
    )
    rows = [row for (row,) in result.all()]
    return merge_policy(
        rows,
        env_enabled=settings.enable_email_alerts,
        env_recipient=settings.alert_email_to,
    )
