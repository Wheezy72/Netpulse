from __future__ import annotations

import os
from typing import Any, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, get_current_user
from app.core.config import settings as app_settings
from app.models.user import User
from app.models.user_settings import UserSettings

router = APIRouter()


class NotificationSettings(BaseModel):
    email_enabled: bool = False
    email_address: Optional[str] = None
    whatsapp_enabled: bool = False
    whatsapp_number: Optional[str] = None
    alert_on_critical: bool = True
    alert_on_warning: bool = False
    alert_on_device_down: bool = True
    daily_digest: bool = False


class AISettings(BaseModel):
    provider: str = "openai"
    model: str = "gpt-4o-mini"
    enabled: bool = False
    custom_base_url: Optional[str] = None
    custom_model: Optional[str] = None


class ThreatIntelSettings(BaseModel):
    abuseipdb_enabled: bool = False
    abuseipdb_max_age: int = 90


class ScanSchedule(BaseModel):
    enabled: bool = False
    frequency: str = "daily"
    time: str = "02:00"
    scan_type: str = "quick"
    segments: list[int] = []
    notify_on_complete: bool = True


async def _get_user_settings(db: AsyncSession, user_id: int) -> UserSettings | None:
    return await db.get(UserSettings, user_id)


async def _upsert_user_settings(
    db: AsyncSession,
    user_id: int,
    **fields: Any,
) -> UserSettings:
    row = await _get_user_settings(db, user_id)
    if row is None:
        row = UserSettings(user_id=user_id, **fields)
        db.add(row)
    else:
        for key, value in fields.items():
            setattr(row, key, value)

    await db.commit()
    await db.refresh(row)
    return row


async def load_ai_settings(db: AsyncSession, user_id: int) -> AISettings | None:
    row = await _get_user_settings(db, user_id)
    if row is None or not row.ai_settings:
        return None

    config = AISettings(**row.ai_settings)

    # Backwards-compat: normalize older providers (previously supported) to OpenAI.
    if config.provider in {"groq", "together", "google"}:
        config.provider = "openai"

    return config


@router.get(
    "/notifications",
    response_model=NotificationSettings,
    summary="Get notification settings",
)
async def get_notification_settings(
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> NotificationSettings:
    """Retrieve notification settings for the current user."""
    row = await _get_user_settings(db, current_user.id)
    if row and row.notification_settings:
        return NotificationSettings(**row.notification_settings)
    return NotificationSettings()


@router.put(
    "/notifications",
    response_model=NotificationSettings,
    summary="Update notification settings",
)
async def update_notification_settings(
    settings: NotificationSettings,
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> NotificationSettings:
    """Update notification settings for the current user."""
    await _upsert_user_settings(
        db,
        current_user.id,
        notification_settings=settings.model_dump(),
    )
    return settings


AI_PROVIDER_ENV_VARS: dict[str, str] = {
    "openai": "OPENAI_API_KEY",
    "custom": "OPENAI_API_KEY",
    "anthropic": "ANTHROPIC_API_KEY",
}


def ai_provider_env_var(provider: str) -> str | None:
    return AI_PROVIDER_ENV_VARS.get(provider)


def get_ai_api_key(provider: str) -> str | None:
    """Return the API key for the selected provider from environment.

    Per deployment policy, we never store provider keys per-user.
    """

    env_var = ai_provider_env_var(provider)
    if not env_var:
        return None
    return os.environ.get(env_var)


def is_ai_key_configured(provider: str) -> bool:
    env_var = ai_provider_env_var(provider)
    if not env_var:
        return False
    return bool(os.environ.get(env_var))


@router.get(
    "/ai",
    summary="Get AI settings",
)
async def get_ai_settings(
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Retrieve AI settings for the current user."""
    config = await load_ai_settings(db, current_user.id)
    s = config or AISettings()

    provider = s.provider
    if provider in {"groq", "together", "google"}:
        provider = "openai"

    return {
        "provider": provider,
        "model": s.model,
        "enabled": s.enabled,
        "api_key_configured": is_ai_key_configured(provider),
        "custom_base_url": s.custom_base_url,
        "custom_model": s.custom_model,
    }


@router.put(
    "/ai",
    summary="Update AI settings",
)
async def update_ai_settings(
    settings: AISettings,
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Update AI settings for the current user."""

    # Backwards-compat: normalize older providers (previously supported) to OpenAI.
    if settings.provider in {"groq", "together", "google"}:
        settings.provider = "openai"

    await _upsert_user_settings(
        db,
        current_user.id,
        ai_settings=settings.model_dump(),
    )

    return {
        "provider": settings.provider,
        "model": settings.model,
        "enabled": settings.enabled,
        "api_key_configured": is_ai_key_configured(settings.provider),
        "custom_base_url": settings.custom_base_url,
        "custom_model": settings.custom_model,
    }


def _is_abuseipdb_key_configured() -> bool:
    return bool(os.environ.get("ABUSEIPDB_API_KEY") or app_settings.abuseipdb_api_key)


@router.get(
    "/threat-intel",
    summary="Get threat intelligence settings",
)
async def get_threat_intel_settings(
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Retrieve threat intelligence settings for the current user."""
    row = await _get_user_settings(db, current_user.id)
    if row and row.threat_intel_settings:
        s = ThreatIntelSettings(**row.threat_intel_settings)
    else:
        s = ThreatIntelSettings()

    return {
        "abuseipdb_enabled": s.abuseipdb_enabled,
        "abuseipdb_api_key_configured": _is_abuseipdb_key_configured(),
        "abuseipdb_max_age": s.abuseipdb_max_age,
    }


@router.put(
    "/threat-intel",
    summary="Update threat intelligence settings",
)
async def update_threat_intel_settings(
    settings: ThreatIntelSettings,
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Update threat intelligence settings for the current user."""
    await _upsert_user_settings(
        db,
        current_user.id,
        threat_intel_settings=settings.model_dump(),
    )

    from app.services.abuseipdb import abuseipdb_service

    abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY") or app_settings.abuseipdb_api_key
    if settings.abuseipdb_enabled and abuseipdb_key:
        abuseipdb_service.api_token = abuseipdb_key

    return {
        "abuseipdb_enabled": settings.abuseipdb_enabled,
        "abuseipdb_api_key_configured": _is_abuseipdb_key_configured(),
        "abuseipdb_max_age": settings.abuseipdb_max_age,
    }


@router.get(
    "/scan-schedule",
    response_model=ScanSchedule,
    summary="Get scan schedule settings",
)
async def get_scan_schedule(
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> ScanSchedule:
    """Retrieve scan schedule settings for the current user."""
    row = await _get_user_settings(db, current_user.id)
    if row and row.scan_schedule:
        return ScanSchedule(**row.scan_schedule)
    return ScanSchedule()


@router.put(
    "/scan-schedule",
    response_model=ScanSchedule,
    summary="Update scan schedule settings",
)
async def update_scan_schedule(
    schedule: ScanSchedule,
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> ScanSchedule:
    """Update scan schedule settings for the current user."""
    await _upsert_user_settings(
        db,
        current_user.id,
        scan_schedule=schedule.model_dump(),
    )
    return schedule


SCAN_FREQUENCIES = [
    {"value": "hourly", "label": "Every Hour"},
    {"value": "daily", "label": "Daily"},
    {"value": "weekly", "label": "Weekly"},
    {"value": "monthly", "label": "Monthly"},
]

SCAN_TYPES = [
    {"value": "quick", "label": "Quick Scan", "description": "Fast scan of common ports"},
    {"value": "full", "label": "Full Scan", "description": "Comprehensive port scan"},
    {"value": "vuln", "label": "Vulnerability Scan", "description": "Security vulnerability detection"},
    {"value": "service", "label": "Service Detection", "description": "Identify running services"},
]


@router.get(
    "/scan-schedule/options",
    summary="Get scan schedule options",
)
async def get_scan_schedule_options(
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Retrieve available scan schedule options."""
    return {
        "frequencies": SCAN_FREQUENCIES,
        "scan_types": SCAN_TYPES,
    }


@router.get(
    "/env-status",
    summary="Get environment variable configuration status",
)
async def get_env_status(
    current_user: User = Depends(get_current_user),
) -> dict[str, bool]:
    """Return configuration status of all environment-based keys."""
    return {
        "openai_api_key": bool(os.environ.get("OPENAI_API_KEY")),
        "anthropic_api_key": bool(os.environ.get("ANTHROPIC_API_KEY")),
        "abuseipdb_api_key": bool(os.environ.get("ABUSEIPDB_API_KEY") or app_settings.abuseipdb_api_key),
        "google_oauth_client_id": bool(os.environ.get("GOOGLE_OAUTH_CLIENT_ID") or app_settings.google_oauth_client_id),
        "google_oauth_client_secret": bool(os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET") or app_settings.google_oauth_client_secret),
    }
