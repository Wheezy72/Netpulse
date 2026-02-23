from __future__ import annotations

import os
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, get_current_user
from app.core.config import settings as app_settings
from app.models.user import User

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


_notification_settings: dict[int, NotificationSettings] = {}
_ai_settings: dict[int, AISettings] = {}
_threat_intel_settings: dict[int, ThreatIntelSettings] = {}
_scan_schedules: dict[int, ScanSchedule] = {}


@router.get(
    "/notifications",
    response_model=NotificationSettings,
    summary="Get notification settings",
)
async def get_notification_settings(
    current_user: User = Depends(get_current_user),
) -> NotificationSettings:
    """Retrieve notification settings for the current user."""
    user_id = current_user.id
    if user_id in _notification_settings:
        return _notification_settings[user_id]
    return NotificationSettings()


@router.put(
    "/notifications",
    response_model=NotificationSettings,
    summary="Update notification settings",
)
async def update_notification_settings(
    settings: NotificationSettings,
    current_user: User = Depends(get_current_user),
) -> NotificationSettings:
    """Update notification settings for the current user."""
    user_id = current_user.id
    _notification_settings[user_id] = settings
    return settings


def _is_ai_key_configured(provider: str) -> bool:
    env_map = {
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "google": "GOOGLE_AI_API_KEY",
        "groq": "GROQ_API_KEY",
        "together": "TOGETHER_API_KEY",
    }
    env_var = env_map.get(provider)
    if env_var:
        return bool(os.environ.get(env_var))
    return False


@router.get(
    "/ai",
    summary="Get AI settings",
)
async def get_ai_settings(
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Retrieve AI settings for the current user."""
    user_id = current_user.id
    if user_id in _ai_settings:
        s = _ai_settings[user_id]
        return {
            "provider": s.provider,
            "model": s.model,
            "enabled": s.enabled,
            "api_key_configured": _is_ai_key_configured(s.provider),
            "custom_base_url": s.custom_base_url,
            "custom_model": s.custom_model,
        }
    defaults = AISettings()
    return {
        **defaults.model_dump(),
        "api_key_configured": _is_ai_key_configured(defaults.provider),
    }


@router.put(
    "/ai",
    summary="Update AI settings",
)
async def update_ai_settings(
    settings: AISettings,
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Update AI settings for the current user."""
    user_id = current_user.id
    _ai_settings[user_id] = settings
    
    return {
        "provider": settings.provider,
        "model": settings.model,
        "enabled": settings.enabled,
        "api_key_configured": _is_ai_key_configured(settings.provider),
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
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Retrieve threat intelligence settings for the current user."""
    user_id = current_user.id
    if user_id in _threat_intel_settings:
        s = _threat_intel_settings[user_id]
        return {
            "abuseipdb_enabled": s.abuseipdb_enabled,
            "abuseipdb_api_key_configured": _is_abuseipdb_key_configured(),
            "abuseipdb_max_age": s.abuseipdb_max_age,
        }
    defaults = ThreatIntelSettings()
    return {
        **defaults.model_dump(),
        "abuseipdb_api_key_configured": _is_abuseipdb_key_configured(),
    }


@router.put(
    "/threat-intel",
    summary="Update threat intelligence settings",
)
async def update_threat_intel_settings(
    settings: ThreatIntelSettings,
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Update threat intelligence settings for the current user."""
    user_id = current_user.id
    _threat_intel_settings[user_id] = settings
    
    from app.services.abuseipdb import abuseipdb_service
    abuseipdb_key = os.environ.get("ABUSEIPDB_API_KEY") or app_settings.abuseipdb_api_key
    if settings.abuseipdb_enabled and abuseipdb_key:
        abuseipdb_service.api_key = abuseipdb_key
    
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
    current_user: User = Depends(get_current_user),
) -> ScanSchedule:
    """Retrieve scan schedule settings for the current user."""
    user_id = current_user.id
    if user_id in _scan_schedules:
        return _scan_schedules[user_id]
    return ScanSchedule()


@router.put(
    "/scan-schedule",
    response_model=ScanSchedule,
    summary="Update scan schedule settings",
)
async def update_scan_schedule(
    schedule: ScanSchedule,
    current_user: User = Depends(get_current_user),
) -> ScanSchedule:
    """Update scan schedule settings for the current user."""
    user_id = current_user.id
    _scan_schedules[user_id] = schedule
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
        "google_ai_api_key": bool(os.environ.get("GOOGLE_AI_API_KEY")),
        "groq_api_key": bool(os.environ.get("GROQ_API_KEY")),
        "together_api_key": bool(os.environ.get("TOGETHER_API_KEY")),
        "abuseipdb_api_key": bool(os.environ.get("ABUSEIPDB_API_KEY") or app_settings.abuseipdb_api_key),
        "google_oauth_client_id": bool(os.environ.get("GOOGLE_OAUTH_CLIENT_ID") or app_settings.google_oauth_client_id),
        "google_oauth_client_secret": bool(os.environ.get("GOOGLE_OAUTH_CLIENT_SECRET") or app_settings.google_oauth_client_secret),
    }
