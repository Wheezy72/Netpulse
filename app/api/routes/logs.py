"""
Logs API Routes

Provides endpoints for viewing application logs in the UI.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, Query

from app.api.deps import get_current_user
from app.models.user import User
from app.services.logging_service import memory_handler

router = APIRouter()


@router.get(
    "",
    summary="Get application logs",
)
async def get_logs(
    level: Optional[str] = Query(None, description="Filter by log level"),
    logger: Optional[str] = Query(None, description="Filter by logger name"),
    search: Optional[str] = Query(None, description="Search in message/module"),
    limit: int = Query(100, ge=1, le=500, description="Number of logs to return"),
    offset: int = Query(0, ge=0, description="Offset for pagination"),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Get recent application logs with optional filtering."""
    logs = memory_handler.get_logs(
        level=level,
        logger_filter=logger,
        search=search,
        limit=limit,
        offset=offset,
    )
    
    return {
        "logs": [log.to_dict() for log in logs],
        "total": len(memory_handler.logs),
        "offset": offset,
        "limit": limit,
    }


@router.get(
    "/stats",
    summary="Get log statistics",
)
async def get_log_stats(
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    """Get log level statistics."""
    return memory_handler.get_stats()


@router.delete(
    "",
    summary="Clear in-memory logs",
)
async def clear_logs(
    current_user: User = Depends(get_current_user),
) -> dict[str, str]:
    """Clear all in-memory logs. File logs are preserved."""
    memory_handler.clear()
    return {"message": "In-memory logs cleared successfully"}
