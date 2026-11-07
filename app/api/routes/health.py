from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse

from app.core.redis import redis_status
from app.services.nmap_capabilities import detect_capabilities

router = APIRouter()


@router.get("/live", summary="Liveness probe")
async def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready", summary="Readiness probe", response_model=None)
async def ready() -> dict[str, Any] | JSONResponse:
    # nmap is a hard requirement for scanning, so its absence makes this
    # instance degraded. Detection is cached for 300s, keeping polls cheap.
    caps = detect_capabilities()
    # Redis is a cache: losing it costs speed, never correctness, so it is
    # reported rather than failing readiness. The check honours the breaker,
    # so polling during an outage answers immediately instead of each poll
    # waiting out a connect timeout.
    redis_report = await redis_status()
    services: dict[str, Any] = {
        "nmap": {"available": caps.available, "version": caps.version},
        "redis": redis_report,
    }
    if not caps.available:
        return JSONResponse(
            status_code=503,
            content={"status": "degraded", **services},
        )
    return {"status": "ok", **services}
