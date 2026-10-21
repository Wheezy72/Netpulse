from __future__ import annotations

from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse

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
    if not caps.available:
        return JSONResponse(
            status_code=503,
            content={
                "status": "degraded",
                "nmap": {"available": False, "version": None},
            },
        )
    return {"status": "ok", "nmap": {"available": True, "version": caps.version}}
