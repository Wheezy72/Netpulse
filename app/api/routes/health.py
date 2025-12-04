from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()


@router.get("/live", summary="Liveness probe")
async def live() -> dict[str, str]:
    return {"status": "ok"}


@router.get("/ready", summary="Readiness probe")
async def ready() -> dict[str, str]:
    # In a more complete implementation, this would check DB/Redis connectivity.
    return {"status": "ok"}