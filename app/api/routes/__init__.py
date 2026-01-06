from fastapi import APIRouter

from app.api.routes import auth, devices, health, metrics, recon, scripts, vault, ws
from app.api.routes import assist

api_router = APIRouter()
api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(scripts.router, prefix="/scripts", tags=["scripts"])
api_router.include_router(recon.router, prefix="/recon", tags=["recon"])
api_router.include_router(devices.router, prefix="/devices", tags=["devices"])
api_router.include_router(metrics.router, prefix="/metrics", tags=["metrics"])
api_router.include_router(vault.router, prefix="/vault", tags=["vault"])
api_router.include_router(ws.router, prefix="/ws", tags=["ws"])
api_router.include_router(assist.router, prefix="/assist", tags=["assist"])