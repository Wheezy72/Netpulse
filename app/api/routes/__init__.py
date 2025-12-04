from fastapi import APIRouter

from app.api.routes import devices, health, recon, scripts, vault

api_router = APIRouter()
api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(scripts.router, prefix="/scripts", tags=["scripts"])
api_router.include_router(recon.router, prefix="/recon", tags=["recon"])
api_router.include_router(devices.router, prefix="/devices", tags=["devices"])
api_router.include_router(vault.router, prefix="/vault", tags=["vault"])