from fastapi import APIRouter

from app.api.routes import health, recon, scripts

api_router = APIRouter()
api_router.include_router(health.router, prefix="/health", tags=["health"])
api_router.include_router(scripts.router, prefix="/scripts", tags=["scripts"])
api_router.include_router(recon.router, prefix="/recon", tags=["recon"])