from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.ext.asyncio import AsyncEngine

from app.api.routes import api_router
from app.core.config import settings
from app.db.base import Base
from app.db.session import engine


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Application lifespan events.

    On startup:
      - Ensure database connectivity and create tables if migrations are not used.
    On shutdown:
      - Dispose the database engine.
    """
    # In production you'd typically use Alembic migrations instead of
    # creating tables on startup, but this provides a sensible default
    # for initial deployments and development environments.
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    try:
        yield
    finally:
        await engine.dispose()


app = FastAPI(
    title=settings.app_name,
    lifespan=lifespan,
)

# CORS - allow frontend by default in development; tighten for production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Adjust in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routes
app.include_router(api_router, prefix="/api")


@app.get("/", include_in_schema=False)
async def root() -> dict[str, str]:
    return {"message": "NetPulse Enterprise API"}