from __future__ import annotations

"""
FastAPI application entrypoint.

Responsible for:
- Initialising the database schema (for simple deployments).
- Configuring CORS.
- Mounting the API router under /api.
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
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

# CORS configuration.
# For local development we allow the default frontend origin; in production
# you should set Settings.cors_allow_origins explicitly.
app.add_middleware(
    CORSMiddleware,
    allow_origins=getattr(settings, "cors_allow_origins", ["http://localhost:8080"]),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Mount API routes under /api
app.include_router(api_router, prefix="/api")


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Return HTTP errors in a consistent JSON envelope."""
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": exc.status_code,
                "message": exc.detail,
            }
        },
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Return request validation errors with field-level details."""
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": 422,
                "message": "Validation error",
                "details": exc.errors(),
            }
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler to avoid leaking internal details to clients."""
    # In production, hook this into structured logging or an APM solution.
    return JSONResponse(
        status_code=500,
        content={
            "error": {
                "code": 500,
                "message": "Internal server error",
            }
        },
    )


@app.get("/", include_in_schema=False)
async def root() -> dict[str, str]:
    return {"message": "NetPulse Enterprise API"}