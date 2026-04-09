from __future__ import annotations

"""
FastAPI application entrypoint.

Responsible for:
- Configuring CORS and security middleware.
- Rate limiting for API protection.
- Mounting the API router under /api.
- Serving the built Vue SPA frontend.

Database schema changes are exclusively handled via Alembic migrations.
The `create_all` call has been removed; run `alembic upgrade head` before
starting the app for the first time or after adding new migrations.
"""

import os
from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, FileResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.api.routes import api_router
from app.core.config import settings
from app.core.redis import close_pool, init_pool
from app.db.session import engine
from app.services.logging_service import setup_logging

import app.models  # noqa: F401 – ensure all models are registered with SQLAlchemy


limiter = Limiter(key_func=get_remote_address, default_limits=["200/minute"])


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add security headers to all responses."""

    async def dispatch(self, request: Request, call_next) -> Response:
        response = await call_next(request)

        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"

        if request.url.path.startswith("/api"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"

        return response


class RequestValidationMiddleware(BaseHTTPMiddleware):
    """Validate and sanitize incoming requests."""

    MAX_CONTENT_LENGTH = 10 * 1024 * 1024

    async def dispatch(self, request: Request, call_next) -> Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > self.MAX_CONTENT_LENGTH:
                    return JSONResponse(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        content={"error": {"code": 413, "message": "Request too large"}}
                    )
            except ValueError:
                pass

        return await call_next(request)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """FastAPI lifespan handler.

    Schema management: use `alembic upgrade head` before starting the app.
    Recurring monitoring jobs are scheduled via Celery Beat – not in this process.
    """
    setup_logging()
    await init_pool()
    try:
        yield
    finally:
        await engine.dispose()
        await close_pool()


app = FastAPI(
    title=settings.app_name,
    lifespan=lifespan,
    docs_url="/api/docs" if getattr(settings, "debug", True) else None,
    redoc_url="/api/redoc" if getattr(settings, "debug", True) else None,
    openapi_url="/api/openapi.json" if getattr(settings, "debug", True) else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

from slowapi.middleware import SlowAPIMiddleware
app.add_middleware(SlowAPIMiddleware)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestValidationMiddleware)

_cors_origins = (
    ["*"]
    if settings.environment == "development"
    else getattr(settings, "cors_allow_origins", ["http://localhost:8000"])
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-Requested-With", "X-CSRF-Token"],
    expose_headers=["X-Report-Name"],
    max_age=600,
)

app.include_router(api_router, prefix="/api")


@app.get("/{catchall:path}", include_in_schema=False)
async def serve_vue_spa(catchall: str):
    """Catch-all route to serve the built Vue.js frontend.

    Serves static assets directly; falls back to index.html so Vue Router
    handles client-side navigation.
    """
    if catchall.startswith("api/"):
        return JSONResponse(
            status_code=404,
            content={"error": {"code": 404, "message": "API endpoint not found"}}
        )

    static_dir = "/app/static"
    file_path = os.path.join(static_dir, catchall)

    if catchall and os.path.isfile(file_path):
        return FileResponse(file_path)

    index_path = os.path.join(static_dir, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)

    return JSONResponse(
        status_code=404,
        content={"error": "Frontend build not found in /app/static"}
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Return HTTP errors in a consistent JSON envelope."""
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.status_code, "message": exc.detail}},
    )


@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request, exc: RequestValidationError
) -> JSONResponse:
    """Return request validation errors with field-level details."""
    sanitized_errors = [
        {
            "loc": error.get("loc", []),
            "msg": error.get("msg", "Validation error"),
            "type": error.get("type", "value_error"),
        }
        for error in exc.errors()
    ]
    return JSONResponse(
        status_code=422,
        content={
            "error": {
                "code": 422,
                "message": "Validation error",
                "details": sanitized_errors,
            }
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Catch-all handler – prevents leaking internal details to clients."""
    return JSONResponse(
        status_code=500,
        content={"error": {"code": 500, "message": "Internal server error"}},
    )


@app.get("/api/security/status", include_in_schema=False)
async def security_status() -> dict:
    """Return security status information."""
    return {
        "rate_limiting": "enabled",
        "security_headers": "enabled",
        "input_validation": "enabled",
        "cors_protection": "enabled",
        "request_size_limit": "10MB",
    }
