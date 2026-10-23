from __future__ import annotations

"""
FastAPI application entrypoint.

Responsible for:
- Configuring CORS and security middleware.
- Rate limiting for API protection.
- Mounting the API router under /api.
- Serving the built Vue SPA frontend.

On startup the lifespan handler runs ``Base.metadata.create_all`` so that a
fresh PostgreSQL volume (e.g. after ``docker compose down -v``) is immediately
populated with all tables without requiring a manual ``alembic upgrade head``.
Alembic is still used for production schema migrations; ``create_all`` is
idempotent and safe to run on every boot.
"""

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager, suppress
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
from sqlalchemy import select

from app.api.routes import api_router
from app.core.config import settings
from app.core.redis import close_pool, init_pool
from app.db.base import Base
from app.db.session import engine, async_session_factory
from app.services.passive_monitor import run_passive_monitor
from app.services.logging_service import setup_logging
from app.api.deps import get_password_hash
from app.models.user import User, UserRole

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

    Automatically creates all SQLAlchemy-managed tables on startup so that a
    fresh database volume works out of the box.  ``create_all`` is idempotent –
    existing tables are never dropped or altered, so Alembic migrations remain
    the authoritative mechanism for schema changes in production.
    """
    logger = logging.getLogger("app.main")
    setup_logging()
    await init_pool()

    # Retry database connection on startup to avoid container race conditions
    max_retries = 10
    retry_delay = 3.0
    for attempt in range(1, max_retries + 1):
        try:
            # 1. Create all base tables
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)

            # 2. TimescaleDB is optional. Only Postgres can carry the
            #    extension, and a plain Postgres install or a restricted user
            #    is a normal configuration, not an error worth a full SQL
            #    traceback on every boot.
            if engine.dialect.name == "postgresql":
                try:
                    async with engine.begin() as conn:
                        from sqlalchemy import text
                        await conn.execute(text("CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;"))
                        await conn.execute(text("SELECT create_hypertable('metrics', 'timestamp', if_not_exists => TRUE);"))
                except Exception as exc:
                    logger.info(
                        "TimescaleDB not used (%s); metrics stay in ordinary PostgreSQL tables.",
                        type(exc).__name__,
                    )

            logger.info("Successfully connected to the database and initialized schema.")
            break
        except Exception as e:
            await engine.dispose()  # Dispose pool to prevent PendingRollbackError on subsequent retry attempts
            if attempt == max_retries:
                logger.critical(f"Failed to connect to database after {max_retries} attempts: {e}")
                raise
            logger.warning(f"Database connection attempt {attempt}/{max_retries} failed: {e}. Retrying in {retry_delay}s...")
            await asyncio.sleep(retry_delay)
    # Only pre-create the first admin when a password was actually supplied.
    # An unset BOOTSTRAP_ADMIN_PASSWORD used to be hashed as None (crashing the
    # boot) and the Docker default used to be "changeme" (a known credential).
    # With neither, an empty install shows the first-run setup screen instead.
    if settings.bootstrap_admin_enabled and settings.bootstrap_admin_pass:
        async with async_session_factory() as session:  # type: ignore
            result = await session.execute(select(User).limit(1))  # type: ignore
            if result.scalar_one_or_none() is None:
                bootstrap_user = User(
                    username=settings.bootstrap_admin_username,
                    email=settings.bootstrap_admin_email,
                    full_name=settings.bootstrap_admin_full_name,
                    hashed_password=get_password_hash(settings.bootstrap_admin_password),
                    role=UserRole.ADMIN,
                    force_password_change=True,
                )
                session.add(bootstrap_user)
                await session.commit()  # type: ignore
    passive_monitor_task: asyncio.Task[None] | None = None
    peer_discovery_task: asyncio.Task[None] | None = None
    flow_collector_task: asyncio.Task[None] | None = None
    latency_monitor_task: asyncio.Task[None] | None = None
    scheduled_task: asyncio.Task[None] | None = None

    async def _latency_loop() -> None:
        """Sample Pulse latency/jitter/loss in-process.

        Celery beat only runs in the full stack. Local/dev installs (and any
        deployment without a worker) previously showed an empty Pulse path
        because nothing ever wrote a metric, so the monitor also runs here.
        """
        from app.services.latency_monitor import monitor_latency

        while True:
            try:
                async with async_session_factory() as session:  # type: ignore[union-attr]
                    await monitor_latency(session)
                    await session.commit()
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # keep the loop alive
                logging.getLogger("app.main").warning("Latency monitor tick failed: %s", exc)
            await asyncio.sleep(10)

    # Vulnerability alerts every 5 minutes; the scan reminder once a day.
    _VULN_ALERT_INTERVAL = 300
    _SCAN_REMINDER_INTERVAL = 86400
    # Discovery runs on the same cadence as the alert sweep: without it the
    # inventory (and therefore the topology) only changed when somebody pressed
    # "sweep", which read as a cached map on a live network.
    _DISCOVERY_INTERVAL = 300

    async def _scheduled_task_loop() -> None:
        """Run the jobs Celery beat would have scheduled.

        Same reasoning as the latency loop: without a worker, nothing ever
        evaluated the vulnerability feed or nudged anyone about scheduled
        scans, so a no-Docker install behaved differently from the full stack.
        """
        from app.services.alerts import process_vulnerability_alerts, send_system_alert
        from app.services.device_discovery import run_device_discovery
        from app.services.scan_scheduler import run_due_scheduled_scans

        log = logging.getLogger("app.main")
        last_reminder = 0.0
        last_discovery = 0.0
        log.info(
            "In-process scheduler running: vulnerability alerts every %ss, "
            "device discovery every %ss, scan reminder every %ss "
            "(Celery beat not required).",
            _VULN_ALERT_INTERVAL,
            _DISCOVERY_INTERVAL,
            _SCAN_REMINDER_INTERVAL,
        )

        while True:
            try:
                async with async_session_factory() as session:  # type: ignore[union-attr]
                    await process_vulnerability_alerts(session)
                    await session.commit()
                log.debug("Vulnerability alert sweep complete.")
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # keep the loop alive
                log.warning("Vulnerability alert tick failed: %s", exc)

            # Schedules saved in Settings → Scheduler. This is the reader the
            # tab was missing; without it the toggle did nothing at all.
            try:
                async with async_session_factory() as session:  # type: ignore[union-attr]
                    queued = await run_due_scheduled_scans(session)
                if queued:
                    log.info("Scheduled scan: queued %s job(s).", queued)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # keep the loop alive
                log.warning("Scheduled scan tick failed: %s", exc)

            # Background discovery keeps last_seen honest, retires stale twins
            # and picks up phones that joined since the last pass. It holds the
            # discovery lock, so an operator's manual sweep is never doubled up.
            if time.time() - last_discovery >= _DISCOVERY_INTERVAL:
                last_discovery = time.time()
                try:
                    async with async_session_factory() as session:  # type: ignore[union-attr]
                        outcome = await run_device_discovery(session)
                    if outcome.warnings:
                        log.info(
                            "Discovery sweep skipped: %s", "; ".join(outcome.warnings)
                        )
                    else:
                        log.info(
                            "Discovery sweep: %s new, %s refreshed across %s.",
                            outcome.created,
                            outcome.updated,
                            ", ".join(outcome.subnets) or "no subnets",
                        )
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # keep the loop alive
                    log.warning("Discovery sweep failed: %s", exc)

            # Wall clock, not the loop's monotonic clock: monotonic time starts
            # at zero when the process starts, so a daily reminder would not
            # fire for a full day of uptime and never at all across restarts.
            now = time.time()
            if now - last_reminder >= _SCAN_REMINDER_INTERVAL:
                last_reminder = now
                try:
                    await send_system_alert(
                        "[NetPulse] Scheduled scan reminder",
                        "Time to review and run your scan playbooks.\n"
                        "Typical actions:\n"
                        "  - Verify recon targets are up to date.\n"
                        "  - Run nmap profiles against critical segments.\n"
                        "  - Check the dashboard for new vulnerabilities.",
                        event_type="scan",
                    )
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    log.warning("Scan reminder failed: %s", exc)
                else:
                    log.info("Daily scan-reminder alert sent.")

            await asyncio.sleep(_VULN_ALERT_INTERVAL)

    try:
        # Start peer discovery on the local network segment
        from app.services.peer_discovery import start_peer_discovery
        peer_discovery_task = asyncio.create_task(start_peer_discovery())

        # Start NetFlow flow collector daemon
        from app.services.flow_collector import start_flow_collector
        flow_collector_task = asyncio.create_task(start_flow_collector())

        if settings.enable_passive_monitor:
            passive_monitor_task = asyncio.create_task(run_passive_monitor())

        if settings.enable_latency_monitor:
            latency_monitor_task = asyncio.create_task(_latency_loop())

        if settings.enable_scheduled_tasks:
            scheduled_task = asyncio.create_task(_scheduled_task_loop())
        yield
    finally:
        if peer_discovery_task is not None:
            peer_discovery_task.cancel()
            with suppress(asyncio.CancelledError):
                await peer_discovery_task
        if flow_collector_task is not None:
            flow_collector_task.cancel()
            with suppress(asyncio.CancelledError):
                await flow_collector_task
        if passive_monitor_task is not None:
            passive_monitor_task.cancel()
            with suppress(asyncio.CancelledError):
                await passive_monitor_task
        if latency_monitor_task is not None:
            latency_monitor_task.cancel()
            with suppress(asyncio.CancelledError):
                await latency_monitor_task
        if scheduled_task is not None:
            scheduled_task.cancel()
            with suppress(asyncio.CancelledError):
                await scheduled_task
        await engine.dispose()
        await close_pool()


# The interactive docs are a development convenience. In production they
# advertise every route and schema, so they follow ENVIRONMENT rather than a
# `debug` setting that never existed (which used to leave them always on).
_docs_enabled = settings.environment == "development"

app = FastAPI(
    title=settings.app_name,
    lifespan=lifespan,
    docs_url="/api/docs" if _docs_enabled else None,
    redoc_url="/api/redoc" if _docs_enabled else None,
    openapi_url="/api/openapi.json" if _docs_enabled else None,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)  # type: ignore

from slowapi.middleware import SlowAPIMiddleware
app.add_middleware(SlowAPIMiddleware)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestValidationMiddleware)

# A wildcard origin together with credentials is rejected by every browser,
# so the wildcard was never usable — it only looked permissive. The configured
# list covers the SPA (same origin in production) and the Vite dev server,
# whose proxy makes API calls same-origin as well.
_cors_origins = list(settings.cors_allow_origins or [])

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


@app.get("/api/security/status", include_in_schema=False)
async def security_status() -> dict:
    """Return security status information.

    Registered before the SPA catch-all: Starlette matches in registration
    order, so a route declared after ``/{catchall:path}`` was unreachable and
    answered "API endpoint not found".
    """
    return {
        "rate_limiting": "enabled",
        "security_headers": "enabled",
        "input_validation": "enabled",
        "cors_protection": "enabled",
        "request_size_limit": "10MB",
    }


def _frontend_dir() -> str:
    """Locate the built SPA for both Docker and bare-metal Linux installs.

    The container puts it at /app/static; a checkout that ran `npm run build`
    has it in frontend/dist. Returning the first directory that actually has
    an index.html keeps `uvicorn app.main:app` usable on a Linux host without
    a separate web server.
    """
    from pathlib import Path

    project_root = Path(__file__).resolve().parent.parent
    candidates = [
        project_root / "static",
        Path.cwd() / "frontend" / "dist",
        project_root / "frontend" / "dist",
        Path("/app/static"),
    ]
    for candidate in candidates:
        if (candidate / "index.html").is_file():
            return str(candidate)
    return str(candidates[0])


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

    static_dir = _frontend_dir()
    root = os.path.realpath(static_dir)
    requested = os.path.realpath(os.path.join(root, catchall))

    # Resolve first, then confirm the result stayed inside the build directory
    # so a crafted path cannot read files elsewhere on the host.
    if (
        catchall
        and requested.startswith(root + os.sep)
        and os.path.isfile(requested)
    ):
        return FileResponse(requested)

    index_path = os.path.join(root, "index.html")
    if os.path.isfile(index_path):
        return FileResponse(index_path)

    return JSONResponse(
        status_code=404,
        content={
            "error": (
                "Frontend build not found. Run 'cd frontend && npm run build' "
                "or use the Vite dev server."
            )
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    """Return HTTP errors in a consistent JSON envelope.

    ``exc.headers`` is forwarded so challenges and retry hints survive the
    envelope — a 401 without ``WWW-Authenticate`` is not a valid challenge.
    """
    return JSONResponse(
        status_code=exc.status_code,
        content={"error": {"code": exc.status_code, "message": exc.detail}},
        headers=exc.headers,
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
    logger = logging.getLogger("app.main")
    logger.error(
        "Unhandled exception during %s %s: %s",
        request.method,
        request.url.path,
        exc,
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={"error": {"code": 500, "message": "Internal server error"}},
    )
