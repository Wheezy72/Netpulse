from __future__ import annotations

"""Global Redis connection pool for the NetPulse backend.

The pool is initialised once during the FastAPI application lifespan
(startup) and torn down on shutdown.  All coroutines that need Redis
should call ``get_redis()`` to obtain a client that shares the same
underlying socket pool rather than opening a new connection per request.

Redis is a cache here, never the source of truth: every caller has a database
fallback. That only holds up if a broken Redis fails *quickly*. Without an
explicit socket timeout the operating system decides how long to wait for a
host that never answers, which on a misconfigured ``REDIS_URL`` is tens of
seconds — and the first place a person notices is a sign-in that appears to
hang after the password. So each attempt is capped, and one failure opens a
breaker so the next twenty seconds of requests skip Redis entirely instead of
paying the timeout again.
"""

import logging
import time

import redis.asyncio as aioredis

from app.core.config import settings

logger = logging.getLogger("netpulse.redis")

_pool: aioredis.ConnectionPool | None = None

# How long to stop trying after one failure. Short enough that a Redis which
# comes back is used again without a restart, long enough that a burst of
# requests does not each rediscover that it is down.
COOLDOWN_SECONDS = 20.0

_down_until: float = 0.0
_last_error: str | None = None


def redis_reachable() -> bool:
    """False while the breaker is open, i.e. Redis failed in the last cooldown.

    Callers check this before touching Redis so the database fallback they
    already have runs immediately rather than after a connect timeout.
    """
    return time.monotonic() >= _down_until


def note_redis_failure(exc: BaseException) -> None:
    """Record a failed call and open the breaker for ``COOLDOWN_SECONDS``."""
    global _down_until, _last_error
    detail = str(exc).strip()
    message = f"{type(exc).__name__}: {detail}" if detail else type(exc).__name__
    if redis_reachable():
        # One line per outage rather than one per request.
        logger.warning(
            "Redis unavailable, using database fallbacks for %.0fs: %s",
            COOLDOWN_SECONDS,
            message,
        )
    _down_until = time.monotonic() + COOLDOWN_SECONDS
    _last_error = message


def note_redis_success() -> None:
    """A call completed: close the breaker and forget the last error."""
    global _down_until, _last_error
    _down_until = 0.0
    _last_error = None


def last_redis_error() -> str | None:
    """The last failure, for health reporting."""
    return _last_error


def get_redis() -> aioredis.Redis:
    """Return a Redis client backed by the shared connection pool.

    The pool must have been initialised via ``init_pool()`` before this
    is called.  The FastAPI lifespan handler guarantees that for every
    live request.
    """
    if _pool is None:
        raise RuntimeError(
            "Redis connection pool has not been initialised. "
            "Ensure init_pool() is called during application startup."
        )
    return aioredis.Redis(connection_pool=_pool)


async def init_pool() -> None:
    """Create the shared connection pool.  Called once at app startup."""
    global _pool
    _pool = aioredis.ConnectionPool.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True,
        socket_connect_timeout=settings.redis_connect_timeout,
        socket_timeout=settings.redis_socket_timeout,
    )


async def close_pool() -> None:
    """Drain and close the connection pool.  Called once at app shutdown."""
    global _pool
    if _pool is not None:
        await _pool.aclose()
        _pool = None
