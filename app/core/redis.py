from __future__ import annotations

"""Global Redis connection pool for the NetPulse backend.

The pool is initialised once during the FastAPI application lifespan
(startup) and torn down on shutdown.  All coroutines that need Redis
should call ``get_redis()`` to obtain a client that shares the same
underlying socket pool rather than opening a new connection per request.
"""

import redis.asyncio as aioredis

from app.core.config import settings

_pool: aioredis.ConnectionPool | None = None


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
    )


async def close_pool() -> None:
    """Drain and close the connection pool.  Called once at app shutdown."""
    global _pool
    if _pool is not None:
        await _pool.aclose()
        _pool = None
