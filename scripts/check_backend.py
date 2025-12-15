from __future__ import annotations

"""
check_backend.py

Quick diagnostics script for NetPulse backend services.

It checks:
  - PostgreSQL connectivity and basic queries.
  - Presence and accessibility of the User table.
  - Redis connectivity.

Run from the repo root (with the virtualenv active):

  source .venv/bin/activate
  python scripts/check_backend.py
"""

import asyncio
from typing import Optional

from sqlalchemy import text, select
from sqlalchemy.exc import SQLAlchemyError

from app.core.config import settings
from app.db.session import engine, async_session_factory
from app.models.user import User

try:
    import redis.asyncio as redis  # type: ignore[import]
except Exception:  # pragma: no cover - optional dependency guard
    redis = None  # type: ignore[assignment]


async def check_postgres() -> None:
    print("==> Checking PostgreSQL connectivity")
    print(f"    database_url = {settings.database_url!r}")

    # 1) Raw connection / SELECT 1
    try:
        async with engine.begin() as conn:
            await conn.execute(text("SELECT 1"))
        print("  [OK] Connected to PostgreSQL and executed SELECT 1.")
    except SQLAlchemyError as exc:
        print("  [FAIL] PostgreSQL connection failed:")
        print(f"        {exc!r}")
        return

    # 2) Check that the users table is accessible via SQLAlchemy
    try:
        async with async_session_factory() as session:
            result = await session.execute(select(User).limit(1))
            user: Optional[User] = result.scalar_one_or_none()
        if user is None:
            print("  [OK] User table is accessible (no users found yet).")
        else:
            print(f"  [OK] User table is accessible (at least one user: {user.email}).")
    except SQLAlchemyError as exc:
        print("  [FAIL] Querying User table failed:")
        print(f"        {exc!r}")


async def check_redis() -> None:
    print("==> Checking Redis connectivity")
    print(f"    redis_url = {settings.redis_url!r}")

    if redis is None:
        print("  [WARN] redis-py is not installed; skipping Redis check.")
        return

    try:
        client = redis.from_url(settings.redis_url)
        pong = await client.ping()
        print(f"  [OK] Redis PING returned: {pong!r}")
    except Exception as exc:  # noqa: BLE001
        print("  [FAIL] Redis connection failed:")
        print(f"        {exc!r}")
    finally:
        try:
            await client.close()  # type: ignore[func-returns-value]
        except Exception:  # noqa: BLE001
            pass


async def main() -> None:
    await check_postgres()
    print()
    await check_redis()


if __name__ == "__main__":
    asyncio.run(main())