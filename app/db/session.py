from __future__ import annotations

from collections.abc import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.config import settings


engine: AsyncEngine = create_async_engine(
    settings.database_url,
    echo=False,
    future=True,
    # Connection pool settings – sized for a PgBouncer session-mode frontend.
    pool_size=20,
    max_overflow=10,
    pool_pre_ping=True,       # detect stale connections before using them
    pool_recycle=1800,         # recycle connections every 30 min
)


async_session_factory = sessionmaker(
    bind=engine,
    expire_on_commit=False,
    class_=AsyncSession,
)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency that provides an async DB session."""
    async with async_session_factory() as session:
        yield session