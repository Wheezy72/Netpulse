from __future__ import annotations

from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import get_db


# Re-export DB dependency for convenience
async def db_session() -> AsyncSession:
    async for session in get_db():
        return session