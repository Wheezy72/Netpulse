"""Apply the 2026-10-19 migration: make users.email nullable.

Idempotent: it checks the current column definition first and only runs the
ALTER when needed. Uses the application's own database settings, so you do not
need psql on PATH.

Usage, from the repository root:

    python scripts/apply_email_nullable.py
"""
from __future__ import annotations

import asyncio
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:
    import asyncpg
except ModuleNotFoundError:  # pragma: no cover - dependency guard
    sys.exit("asyncpg is not installed. Run: pip install -r requirements.txt")

from app.core.config import settings  # noqa: E402

CHECK_SQL = """
SELECT is_nullable
FROM information_schema.columns
WHERE table_schema = 'public' AND table_name = 'users' AND column_name = 'email'
"""

ALTER_SQL = "ALTER TABLE users ALTER COLUMN email DROP NOT NULL"


def _asyncpg_url(url: str) -> str:
    """asyncpg wants a plain postgresql:// DSN, not SQLAlchemy's +asyncpg form."""
    return url.replace("postgresql+asyncpg://", "postgresql://", 1)


async def main() -> int:
    url = settings.database_url
    if not url.startswith(("postgresql://", "postgresql+asyncpg://", "postgres://")):
        sys.exit(f"This migration is Postgres-only; configured URL is {url.split(':', 1)[0]}://...")

    dsn = _asyncpg_url(url).replace("postgres://", "postgresql://", 1)
    safe = dsn.split("@")[-1]
    print(f"Connecting to {safe} ...")

    try:
        conn = await asyncpg.connect(dsn, timeout=8)
    except Exception as exc:
        sys.exit(
            "Could not connect: {exc}\n"
            "If the stack runs in Docker, start it first (docker compose up -d), "
            "or apply the SQL inside the container:\n"
            "  docker compose exec db psql -U netpulse -d netpulse "
            "-c \"ALTER TABLE users ALTER COLUMN email DROP NOT NULL\"".format(exc=exc)
        )

    try:
        state = await conn.fetchval(CHECK_SQL)
        if state is None:
            print("The users table does not exist yet. Start the app once so it is created, then re-run.")
            return 1

        if state == "YES":
            print("users.email is already nullable. Nothing to do.")
            return 0

        await conn.execute(ALTER_SQL)
        state_after = await conn.fetchval(CHECK_SQL)
        if state_after != "YES":
            print(f"ALTER ran but the column still reports is_nullable={state_after!r}. Check permissions.")
            return 1

        print("Applied. users.email now allows NULL.")
        return 0
    finally:
        await conn.close()


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
