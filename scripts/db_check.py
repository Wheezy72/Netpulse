import asyncio
import os
import sys

from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine

from redis import asyncio as redis_async  # type: ignore[import]



# Ensure the repo root (where the `app` package lives) is on sys.path
ROOT_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)



async def check_database() -> None:
    from app.core.config import settings

    print("==> Checking database connectivity")
    print("Using database URL:", settings.database_url)
    engine = create_async_engine(settings.database_url, echo=False)
    try:
        async with engine.begin() as conn:
            result = await conn.execute(text("SELECT 1"))
            print("DB check OK, result:", result.scalar())
    except Exception as exc:  # noqa: BLE001
        print("DB check FAILED:", repr(exc))
    finally:
        await engine.dispose()



async def check_redis() -> None:
    from app.core.config import settings

    print("\n==> Checking Redis connectivity")
    print("Using Redis URL:", settings.redis_url)
    client = redis_async.from_url(settings.redis_url)
    try:
        pong = await client.ping()
        print("Redis check OK, response:", pong)
    except Exception as exc:  # noqa: BLE001
        print("Redis check FAILED:", repr(exc))
    finally:
        await client.close()



async def main() -> None:
    await check_database()
    await check_redis()



if __name__ == "__main__":
    asyncio.run(main())