"""Measure the topology endpoint as the inventory grows.

The Eye panel's draw budget was tuned by eye because there was no way to measure
the other half of the cost: how long the server takes to answer and how large the
payload is. This seeds an in-memory SQLite database with N devices on one
network and reports both.

    ./.venv/Scripts/python.exe scripts/bench_topology.py
    ./.venv/Scripts/python.exe scripts/bench_topology.py 50,120,300,1000

It measures the API only. Browser paint and pan/zoom latency still need a
running console with real data.
"""
from __future__ import annotations

import asyncio
import os
import sys
import time

# The app's engine is built at import time from these settings and is never
# connected here; the benchmark runs on its own in-memory SQLite engine.
os.environ.setdefault("SECRET_KEY", "bench-secret-key-not-used")
os.environ.setdefault(
    "DATABASE_URL", "postgresql+asyncpg://netpulse:netpulse@localhost:5432/netpulse"
)
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine  # noqa: E402

from app.api.routes.devices import get_topology  # noqa: E402
from app.db.base import Base  # noqa: E402
from app.models.device import Device  # noqa: E402
from app.models.network import Network  # noqa: E402

DEFAULT_SIZES = (50, 120, 300, 1000)


def _devices(start: int, count: int, network_id: int, mac_offset: int) -> list[Device]:
    """Distinct IPs and MACs, so the endpoint's grouping has nothing to fold."""
    return [
        Device(
            ip_address=f"10.9.{((start + i) // 250) % 250}.{((start + i) % 250) + 1}",
            mac_address=f"02:00:{mac_offset:02X}:{i // 65536:02X}:{(i // 256) % 256:02X}:{i % 256:02X}",
            hostname=f"host-{start + i}",
            device_type="Workstation",
            network_id=network_id,
        )
        for i in range(count)
    ]


async def bench(sizes: tuple[int, ...]) -> None:
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as db:
        network = Network(key="mac:BENCH", name="bench", cidr="10.9.0.0/16")
        db.add(network)
        await db.commit()
        await db.refresh(network)

        added = 0
        mac_offset = 0
        print(f"{'hosts':>6}  {'nodes':>5}  {'server':>9}  {'payload':>9}")
        for size in sizes:
            if size > added:
                db.add_all(_devices(added, size - added, network.id, mac_offset))
                await db.commit()
                added = size
                mac_offset += 1

            started = time.perf_counter()
            topology = await get_topology(db, network_id=network.id)
            elapsed_ms = (time.perf_counter() - started) * 1000
            payload_kib = len(topology.model_dump_json()) / 1024
            print(
                f"{size:>6}  {len(topology.nodes):>5}  {elapsed_ms:>7.1f}ms  {payload_kib:>7.1f}KiB"
            )

    await engine.dispose()


def main() -> None:
    raw = sys.argv[1] if len(sys.argv) > 1 else ""
    sizes = tuple(sorted({int(part) for part in raw.split(",") if part.strip()})) or DEFAULT_SIZES
    asyncio.run(bench(sizes))


if __name__ == "__main__":
    main()
