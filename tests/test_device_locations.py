"""The same hardware must be linked across networks however its MAC is stored.

Legacy rows and different discovery sources write ``F41E5796FBC7`` and
``f4:1e:57:96:fb:c7`` for one NIC. Comparing the column as a string made those
two devices, so the drawer reported a device as never having left the network it
was found on.
"""
from __future__ import annotations

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://netpulse:netpulse@localhost:5432/netpulse")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

import pytest  # noqa: E402


@pytest.fixture
async def db_session():
    pytest.importorskip("sqlalchemy")
    pytest.importorskip("greenlet", reason="SQLAlchemy's async extension requires greenlet")
    pytest.importorskip("aiosqlite")

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.db.base import Base
    from app.models.device import Device  # noqa: F401 - registers the mapper
    from app.models.device_port import DevicePort  # noqa: F401
    from app.models.metric import Metric  # noqa: F401
    from app.models.network import Network  # noqa: F401
    from app.models.scan_job import ScanJob  # noqa: F401
    from app.models.script_job import ScriptJob  # noqa: F401
    from app.models.vulnerability import Vulnerability  # noqa: F401

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session

    await engine.dispose()


async def _seed(db_session):
    from app.models.device import Device
    from app.models.network import Network

    home = Network(key="mac:HOME", name="home", cidr="192.168.1.0/24")
    away = Network(key="mac:AWAY", name="friend's wifi", cidr="192.168.56.0/24")
    db_session.add_all([home, away])
    await db_session.commit()

    laptop = Device(ip_address="192.168.1.50", mac_address="f4:1e:57:96:fb:c7", network_id=home.id)
    compact = Device(ip_address="192.168.56.50", mac_address="F41E5796FBC7", network_id=away.id)
    other = Device(ip_address="192.168.56.51", mac_address="AABBCCDDEEFF", network_id=away.id)
    db_session.add_all([laptop, compact, other])
    await db_session.commit()
    return laptop, compact, other


class TestDeviceLocations:
    async def test_a_mac_written_two_ways_is_one_device(self, db_session):
        from app.api.routes.devices import get_device_detail

        laptop, compact, _other = await _seed(db_session)

        detail = await get_device_detail(laptop.id, db_session)

        found = {location.device_id for location in detail.locations}
        assert found == {laptop.id, compact.id}
        assert {location.network_id for location in detail.locations} == {1, 2}

    async def test_other_hardware_is_not_linked(self, db_session):
        from app.api.routes.devices import get_device_detail

        laptop, _compact, other = await _seed(db_session)

        detail = await get_device_detail(laptop.id, db_session)

        assert other.id not in {location.device_id for location in detail.locations}

    async def test_a_device_without_a_mac_has_no_locations(self, db_session):
        from app.api.routes.devices import get_device_detail
        from app.models.device import Device

        anonymous = Device(ip_address="192.168.1.77")
        db_session.add(anonymous)
        await db_session.commit()

        detail = await get_device_detail(anonymous.id, db_session)

        assert detail.locations == []
