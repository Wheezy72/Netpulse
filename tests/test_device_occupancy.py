"""A new machine taking an old machine's address must not inherit its identity.

The reported symptom: a Linux VM picked up the lease of a phone that was off,
and the inventory kept calling it a phone. An address is a lease, not an
identity, so a different MAC at a known address replaces what is known about it.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://netpulse:netpulse@localhost:5432/netpulse")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("ENVIRONMENT", "development")

from app.services.device_discovery import (  # noqa: E402
    DiscoveredHost,
    occupant_changed,
    upsert_discovered_hosts,
)

@pytest.fixture
async def db_session():
    """In-memory SQLite session, or skip when the async stack is not installed."""
    pytest.importorskip("sqlalchemy")
    pytest.importorskip("greenlet", reason="SQLAlchemy's async extension requires greenlet")
    pytest.importorskip("aiosqlite")

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.db.base import Base
    from app.models.device import Device  # noqa: F401 - registers the mapper
    from app.models.device_port import DevicePort  # noqa: F401 - registers the mapper

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session

    await engine.dispose()


class TestOccupantChanged:
    def test_same_mac_is_the_same_device(self) -> None:
        host = DiscoveredHost(ip_address="10.0.0.5", mac_address="123A1FAA7FEB", hostname="Immortan")
        assert occupant_changed("123A1FAA7FEB", "Immortan", None, host) is False

    def test_different_name_behind_a_new_mac_is_a_new_device(self) -> None:
        host = DiscoveredHost(
            ip_address="10.0.0.5", mac_address="0A58A9FEAC02", hostname="linux-vm"
        )
        assert occupant_changed("123A1FAA7FEB", "Immortan", None, host) is True

    def test_rotated_private_mac_with_the_same_name_is_the_same_device(self) -> None:
        host = DiscoveredHost(
            ip_address="10.0.0.5", mac_address="0A58A9FEAC02", hostname="Immortan"
        )
        assert occupant_changed("123A1FAA7FEB", "Immortan", None, host) is False

    def test_unknown_mac_never_replaces_a_known_row(self) -> None:
        host = DiscoveredHost(ip_address="10.0.0.5", hostname="mystery")
        assert occupant_changed("123A1FAA7FEB", "Immortan", None, host) is False

    def test_different_vendor_is_a_different_device(self) -> None:
        host = DiscoveredHost(
            ip_address="10.0.0.5", mac_address="AABBCCDDEEFF", vendor="Proxmox Server Solutions"
        )
        assert occupant_changed("123A1FAA7FEB", None, "Apple, Inc.", host) is True


class TestNewOccupantResetsTheRow:
    async def test_stale_hostname_and_type_are_cleared(self, db_session) -> None:
        from sqlalchemy import select

        from app.models.device import Device

        await upsert_discovered_hosts(
            db_session,
            [
                DiscoveredHost(
                    ip_address="192.168.1.55",
                    mac_address="123A1FAA7FEB",
                    hostname="iPhone-de-Immortan",
                    vendor="Private",
                    device_type="phone",
                    os="iOS",
                )
            ],
        )

        # The phone switches off; a VM takes the lease with its own MAC.
        await upsert_discovered_hosts(
            db_session,
            [
                DiscoveredHost(
                    ip_address="192.168.1.55",
                    mac_address="0A58A9FEAC02",
                    hostname="linux-vm",
                )
            ],
        )

        device = (await db_session.execute(select(Device))).scalars().one()
        assert device.hostname == "linux-vm"
        assert device.mac_address == "0A58A9FEAC02"
        assert device.device_type is None
        assert device.os is None
        assert device.vendor is None

    async def test_same_device_keeps_its_description(self, db_session) -> None:
        from sqlalchemy import select

        from app.models.device import Device

        await upsert_discovered_hosts(
            db_session,
            [
                DiscoveredHost(
                    ip_address="192.168.1.20",
                    mac_address="123A1FAA7FEB",
                    hostname="Immortan",
                    device_type="laptop",
                )
            ],
        )
        # A later, shallower sweep reports the same MAC and nothing else.
        await upsert_discovered_hosts(
            db_session, [DiscoveredHost(ip_address="192.168.1.20", mac_address="123A1FAA7FEB")]
        )

        device = (await db_session.execute(select(Device))).scalars().one()
        assert device.hostname == "Immortan"
        assert device.device_type == "laptop"


class TestDerivedFactsFollowTheHardware:
    """The sweep decides the label; a stale one cannot outlive its evidence.

    Reported symptom: a USB Wi-Fi adapter was used once and its vendor block
    landed in the inventory. Every later sweep of the built-in NIC still
    described the machine from that adapter, because the merge only ever
    filled blanks — ``stored or observed`` — so nothing could revise a fact.
    """

    async def test_a_new_sweep_replaces_the_old_cards_description(self, db_session) -> None:
        from sqlalchemy import select

        from app.models.device import Device

        await upsert_discovered_hosts(
            db_session,
            [
                DiscoveredHost(
                    ip_address="192.168.1.10",
                    mac_address="50C7BF112233",  # the USB adapter answers first
                    hostname="Immortan",
                    vendor="TP-Link",
                    device_type="Router",
                    os="Linux/Embedded",
                )
            ],
        )

        # Adapter unplugged; the built-in NIC answers, same address and name,
        # and the sweep derives a different description from it.
        await upsert_discovered_hosts(
            db_session,
            [
                DiscoveredHost(
                    ip_address="192.168.1.10",
                    mac_address="FCA47A112233",
                    hostname="Immortan",
                    vendor="Intel",
                    device_type="Windows Workstation",
                    os="Windows",
                )
            ],
        )

        device = (await db_session.execute(select(Device))).scalars().one()
        assert device.mac_address == "FCA47A112233"
        assert device.vendor == "Intel"
        assert device.device_type == "Windows Workstation"
        assert device.os == "Windows"

    async def test_a_silent_sweep_keeps_the_known_description(self, db_session) -> None:
        from sqlalchemy import select

        from app.models.device import Device

        await upsert_discovered_hosts(
            db_session,
            [
                DiscoveredHost(
                    ip_address="192.168.1.13",
                    mac_address="FCA47A112233",
                    hostname="Immortan",
                    device_type="Windows Workstation",
                    os="Windows",
                )
            ],
        )
        # A shallow ARP-only pass: same card, nothing observed but the address.
        await upsert_discovered_hosts(
            db_session, [DiscoveredHost(ip_address="192.168.1.13", mac_address="FCA47A112233")]
        )

        device = (await db_session.execute(select(Device))).scalars().one()
        assert device.device_type == "Windows Workstation"
        assert device.os == "Windows"
