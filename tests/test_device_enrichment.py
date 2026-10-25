"""Unit tests for the per-device deep scan and the persistence paths.

The parsing tests are pure. The persistence tests use in-memory SQLite and skip
themselves when SQLAlchemy is unavailable, so the suite still runs in the
minimal CI environment that installs neither SQLAlchemy nor aiosqlite.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://netpulse:netpulse@localhost:5432/netpulse")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("ENVIRONMENT", "development")

from app.core.config import settings  # noqa: E402
from app.services.device_discovery import DiscoveredHost, upsert_discovered_hosts  # noqa: E402
from app.services.device_enrichment import (  # noqa: E402
    PortObservation,
    ports_from_scan_data,
    scan_device_ports,
    upsert_device_ports,
)


# --------------------------------------------------------------------- parsing


class TestPortParsing:
    def test_keeps_only_listening_ports(self) -> None:
        scan_data = {
            "10.0.0.5": {
                "tcp": {
                    80: {"state": "open", "name": "http", "product": "nginx", "version": "1.18.0"},
                    22: {"state": "closed", "name": "ssh"},
                    443: {"state": "filtered", "name": "https"},
                    8080: {"state": "open|filtered", "name": "http-proxy"},
                }
            }
        }
        ports = ports_from_scan_data(scan_data)
        assert [(p.port, p.protocol) for p in ports] == [(80, "tcp"), (8080, "tcp")]
        assert ports[0].service == "http"
        assert ports[0].product == "nginx"
        assert ports[0].version == "1.18.0"

    def test_includes_udp_and_sorts(self) -> None:
        scan_data = {
            "10.0.0.5": {
                "udp": {161: {"state": "open", "name": "snmp"}},
                "tcp": {22: {"state": "open", "name": "ssh"}},
            }
        }
        ports = ports_from_scan_data(scan_data)
        assert [(p.protocol, p.port) for p in ports] == [("tcp", 22), ("udp", 161)]

    def test_flattens_script_output_into_banner(self) -> None:
        scan_data = {
            "10.0.0.5": {
                "tcp": {
                    22: {
                        "state": "open",
                        "name": "ssh",
                        "script": {"ssh-hostkey": "2048 SHA256:abc", "banner": "SSH-2.0-OpenSSH_8.9"},
                    }
                }
            }
        }
        banner = ports_from_scan_data(scan_data)[0].banner
        assert banner is not None
        assert "ssh-hostkey" in banner
        assert "OpenSSH_8.9" in banner

    def test_tolerates_junk(self) -> None:
        assert ports_from_scan_data({}) == []
        assert ports_from_scan_data({"10.0.0.5": "nope"}) == []
        assert ports_from_scan_data({"10.0.0.5": {"tcp": {"not-a-port": {"state": "open"}}}}) == []
        assert ports_from_scan_data({"10.0.0.5": {"tcp": {80: "nope"}}}) == []


class TestScanGuards:
    async def test_refuses_invalid_target(self) -> None:
        ports, warnings = await scan_device_ports("not an ip; rm -rf /")
        assert ports == []
        assert warnings and "invalid target" in warnings[0]

    async def test_refuses_restricted_target(self, monkeypatch) -> None:
        monkeypatch.setattr(settings, "restricted_vlan_cidrs", ["10.20.0.0/16"])
        monkeypatch.setattr(settings, "medical_iot_vlan_cidrs", [])

        ports, warnings = await scan_device_ports("10.20.1.5")
        assert ports == []
        assert warnings and "restricted" in warnings[0].lower()


# ----------------------------------------------------------------- persistence


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


class TestUpsertDiscoveredHosts:
    async def test_creates_then_refreshes(self, db_session) -> None:
        from sqlalchemy import select

        from app.models.device import Device

        created, updated = await upsert_discovered_hosts(
            db_session,
            [DiscoveredHost(ip_address="10.0.0.5", mac_address="B827EB112233", hostname="pi.hole")],
        )
        assert (created, updated) == (1, 0)

        # Second sweep of the same host updates rather than duplicating.
        created, updated = await upsert_discovered_hosts(
            db_session,
            [DiscoveredHost(ip_address="10.0.0.5", mac_address="B827EB112233", vendor="Raspberry Pi")],
        )
        assert (created, updated) == (0, 1)

        rows = (await db_session.execute(select(Device))).scalars().all()
        assert len(rows) == 1
        assert rows[0].hostname == "pi.hole"  # not clobbered by the empty value
        assert rows[0].vendor == "Raspberry Pi"  # blank filled in
        assert rows[0].last_seen is not None

    async def test_preserves_richer_data_but_follows_mac_changes(self, db_session) -> None:
        from sqlalchemy import select

        from app.models.device import Device

        # Discovery paths emit canonical 12-hex MACs (see normalize_mac).
        await upsert_discovered_hosts(
            db_session,
            [DiscoveredHost(ip_address="10.0.0.6", mac_address="AABBCC000001", device_type="Router")],
        )
        await upsert_discovered_hosts(
            db_session,
            [DiscoveredHost(ip_address="10.0.0.6", mac_address="AABBCC000002")],
        )

        device = (await db_session.execute(select(Device))).scalars().one()
        assert device.device_type == "Router"  # a shallow sweep must not erase it
        assert device.mac_address == "AABBCC000002"  # a MAC change is a real signal

    async def test_follows_a_randomised_host_that_lost_its_mac(self, db_session) -> None:
        """A host found by ICMP alone has no ARP entry, so no MAC.

        That used to look like a brand-new machine and created a second row
        under the same name; the identity now follows the unique hostname.
        """
        from sqlalchemy import select

        from app.models.device import Device

        # 0x12 sets the locally-administered bit: a randomised/private MAC.
        await upsert_discovered_hosts(
            db_session,
            [
                DiscoveredHost(
                    ip_address="10.0.0.20",
                    mac_address="123A1FAA7FEB",
                    hostname="Immortan",
                    device_type="Windows Workstation",
                )
            ],
        )

        created, updated = await upsert_discovered_hosts(
            db_session,
            [DiscoveredHost(ip_address="10.0.0.22", hostname="Immortan")],
        )
        assert (created, updated) == (0, 1)

        device = (await db_session.execute(select(Device))).scalars().one()
        assert device.ip_address == "10.0.0.22"
        assert device.device_type == "Windows Workstation"

    async def test_retires_a_macless_twin_of_a_live_row(self, db_session) -> None:
        """The ghost left by the old address-keyed upsert has no MAC at all."""
        from sqlalchemy import select

        from app.models.device import Device

        db_session.add(
            Device(ip_address="10.0.0.102", hostname="Immortan", device_type="Windows Workstation")
        )
        await db_session.flush()

        await upsert_discovered_hosts(
            db_session,
            [
                DiscoveredHost(
                    ip_address="10.0.0.100",
                    mac_address="123A1FAA7FEB",
                    hostname="Immortan",
                    device_type="Windows Workstation",
                )
            ],
        )

        rows = (await db_session.execute(select(Device))).scalars().all()
        assert len(rows) == 1
        assert rows[0].ip_address == "10.0.0.100"

    async def test_folds_a_macless_twin_even_when_it_answered(self, db_session) -> None:
        """Both addresses reply, only one can be identified by MAC.

        That is what the router-side ARP table shows when a machine holds two
        addresses: the topology should still draw one node, not two.
        """
        from sqlalchemy import select

        from app.models.device import Device

        db_session.add(Device(ip_address="10.0.0.102", hostname="Immortan"))
        await db_session.flush()

        await upsert_discovered_hosts(
            db_session,
            [
                DiscoveredHost(ip_address="10.0.0.100", mac_address="123A1FAA7FEB", hostname="Immortan"),
                DiscoveredHost(ip_address="10.0.0.102", hostname="Immortan"),
            ],
        )

        rows = (await db_session.execute(select(Device))).scalars().all()
        assert [row.ip_address for row in rows] == ["10.0.0.100"]

    async def test_one_sweep_does_not_add_a_macless_twin(self, db_session) -> None:
        """Same sweep, two answers from one machine: one address has the MAC."""
        from sqlalchemy import select

        from app.models.device import Device

        created, updated = await upsert_discovered_hosts(
            db_session,
            [
                DiscoveredHost(
                    ip_address="10.0.0.100",
                    mac_address="123A1FAA7FEB",
                    hostname="Immortan",
                ),
                DiscoveredHost(ip_address="10.0.0.102", hostname="Immortan"),
            ],
        )
        assert (created, updated) == (1, 0)

        rows = (await db_session.execute(select(Device))).scalars().all()
        assert [row.ip_address for row in rows] == ["10.0.0.100"]

    async def test_gateway_flag_latches(self, db_session) -> None:
        from sqlalchemy import select

        from app.models.device import Device

        await upsert_discovered_hosts(db_session, [DiscoveredHost(ip_address="10.0.0.1")])
        await upsert_discovered_hosts(
            db_session, [DiscoveredHost(ip_address="10.0.0.1", is_gateway=True)]
        )
        await upsert_discovered_hosts(db_session, [DiscoveredHost(ip_address="10.0.0.1")])

        device = (await db_session.execute(select(Device))).scalars().one()
        assert device.is_gateway is True


class TestUpsertDevicePorts:
    async def test_create_update_and_remove_stale(self, db_session) -> None:
        from sqlalchemy import select

        from app.models.device import Device
        from app.models.device_port import DevicePort

        device = Device(ip_address="10.0.0.7")
        db_session.add(device)
        await db_session.commit()

        created, updated, removed = await upsert_device_ports(
            db_session,
            device.id,
            [
                PortObservation(port=80, protocol="tcp", state="open", service="http"),
                PortObservation(port=22, protocol="tcp", state="open", service="ssh"),
            ],
        )
        assert (created, updated, removed) == (2, 0, 0)

        # Re-scan: 80 stays, 22 is gone, 443 appears.
        created, updated, removed = await upsert_device_ports(
            db_session,
            device.id,
            [
                PortObservation(port=80, protocol="tcp", state="open", service="http", product="nginx"),
                PortObservation(port=443, protocol="tcp", state="open", service="https"),
            ],
        )
        assert (created, updated, removed) == (1, 1, 1)

        rows = (await db_session.execute(select(DevicePort))).scalars().all()
        assert sorted(row.port for row in rows) == [80, 443]
        assert {row.port: row.product for row in rows}[80] == "nginx"

    async def test_empty_observation_clears_the_device(self, db_session) -> None:
        from sqlalchemy import select

        from app.models.device import Device
        from app.models.device_port import DevicePort

        device = Device(ip_address="10.0.0.8")
        db_session.add(device)
        await db_session.commit()

        await upsert_device_ports(
            db_session, device.id, [PortObservation(port=80, protocol="tcp", state="open")]
        )
        created, updated, removed = await upsert_device_ports(db_session, device.id, [])
        assert (created, updated, removed) == (0, 0, 1)
        assert (await db_session.execute(select(DevicePort))).scalars().all() == []


# -------------------------------------------------------------------- API shape


def _load_devices_module():
    """Import app/api/routes/devices.py without executing the package __init__.

    ``app/api/routes/__init__.py`` imports every router, which drags in
    email_validator and the rest of the app graph. test_health.py loads its
    module the same way so the suite stays runnable on a minimal install.
    """
    import importlib.util
    from pathlib import Path

    spec = importlib.util.spec_from_file_location(
        "netpulse_devices_route",
        Path(__file__).parent.parent / "app" / "api" / "routes" / "devices.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestDevicesApiModule:
    """Guard the wiring of the endpoints this feature adds."""

    def test_module_imports_everything_it_references(self) -> None:
        pytest.importorskip("fastapi")
        pytest.importorskip("sqlalchemy")

        import pathlib

        from fastapi.responses import FileResponse

        devices_module = _load_devices_module()

        # These were used without being imported, so the config endpoints raised
        # NameError at request time rather than returning a response.
        assert devices_module.Path is pathlib.Path
        assert devices_module.FileResponse is FileResponse

    def test_expected_routes_are_registered(self) -> None:
        pytest.importorskip("fastapi")
        pytest.importorskip("sqlalchemy")

        devices_module = _load_devices_module()

        registered = {
            (route.path, method)
            for route in devices_module.router.routes
            for method in getattr(route, "methods", set())
        }
        assert ("/discover", "POST") in registered
        assert ("/{device_id}/detail", "GET") in registered
        assert ("/{device_id}/deep-scan", "POST") in registered
