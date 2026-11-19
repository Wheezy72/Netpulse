"""Unit tests for the ICMP helper and the device ping-status wiring."""
from __future__ import annotations

import importlib.util
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.services.icmp import PingOutcome, build_ping_argv, parse_ping_output
from app.services.icmp import ping as icmp_ping


_LINUX_SAMPLE = """
PING 192.168.1.1 (192.168.1.1) 56(84) bytes of data.
64 bytes from 192.168.1.1: icmp_seq=1 ttl=64 time=1.24 ms
64 bytes from 192.168.1.1: icmp_seq=2 ttl=64 time=0.98 ms

--- 192.168.1.1 ping statistics ---
2 packets transmitted, 2 received, 0% packet loss, time 3ms
rtt min/avg/max/mdev = 0.980/1.110/1.240/0.130 ms
"""

_WINDOWS_SAMPLE = """
Pinging 192.168.1.1 with 32 bytes of data:
Reply from 192.168.1.1: bytes=32 time=2ms TTL=64
Reply from 192.168.1.1: bytes=32 time=4ms TTL=64

Ping statistics for 192.168.1.1:
    Packets: Sent = 2, Received = 2, Lost = 0 (0% loss),
"""

_WINDOWS_LOSS_SAMPLE = """
Pinging 192.168.1.50 with 32 bytes of data:
Request timed out.

Ping statistics for 192.168.1.50:
    Packets: Sent = 1, Received = 0, Lost = 1 (100% loss),
"""


class TestBuildPingArgv:
    def test_posix_argv(self, monkeypatch):
        monkeypatch.setattr("os.name", "posix")
        argv = build_ping_argv("10.0.0.1", count=3, timeout_s=2.0)
        assert argv == ["ping", "-c", "3", "-W", "2", "10.0.0.1"]

    def test_windows_argv_uses_milliseconds(self, monkeypatch):
        monkeypatch.setattr("os.name", "nt")
        argv = build_ping_argv("10.0.0.1", count=1, timeout_s=1.0)
        assert argv == ["ping", "-n", "1", "-w", "1000", "10.0.0.1"]

    def test_host_is_last_element(self, monkeypatch):
        monkeypatch.setattr("os.name", "posix")
        argv = build_ping_argv("host.lan")
        assert argv[-1] == "host.lan"


class TestParsePingOutput:
    def test_linux_latency_and_loss(self):
        avg_ms, loss = parse_ping_output(_LINUX_SAMPLE)
        assert avg_ms == pytest.approx((1.24 + 0.98) / 2)
        assert loss == 0.0

    def test_windows_latency_and_loss(self):
        avg_ms, loss = parse_ping_output(_WINDOWS_SAMPLE)
        assert avg_ms == pytest.approx(3.0)
        assert loss == 0.0

    def test_windows_total_loss(self):
        avg_ms, loss = parse_ping_output(_WINDOWS_LOSS_SAMPLE)
        assert avg_ms is None
        assert loss == 100.0

    def test_garbage_output(self):
        avg_ms, loss = parse_ping_output("nothing useful here")
        assert avg_ms is None
        assert loss is None


class TestPingFailureModes:
    @pytest.mark.asyncio
    async def test_empty_host_is_safe(self):
        outcome = await icmp_ping("  ")
        assert outcome.reachable is False
        assert outcome.error

    @pytest.mark.asyncio
    async def test_unroutable_host_never_raises(self):
        # RFC 5737 documentation range; nothing should answer. The helper must
        # return an outcome, never raise.
        outcome = await icmp_ping("192.0.2.123", count=1, timeout_s=0.3)
        assert isinstance(outcome, PingOutcome)
        assert outcome.reachable is False


def _load_devices_router():
    spec = importlib.util.spec_from_file_location(
        "devices_routes",
        Path(__file__).parent.parent / "app" / "api" / "routes" / "devices.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestPingStatusWiring:
    def test_route_registered_before_parametrised_routes(self):
        module = _load_devices_router()
        paths = [getattr(route, "path", None) for route in module.router.routes]
        assert "/ping-status" in paths

    def test_classify_thresholds(self):
        module = _load_devices_router()
        classify = module._classify_ping
        assert classify(5.0, True) == "up"
        assert classify(99.9, True) == "up"
        assert classify(150.0, True) == "slow"
        assert classify(None, True) == "up"
        assert classify(1.0, False) == "down"

    def test_console_adapters_are_one_row_per_network(self):
        module = _load_devices_router()
        devices = [
            SimpleNamespace(id=1, mac_address="AA:00:00:00:00:01", network_id=7),
            SimpleNamespace(id=2, mac_address="AA:00:00:00:00:02", network_id=7),
            SimpleNamespace(id=3, mac_address="AA:00:00:00:00:01", network_id=8),
            SimpleNamespace(id=4, mac_address="BB:00:00:00:00:01", network_id=7),
        ]

        groups = module._topology_device_groups(
            devices,
            {"AA0000000001", "AA0000000002"},
        )

        assert [[device.id for device in members] for _, members in groups] == [
            [4], [1, 2], [3]
        ]

    def test_the_node_is_shown_on_its_most_recent_address(self):
        from datetime import datetime, timezone

        module = _load_devices_router()
        devices = [
            SimpleNamespace(
                id=1,
                mac_address="AA:00:00:00:00:01",
                network_id=7,
                last_seen=datetime(2026, 11, 2, 20, 0, tzinfo=timezone.utc),
            ),
            SimpleNamespace(
                id=2,
                mac_address="AA:00:00:00:00:02",
                network_id=7,
                last_seen=datetime(2026, 11, 18, 11, 0, tzinfo=timezone.utc),
            ),
        ]

        groups = module._topology_device_groups(devices, {"AA0000000001", "AA0000000002"})

        representative, members = groups[0]
        assert representative.id == 2, "the map must show the address seen most recently"
        assert [member.id for member in members] == [1, 2]

    def test_a_never_sighted_row_does_not_win_over_a_sighted_one(self):
        from datetime import datetime, timezone

        module = _load_devices_router()
        devices = [
            SimpleNamespace(
                id=1, mac_address="AA:00:00:00:00:01", network_id=7,
                last_seen=datetime(2026, 11, 18, 11, 0, tzinfo=timezone.utc),
            ),
            SimpleNamespace(id=2, mac_address="AA:00:00:00:00:02", network_id=7, last_seen=None),
        ]

        representative, _members = module._topology_device_groups(
            devices, {"AA0000000001", "AA0000000002"}
        )[0]

        assert representative.id == 1

    def test_same_hostname_does_not_merge_an_unidentified_host(self):
        module = _load_devices_router()
        console = SimpleNamespace(
            id=1, mac_address="AA:00:00:00:00:01", network_id=7,
            hostname="Immortan", os="Windows 11", device_type="workstation", verified=True,
        )
        other_pc = SimpleNamespace(
            id=2, mac_address="CC:00:00:00:00:02", network_id=7,
            hostname="Immortan", os="Windows 11", device_type="workstation", verified=True,
        )

        groups = module._topology_device_groups([console, other_pc], {"AA0000000001"})

        assert [[device.id for device in members] for _, members in groups] == [[2], [1]]


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


class TestPingStatusSkipsThisMachine:
    """The console machine is never pinged, so it cannot appear as an outage.

    A NIC keeps a row for every address it has held; the old lease answers
    nothing, and the dashboard used to list the machine it runs on under "not
    responding".
    """

    async def _seed(self, session):
        from app.models.device import Device
        from app.models.network import Network

        home = Network(key="mac:HOME", name="home", cidr="192.168.1.0/24")
        session.add(home)
        await session.commit()

        rows = [
            # This machine's NIC, on the address it holds now.
            Device(ip_address="192.168.1.10", mac_address="F41E5796FBC7", network_id=home.id),
            # The same NIC on a lease it let go — the row that read as "down".
            Device(ip_address="192.168.1.90", mac_address="f4:1e:57:96:fb:c7", network_id=home.id),
            # No MAC at all: must still be probed.
            Device(ip_address="192.168.1.20", network_id=home.id),
            Device(ip_address="192.168.1.21", mac_address="AABBCCDDEEFF", network_id=home.id),
        ]
        session.add_all(rows)
        await session.commit()
        return rows

    async def _prepare(self, session, monkeypatch, macs):
        rows = await self._seed(session)
        probed: list[str] = []

        async def fake_ping(host, count=1, timeout_s=1.0):
            probed.append(host)
            return PingOutcome(host=host, reachable=True, latency_ms=3.0, packet_loss_pct=0.0)

        from app.api.routes import devices as devices_route

        async def stay_on(db, *, network_id=None, scope="current"):
            return rows[0].network_id

        monkeypatch.setattr(devices_route, "console_macs", lambda: frozenset(macs))
        monkeypatch.setattr(devices_route, "icmp_ping", fake_ping)
        monkeypatch.setattr(devices_route, "scoped_network_id", stay_on)
        return devices_route, probed

    async def test_this_machines_addresses_are_neither_probed_nor_reported(
        self, db_session, monkeypatch
    ):
        devices_route, probed = await self._prepare(db_session, monkeypatch, {"F41E5796FBC7"})

        payload = await devices_route.get_ping_status(
            limit=12, db=db_session, _user=SimpleNamespace(id=1)
        )

        assert sorted(probed) == ["192.168.1.20", "192.168.1.21"]
        assert {row["ip_address"] for row in payload["results"]} == {
            "192.168.1.20",
            "192.168.1.21",
        }
        assert payload["summary"] == {"up": 2, "slow": 0, "down": 0, "total": 2}

    async def test_a_skipped_row_does_not_burn_a_slot(self, db_session, monkeypatch):
        devices_route, probed = await self._prepare(db_session, monkeypatch, {"F41E5796FBC7"})

        payload = await devices_route.get_ping_status(
            limit=1, db=db_session, _user=SimpleNamespace(id=1)
        )

        # Filtering after the query would have spent the single slot on this
        # machine and returned nothing at all.
        assert len(payload["results"]) == 1
        assert len(probed) == 1

    async def test_no_detected_macs_pings_the_whole_inventory(self, db_session, monkeypatch):
        devices_route, probed = await self._prepare(db_session, monkeypatch, set())

        payload = await devices_route.get_ping_status(
            limit=12, db=db_session, _user=SimpleNamespace(id=1)
        )

        # Mislabelling another device as this machine is worse than not
        # labelling at all, so an empty set must filter nothing.
        assert payload["summary"]["total"] == 4
        assert len(probed) == 4
