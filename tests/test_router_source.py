"""Unit tests for the router-verified device source.

Everything is offline: the SNMP pull is stubbed, the leases file is a tmp_path
fixture and the inventory is in-memory SQLite, so the assertions are about the
*rules* — what counts as verified, when a device stops being verified, and what
happens when the router cannot be reached.
"""
from __future__ import annotations

import os

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://netpulse:netpulse@localhost:5432/netpulse")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("ENVIRONMENT", "development")

from app.core.config import settings  # noqa: E402
from app.services import router_source  # noqa: E402
from app.services.router_source import RouterEntry, _correlate, _from_dnsmasq, _matches  # noqa: E402


@pytest.fixture
async def db_session():
    """In-memory inventory, same shape the enrichment tests use."""
    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.db.base import Base
    from app.models.device import Device  # noqa: F401 - registers the mapper

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session

    await engine.dispose()


async def _seed(db, ip: str, **kwargs):
    from app.models.device import Device

    device = Device(ip_address=ip, **kwargs)
    db.add(device)
    await db.flush()
    return device


# --------------------------------------------------------------------- matching


class TestMatching:
    def test_matches_by_address(self) -> None:
        class D:
            id = 1
            ip_address = "192.168.1.100"
            mac_address = "123A1FAA7FEB"

        matched, unmatched = _matches([D()], [RouterEntry(ip_address="192.168.1.100")])
        assert matched[1].ip_address == "192.168.1.100"
        assert unmatched == []

    def test_falls_back_to_mac_when_the_address_changed(self) -> None:
        class D:
            id = 7
            ip_address = "192.168.1.50"
            mac_address = "123A1FAA7FEB"

        matched, _ = _matches([D()], [RouterEntry(ip_address="192.168.1.102", mac_address="123A1FAA7FEB")])
        assert matched[7].ip_address == "192.168.1.102"

    def test_unmatched_entries_are_reported_not_invented(self) -> None:
        matched, unmatched = _matches([], [RouterEntry(ip_address="192.168.1.102")])
        assert matched == {}
        assert [entry.ip_address for entry in unmatched] == ["192.168.1.102"]

    def test_one_entry_cannot_verify_two_rows(self) -> None:
        class D:
            def __init__(self, ident: int) -> None:
                self.id = ident
                self.ip_address = "192.168.1.100"
                self.mac_address = None

        matched, _ = _matches([D(1), D(2)], [RouterEntry(ip_address="192.168.1.100")])
        assert len(matched) == 1


# ------------------------------------------------------------------- SNMP column join


class TestCorrelate:
    def test_joins_the_two_walked_columns_on_their_index(self) -> None:
        base = "1.3.6.1.2.1.4.22.1"
        phys = [
            (f"{base}.2.1.192.168.1.1", bytes.fromhex("8C44BB076C10")),
            (f"{base}.2.1.192.168.1.100", bytes.fromhex("123A1FAA7FEB")),
        ]
        net = [
            (f"{base}.3.1.192.168.1.1", "192.168.1.1"),
            (f"{base}.3.1.192.168.1.100", "192.168.1.100"),
        ]
        entries = _correlate(phys, net, f"{base}.2", f"{base}.3")
        assert {(e.ip_address, e.mac_address) for e in entries} == {
            ("192.168.1.1", "8C44BB076C10"),
            ("192.168.1.100", "123A1FAA7FEB"),
        }

    def test_missing_mac_leaves_none_rather_than_a_guess(self) -> None:
        base = "1.3.6.1.2.1.4.22.1"
        entries = _correlate(
            [], [(f"{base}.3.1.10.0.0.5", "10.0.0.5")], f"{base}.2", f"{base}.3"
        )
        assert entries == [RouterEntry(ip_address="10.0.0.5", mac_address=None, kind="arp")]


# ------------------------------------------------------------------ leases file


class TestDnsmasqSource:
    def test_parses_a_lease_file(self, tmp_path) -> None:
        leases = tmp_path / "dnsmasq.leases"
        leases.write_text(
            "1758000000 12:3a:1f:aa:7f:eb 192.168.1.100 Immortan 01:12:3a:1f:aa:7f:eb\n"
            "1758000001 00:11:22:33:44:55 192.168.1.1 * 00:11:22:33:44:55\n"
            "not-a-lease-line\n",
            encoding="utf-8",
        )
        pull = _from_dnsmasq(str(leases))
        assert pull.ok
        assert pull.error is None
        assert len(pull.entries) == 2
        assert pull.entries[0].hostname == "Immortan"
        assert pull.entries[0].mac_address == "123A1FAA7FEB"
        assert pull.entries[1].hostname is None  # "*" is the wildcard name

    def test_unreadable_file_is_an_error_not_a_crash(self) -> None:
        pull = _from_dnsmasq("/definitely/not/here.leases")
        assert not pull.ok
        assert "unreadable" in (pull.error or "")


# -------------------------------------------------------------------- verification


class TestVerifyDevices:
    async def test_marks_listed_devices_and_clears_unlisted_ones(
        self, db_session, monkeypatch
    ) -> None:
        listed = await _seed(db_session, "192.168.1.100", verified=True, verified_source="snmp")
        gone = await _seed(db_session, "192.168.1.101", verified=True, verified_source="snmp")

        async def _pull():
            return router_source.RouterPull(
                source="snmp",
                target="192.168.1.1",
                entries=[RouterEntry(ip_address="192.168.1.100", mac_address="123A1FAA7FEB")],
            )

        monkeypatch.setattr(router_source, "pull_router_entries", _pull)
        outcome = await router_source.verify_devices(db_session)

        assert outcome.verified == 1
        assert outcome.unverified == 1
        assert outcome.entries == 1
        assert outcome.source == "snmp"

        await db_session.refresh(listed)
        await db_session.refresh(gone)
        assert listed.verified is True
        assert listed.verified_source == "snmp"
        assert listed.verified_at is not None
        # The router's own MAC beats whatever the neighbour table carried.
        assert listed.mac_address == "123A1FAA7FEB"
        assert gone.verified is False
        # Kept, so "last confirmed at" stays meaningful.
        assert gone.verified_source == "snmp"

    async def test_fills_hostname_from_a_dhcp_lease(self, db_session, monkeypatch) -> None:
        device = await _seed(db_session, "192.168.1.100")

        async def _pull():
            return router_source.RouterPull(
                source="dnsmasq",
                target="/var/lib/misc/dnsmasq.leases",
                entries=[
                    RouterEntry(ip_address="192.168.1.100", hostname="Immortan", kind="lease")
                ],
            )

        monkeypatch.setattr(router_source, "pull_router_entries", _pull)
        await router_source.verify_devices(db_session)

        await db_session.refresh(device)
        assert device.hostname == "Immortan"
        assert device.verified is True

    async def test_unmatched_router_entries_are_reported(self, db_session, monkeypatch) -> None:
        async def _pull():
            return router_source.RouterPull(
                source="snmp",
                target="192.168.1.1",
                entries=[
                    RouterEntry(ip_address="192.168.1.1"),
                    RouterEntry(ip_address="192.168.1.102"),
                ],
            )

        monkeypatch.setattr(router_source, "pull_router_entries", _pull)
        outcome = await router_source.verify_devices(db_session)

        assert outcome.verified == 0
        assert outcome.unmatched == ["192.168.1.1", "192.168.1.102"]

    async def test_failed_pull_reports_without_touching_rows(self, db_session, monkeypatch) -> None:
        device = await _seed(db_session, "192.168.1.100", verified=True)

        async def _pull():
            return router_source.RouterPull(
                source="snmp",
                target="192.168.1.1",
                error="no reply from 192.168.1.1:161",
            )

        monkeypatch.setattr(router_source, "pull_router_entries", _pull)
        outcome = await router_source.verify_devices(db_session)

        assert not outcome.ok
        assert "no reply" in (outcome.error or "")
        await db_session.refresh(device)
        assert device.verified is True  # an unreachable router is not proof of absence

    async def test_off_switch_skips_the_pull(self, db_session, monkeypatch) -> None:
        async def _pull():  # pragma: no cover - must never run
            raise AssertionError("pull must not run when ROUTER_SOURCE=off")

        monkeypatch.setattr(router_source, "pull_router_entries", _pull)
        monkeypatch.setattr(settings, "router_source", "off")
        assert await router_source.verify_if_configured(db_session) is None


# ------------------------------------------------------------------ configuration


class TestConfiguration:
    def test_auto_is_the_default_and_enabled(self) -> None:
        assert settings.router_source == "auto"
        assert settings.router_source_configured is True

    def test_off_disables_it(self, monkeypatch) -> None:
        monkeypatch.setattr(settings, "router_source", "off")
        assert settings.router_source_configured is False

    @pytest.mark.parametrize("value", ["", "none", "disabled", "OFF"])
    def test_every_off_spelling_disables_it(self, value: str) -> None:
        monkey_value = value
        original = settings.router_source
        try:
            settings.router_source = monkey_value
            assert settings.router_source_configured is False
        finally:
            settings.router_source = original

    def test_describe_reports_the_target(self, monkeypatch) -> None:
        monkeypatch.setattr(settings, "router_source", "auto")
        monkeypatch.setattr(settings, "router_host", "192.168.1.1")
        monkeypatch.setattr(settings, "router_dhcp_leases_file", "")
        monkeypatch.setattr(settings, "routeros_url", "")
        described = router_source.describe_configuration()
        assert described["enabled"] is True
        assert described["source"] == "auto"
        assert described["target"] == "192.168.1.1"
