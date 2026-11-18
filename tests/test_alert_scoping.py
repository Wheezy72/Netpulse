"""Alerts describe the network this host is on, not every network it has seen.

A trip leaves hundreds of rows on a network the machine has since left. Their
``last_seen`` never refreshes, so with an unscoped query every one of them looks
like a brand-new outage and the operator gets a mail full of strangers — which
is exactly what teaches someone to ignore these alerts.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://netpulse:netpulse@localhost:5432/netpulse")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("ENVIRONMENT", "development")

import pytest  # noqa: E402

from app.services import alerts  # noqa: E402


@pytest.fixture
async def db_session():
    pytest.importorskip("sqlalchemy")
    pytest.importorskip("greenlet", reason="SQLAlchemy's async extension requires greenlet")
    pytest.importorskip("aiosqlite")

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.db.base import Base
    from app.models.device import Device  # noqa: F401 - registers the mapper
    from app.models.network import Network  # noqa: F401 - registers the mapper
    from app.models.vulnerability import Vulnerability  # noqa: F401 - registers the mapper

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as connection:
        await connection.run_sync(Base.metadata.create_all)

    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session

    await engine.dispose()


async def _seed(db_session):
    """One stale host on the network we are on, two on the one we left."""
    from app.models.device import Device
    from app.models.network import Network

    here = Network(key="mac:HERE", name="home", cidr="192.168.1.0/24")
    away = Network(key="mac:AWAY", name="friend's wifi", cidr="192.168.56.0/24")
    db_session.add_all([here, away])
    await db_session.commit()

    stale = datetime.now(timezone.utc) - timedelta(minutes=30)
    db_session.add_all(
        [
            Device(ip_address="192.168.1.20", network_id=here.id, last_seen=stale),
            Device(ip_address="192.168.56.20", network_id=away.id, last_seen=stale),
            Device(ip_address="192.168.56.21", network_id=away.id, last_seen=stale),
        ]
    )
    await db_session.commit()
    return here, away


def _stay_on(monkeypatch, attached: int) -> None:
    async def _scoped(db, *, network_id=None, scope="current"):
        return attached

    monkeypatch.setattr(alerts, "scoped_network_id", _scoped)


@pytest.fixture
def quiet_settings(monkeypatch):
    """The scheduler is what refreshes last_seen; without it alerts stay silent."""
    monkeypatch.setattr(
        alerts,
        "settings",
        SimpleNamespace(enable_scheduled_tasks=True, device_offline_minutes=10),
    )


@pytest.fixture
def recorded(monkeypatch):
    sent: list[tuple[str, str]] = []

    async def _send(subject, body, **kwargs):
        sent.append((subject, body))
        return True

    monkeypatch.setattr(alerts, "send_system_alert", _send)
    return sent


def _policy():
    return SimpleNamespace(enabled=True, notify_device_down=True, recipients=["ops@example.com"])


class TestDeviceDownAlerts:
    async def test_only_the_current_network_is_reported(
        self, db_session, monkeypatch, quiet_settings, recorded
    ):
        here, _away = await _seed(db_session)
        _stay_on(monkeypatch, here.id)
        monkeypatch.setattr(alerts, "_offline_baseline_done", True)

        reported = await alerts.process_device_down_alerts(db_session, policy=_policy())

        assert reported == 1
        subject, body = recorded[0]
        assert "1 host(s) offline" in subject
        assert "192.168.1.20" in body
        assert "192.168.56." not in body

    async def test_a_network_this_host_left_mails_nothing(
        self, db_session, monkeypatch, quiet_settings, recorded
    ):
        _here, away = await _seed(db_session)
        _stay_on(monkeypatch, away.id)
        # Only the stale row on *this* network is reportable, so make the host
        # look freshly seen there and the left-behind rows the only stale ones.
        from app.models.device import Device
        from sqlalchemy import update

        await db_session.execute(
            update(Device)
            .where(Device.ip_address == "192.168.56.20")
            .values(last_seen=datetime.now(timezone.utc))
        )
        await db_session.commit()
        monkeypatch.setattr(alerts, "_offline_baseline_done", True)

        reported = await alerts.process_device_down_alerts(db_session, policy=_policy())

        assert reported == 1
        assert "192.168.56.21" in recorded[0][1]
        assert "192.168.1.20" not in recorded[0][1]


class TestDailyDigest:
    async def test_counts_only_the_current_network(self, db_session, monkeypatch):
        here, _away = await _seed(db_session)
        _stay_on(monkeypatch, here.id)

        subject, body = await alerts._digest_message(db_session)

        assert "digest" in subject.lower()
        assert "Devices: 1 known" in body
        assert "3 known" not in body
