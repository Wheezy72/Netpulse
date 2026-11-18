"""Purging a network's devices must never touch a network this host could be on.

The guard cannot rely on live detection alone: when detection fails there is no
"current" answer, and an endpoint that then treats every network as purgeable
empties the inventory of the network the machine is actually attached to.
"""
from __future__ import annotations

import os
from types import SimpleNamespace

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://netpulse:netpulse@localhost:5432/netpulse")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
import pytest  # noqa: E402

from app.api.deps import db_session, require_admin  # noqa: E402
from app.api.routes import networks  # noqa: E402


class _Result:
    def __init__(self, rows, rowcount: int = -1):
        self._rows = list(rows)
        self.rowcount = rowcount

    def scalar_one_or_none(self):
        return self._rows[0] if self._rows else None

    def scalars(self):
        return self

    def all(self):
        return self._rows


class _Session:
    """Records statements; answers the selects the route makes."""

    def __init__(self, device_ids=(1, 2, 3), latest_id: int = 5):
        self.device_ids = list(device_ids)
        self.latest_id = latest_id
        self.executed = []
        self.committed = False

    async def execute(self, statement):
        self.executed.append(statement)
        sql = str(statement)
        if "networks.name" in sql:
            return _Result(
                [SimpleNamespace(id=7, name="friend's wifi", cidr="192.168.56.0/24")]
            )
        if "networks.id" in sql:
            return _Result([self.latest_id])
        if "FROM devices" in sql:
            return _Result(self.device_ids, rowcount=len(self.device_ids))
        return _Result([], rowcount=len(self.device_ids))

    async def commit(self):
        self.committed = True


@pytest.fixture
def app():
    test_app = FastAPI()
    test_app.include_router(networks.router, prefix="/networks")
    test_app.dependency_overrides[require_admin] = lambda: object()
    return test_app


@pytest.fixture
def session():
    return _Session()


def _client(app, session):
    app.dependency_overrides[db_session] = lambda: session
    return TestClient(app)


def _scoped_to(monkeypatch, attached: int) -> None:
    async def _scoped(db, *, network_id=None, scope="current"):
        return attached

    monkeypatch.setattr(networks, "scoped_network_id", _scoped)


def _written_statements(session):
    return [
        statement
        for statement in session.executed
        if getattr(statement, "is_delete", False) or getattr(statement, "is_update", False)
    ]


def test_purge_refuses_the_network_this_host_is_on(app, session, monkeypatch):
    _scoped_to(monkeypatch, 7)

    response = _client(app, session).delete("/networks/7/devices")

    assert response.status_code == 409
    assert _written_statements(session) == []
    assert session.committed is False


def test_purge_refuses_the_most_recently_used_network(app, monkeypatch):
    # Detection named a different row, but this one was seen most recently, so
    # it is still the network the host was on last.
    session = _Session(latest_id=7)
    _scoped_to(monkeypatch, 6)

    response = _client(app, session).delete("/networks/7/devices")

    assert response.status_code == 409
    assert session.committed is False


def test_purge_deletes_a_network_this_host_left(app, session, monkeypatch):
    _scoped_to(monkeypatch, 5)

    response = _client(app, session).delete("/networks/7/devices")

    assert response.status_code == 200
    body = response.json()
    assert body["deleted_devices"] == 3
    assert body["network_name"] == "friend's wifi"


def test_purge_refuses_when_the_reviewed_count_is_stale(app, session, monkeypatch):
    _scoped_to(monkeypatch, 5)

    response = _client(app, session).delete("/networks/7/devices?expected_devices=99")

    assert response.status_code == 409
    assert "Review the list again" in response.json()["detail"]
    assert _written_statements(session) == []
