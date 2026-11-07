"""The maintenance routes: who may call them, and what they do.

The preview must never write and the prune must delete exactly what the preview
listed, so the session here is a stub that records the statements it is given
instead of reaching Postgres.
"""
from __future__ import annotations

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://netpulse:netpulse@localhost:5432/netpulse")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
import pytest  # noqa: E402

from app.api.deps import db_session, require_admin  # noqa: E402
from app.api.routes import maintenance  # noqa: E402
from app.services.phantom_devices import DEFAULT_LIMIT  # noqa: E402

ROUTER_MAC = "8C:44:BB:07:6C:10"


class _Result:
    def __init__(self, rows=(), rowcount: int = -1):
        self._rows = list(rows)
        self.rowcount = rowcount

    def all(self):
        return self._rows


class _Session:
    """Enough of an AsyncSession to run the service without a database."""

    def __init__(self, rows):
        self.rows = list(rows)
        self.executed: list[object] = []
        self.committed = False

    async def execute(self, statement):
        self.executed.append(statement)
        if getattr(statement, "is_select", False):
            return _Result(self.rows)
        return _Result(rowcount=max(0, len(self.rows) - 1))

    async def commit(self):
        self.committed = True


def _phantom_rows():
    rows = [(1, None, ROUTER_MAC, "192.168.1.1", "router", True)]
    rows += [(i, None, ROUTER_MAC, f"192.168.1.{i}", None, False) for i in range(2, 256)]
    return rows


@pytest.fixture
def app():
    app = FastAPI()
    app.include_router(maintenance.router, prefix="/maintenance")
    return app


@pytest.fixture
def session():
    return _Session(_phantom_rows())


@pytest.fixture
def admin_client(app, session):
    app.dependency_overrides[db_session] = lambda: session
    app.dependency_overrides[require_admin] = lambda: object()
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


class TestAccess:
    def test_anonymous_callers_are_refused(self, app):
        client = TestClient(app)

        assert client.get("/maintenance/phantom-devices").status_code == 401
        assert client.post("/maintenance/phantom-devices/prune").status_code == 401


class TestPreview:
    def test_lists_the_clump(self, admin_client):
        response = admin_client.get("/maintenance/phantom-devices")

        assert response.status_code == 200
        body = response.json()
        assert body["limit"] == DEFAULT_LIMIT
        assert body["inspected"] == 255
        assert body["removable"] == 254
        assert len(body["clumps"]) == 1

        clump = body["clumps"][0]
        assert clump["mac_address"] == ROUTER_MAC
        assert clump["rows"] == 255
        assert clump["removable"] == 254
        assert clump["keep"]["ip_address"] == "192.168.1.1"
        assert clump["keep"]["is_gateway"] is True
        assert clump["first_dropped"] == "192.168.1.2"
        assert clump["last_dropped"] == "192.168.1.255"

    def test_writes_nothing(self, admin_client, session):
        admin_client.get("/maintenance/phantom-devices")

        assert session.committed is False
        assert all(getattr(statement, "is_select", False) for statement in session.executed)

    def test_the_limit_must_be_sensible(self, admin_client):
        assert admin_client.get("/maintenance/phantom-devices?limit=0").status_code == 422
        assert admin_client.get("/maintenance/phantom-devices?limit=8").status_code == 200


class TestPrune:
    def test_deletes_the_rows_it_listed(self, admin_client):
        response = admin_client.post("/maintenance/phantom-devices/prune")

        assert response.status_code == 200
        body = response.json()
        assert body["deleted"] == 254
        assert body["clumps"][0]["keep"]["ip_address"] == "192.168.1.1"

    def test_removes_children_before_the_devices(self, admin_client, session):
        admin_client.post("/maintenance/phantom-devices/prune")

        assert session.committed is True
        # metrics, vulnerabilities, ports, the script-job update, then devices.
        assert len(session.executed) == 6
        assert getattr(session.executed[-1], "is_delete", False) is True
        assert any(getattr(statement, "is_update", False) for statement in session.executed)

    def test_a_clean_inventory_deletes_nothing(self, app, session):
        session.rows = [(1, None, "AA:BB:CC:DD:EE:01", "192.168.1.1", None, True)]
        app.dependency_overrides[db_session] = lambda: session
        app.dependency_overrides[require_admin] = lambda: object()

        response = TestClient(app).post("/maintenance/phantom-devices/prune")

        assert response.status_code == 200
        assert response.json() == {"deleted": 0, "clumps": []}
        assert session.committed is False
