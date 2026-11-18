"""Handshake invariants for the WebSocket surface.

Every socket in the app once answered HTTP 500 before reaching its endpoint: a
CSRF dependency that demanded a ``Request`` was called with no argument on
socket scopes. Nothing in the suite noticed, so the whole SSH console and the
live metrics feed were dead while the tests were green.

These are the cheap invariants: no token, no socket; a viewer only gets the
read-only stream.
"""
from __future__ import annotations

import os
from types import SimpleNamespace

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://netpulse:netpulse@localhost:5432/netpulse")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")

from fastapi import FastAPI  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402
from starlette.websockets import WebSocketDisconnect  # noqa: E402
import pytest  # noqa: E402

from app.api.routes import ws  # noqa: E402
from app.models.user import UserRole  # noqa: E402


class _Session:
    """Stands in for the session factory; authentication is patched out."""

    async def __aenter__(self):
        return object()

    async def __aexit__(self, *exc_info):
        return False


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setattr(ws, "async_session_factory", lambda: _Session())
    app = FastAPI()
    app.include_router(ws.router, prefix="/api/ws")
    with TestClient(app) as test_client:
        yield test_client


def _sign_in_as(monkeypatch, role: UserRole) -> None:
    async def _user(token, db):
        return SimpleNamespace(id=1, role=role, is_active=True)

    monkeypatch.setattr(ws, "_get_user_from_token", _user)


def test_metrics_socket_without_a_token_is_refused(client):
    with client.websocket_connect("/api/ws/metrics") as socket:
        assert socket.receive_json()["message"] == "Missing token"
        with pytest.raises(WebSocketDisconnect) as closed:
            socket.receive_text()
    assert closed.value.code == 4401


def test_ssh_socket_without_a_token_is_refused(client):
    with client.websocket_connect("/api/ws/ssh?ip=127.0.0.1") as socket:
        socket.send_json({"type": "auth", "username": "admin", "password": "x"})
        assert "Missing token" in socket.receive_text()
        with pytest.raises(WebSocketDisconnect) as closed:
            socket.receive_text()
    assert closed.value.code == 4400


def test_ssh_console_is_closed_to_a_viewer(client, monkeypatch):
    _sign_in_as(monkeypatch, UserRole.VIEWER)
    with client.websocket_connect("/api/ws/ssh?ip=127.0.0.1") as socket:
        socket.send_json(
            {"type": "auth", "token": "t", "username": "admin", "password": "x"}
        )
        assert "cannot open console sessions" in socket.receive_text()
        with pytest.raises(WebSocketDisconnect) as closed:
            socket.receive_text()
    assert closed.value.code == 4403


def test_script_logs_are_closed_to_a_viewer(client, monkeypatch):
    _sign_in_as(monkeypatch, UserRole.VIEWER)
    with client.websocket_connect("/api/ws/scripts/1?token=t") as socket:
        assert socket.receive_json()["message"] == "Forbidden"
        with pytest.raises(WebSocketDisconnect) as closed:
            socket.receive_text()
    assert closed.value.code == 4403
