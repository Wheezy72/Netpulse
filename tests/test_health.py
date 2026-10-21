"""
Unit tests for the health-check endpoints.

These tests create a minimal FastAPI app that only mounts the health
router, so no database, Redis, or other external services are required.

The health module is loaded directly via importlib to avoid triggering
app/api/routes/__init__.py, which imports every route module (and their
heavy transitive dependencies such as SQLAlchemy, asyncpg, etc.).
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


def _load_health_module():
    """Import app/api/routes/health.py without executing the package __init__."""
    spec = importlib.util.spec_from_file_location(
        "health",
        Path(__file__).parent.parent / "app" / "api" / "routes" / "health.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


health = _load_health_module()

# Minimal test app — only the health router is mounted.
_app = FastAPI()
_app.include_router(health.router, prefix="/health")

client = TestClient(_app)


class _StubCapabilities:
    """The two fields the readiness probe actually reads."""

    def __init__(self, available: bool, version: str | None = None) -> None:
        self.available = available
        self.version = version


@pytest.fixture
def nmap_available(monkeypatch):
    """Pretend nmap is installed so readiness does not depend on the host."""
    monkeypatch.setattr(
        health,
        "detect_capabilities",
        lambda *args, **kwargs: _StubCapabilities(available=True, version="7.95"),
    )


class TestLiveness:
    def test_returns_200(self):
        response = client.get("/health/live")
        assert response.status_code == 200

    def test_body_contains_status_ok(self):
        response = client.get("/health/live")
        assert response.json() == {"status": "ok"}

    def test_content_type_is_json(self):
        response = client.get("/health/live")
        assert "application/json" in response.headers["content-type"]


class TestReadiness:
    def test_returns_200(self, nmap_available):
        response = client.get("/health/ready")
        assert response.status_code == 200

    def test_body_contains_status_ok_and_nmap(self, nmap_available):
        response = client.get("/health/ready")
        body = response.json()
        assert body["status"] == "ok"
        assert body["nmap"]["available"] is True
        assert body["nmap"]["version"] == "7.95"

    def test_content_type_is_json(self, nmap_available):
        response = client.get("/health/ready")
        assert "application/json" in response.headers["content-type"]

    def test_returns_503_when_nmap_missing(self, monkeypatch):
        monkeypatch.setattr(
            health,
            "detect_capabilities",
            lambda *args, **kwargs: _StubCapabilities(available=False),
        )

        response = client.get("/health/ready")
        assert response.status_code == 503
        assert response.json() == {
            "status": "degraded",
            "nmap": {"available": False, "version": None},
        }
