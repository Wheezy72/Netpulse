"""
Pytest configuration and shared fixtures for the NetPulse test suite.

Tests are designed to run without any external services (no database,
no Redis, no RabbitMQ). Each test file imports only the modules it
needs — avoiding the full app.main initialisation chain — so that
the suite can run in CI with a minimal set of pip packages.
"""
from __future__ import annotations

import os

import pytest


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    """
    Provide safe defaults for every environment variable that
    pydantic-settings reads at import time.  The values are chosen so
    that no real connection is attempted during unit tests.
    """
    defaults = {
        "SECRET_KEY": "test-secret-key-for-ci",
        "DATABASE_URL": "postgresql+asyncpg://netpulse:netpulse@localhost:5432/netpulse",
        "REDIS_URL": "redis://localhost:6379/0",
        "RABBITMQ_URL": "amqp://netpulse:netpulse@localhost:5672/netpulse",
        "INFLUXDB_URL": "http://localhost:8086",
        "INFLUXDB_TOKEN": "test-token",
        "ENVIRONMENT": "development",
    }
    for key, value in defaults.items():
        monkeypatch.setenv(key, value)
