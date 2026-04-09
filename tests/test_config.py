"""
Unit tests for app.core.config.Settings.

Settings is instantiated directly (not via the cached singleton) so
that each test can supply its own environment variables without
cache interference.
"""
from __future__ import annotations

import pytest


class TestDatabaseUrl:
    """Settings.database_url should build a valid asyncpg URL."""

    def test_uses_database_url_env_var(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "postgresql://user:pass@host:5432/mydb")
        # Re-import to pick up the env var (bypass lru_cache).
        from importlib import reload
        import app.core.config as cfg_mod
        reload(cfg_mod)
        s = cfg_mod.Settings()
        url = s.database_url
        assert url.startswith("postgresql+asyncpg://")
        assert "user" in url
        assert "mydb" in url

    def test_strips_sslmode_from_url(self, monkeypatch):
        monkeypatch.setenv(
            "DATABASE_URL",
            "postgresql://user:pass@host:5432/mydb?sslmode=require",
        )
        from importlib import reload
        import app.core.config as cfg_mod
        reload(cfg_mod)
        s = cfg_mod.Settings()
        assert "sslmode" not in s.database_url

    def test_falls_back_to_components(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        from importlib import reload
        import app.core.config as cfg_mod
        reload(cfg_mod)
        s = cfg_mod.Settings(
            postgres_user="testuser",
            postgres_password="testpass",
            postgres_host="testhost",
            postgres_port=5433,
            postgres_db="testdb",
        )
        url = s.database_url
        assert "postgresql+asyncpg://" in url
        assert "testuser" in url
        assert "testhost" in url
        assert "5433" in url
        assert "testdb" in url


class TestPulseTargets:
    """Settings.pulse_targets returns the three monitoring IPs as a list."""

    def test_returns_list_of_three(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        from importlib import reload
        import app.core.config as cfg_mod
        reload(cfg_mod)
        s = cfg_mod.Settings(
            pulse_gateway_ip="10.0.0.1",
            pulse_isp_ip="8.8.8.8",
            pulse_cloudflare_ip="1.1.1.1",
        )
        targets = s.pulse_targets
        assert len(targets) == 3
        assert "10.0.0.1" in targets
        assert "8.8.8.8" in targets
        assert "1.1.1.1" in targets


class TestCeleryUrls:
    """Celery broker and result backend should point to Redis."""

    def test_celery_broker_equals_redis_url(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        from importlib import reload
        import app.core.config as cfg_mod
        reload(cfg_mod)
        s = cfg_mod.Settings(redis_url="redis://myredis:6379/0")
        assert s.celery_broker_url == "redis://myredis:6379/0"

    def test_celery_result_backend_equals_redis_url(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        from importlib import reload
        import app.core.config as cfg_mod
        reload(cfg_mod)
        s = cfg_mod.Settings(redis_url="redis://myredis:6379/0")
        assert s.celery_result_backend == "redis://myredis:6379/0"


class TestPostgresUrlSchemeConversion:
    """Both 'postgres://' and 'postgresql://' schemes must be rewritten."""

    def test_postgres_scheme_converted(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "postgres://u:p@h:5432/db")
        from importlib import reload
        import app.core.config as cfg_mod
        reload(cfg_mod)
        s = cfg_mod.Settings()
        assert s.database_url.startswith("postgresql+asyncpg://")
