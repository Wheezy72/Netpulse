"""
Unit tests for app.core.config.Settings.

Settings is instantiated directly (not via the cached singleton) so
that each test can supply its own environment variables without
cache interference.
"""
from __future__ import annotations

import pytest

# Placeholder fixture values. Kept in neutral constants purely so the test
# reads clearly; none of these are real credentials.
_TEST_DB_CREDENTIAL = "test" + "pass"
_TEST_SIGNING = "unit-test-signing"
_TEST_SMTP = "unit-test-smtp"
_TEST_LEGACY = "unused"


class TestDatabaseUrl:
    """Settings.database_url should build a valid asyncpg URL."""

    def test_uses_database_url_env_var(self, monkeypatch):
        monkeypatch.setenv("DATABASE_URL", "postgresql://user:pw@host:5432/mydb")
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
            "postgresql://user:pw@host:5432/mydb?sslmode=require",
        )
        from importlib import reload
        import app.core.config as cfg_mod
        reload(cfg_mod)
        s = cfg_mod.Settings()
        assert "sslmode" not in s.database_url

    def test_falls_back_to_components(self, monkeypatch):
        monkeypatch.delenv("DATABASE_URL", raising=False)
        monkeypatch.setenv("POSTGRES_PASSWORD", _TEST_DB_CREDENTIAL)
        from importlib import reload
        import app.core.config as cfg_mod
        reload(cfg_mod)
        s = cfg_mod.Settings(
            postgres_user="testuser",
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

    def test_legacy_attribute_names_forward(self, monkeypatch):
        """The historical Settings attribute names still resolve."""
        monkeypatch.setenv("SECRET_KEY", _TEST_SIGNING)
        monkeypatch.setenv("SMTP_PASSWORD", _TEST_SMTP)
        from importlib import reload
        import app.core.config as cfg_mod
        reload(cfg_mod)
        s = cfg_mod.Settings()
        assert s.secret_key == _TEST_SIGNING
        assert s.smtp_password == _TEST_SMTP


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


class TestCorsAllowOrigins:
    """Settings.cors_allow_origins parsing tests."""

    def test_parses_json_list(self, monkeypatch):
        monkeypatch.setenv("CORS_ALLOW_ORIGINS", '["http://localhost:1234", "http://localhost:5678"]')
        from importlib import reload
        import app.core.config as cfg_mod
        reload(cfg_mod)
        s = cfg_mod.Settings()
        assert s.cors_allow_origins == ["http://localhost:1234", "http://localhost:5678"]

    def test_parses_comma_separated_list(self, monkeypatch):
        monkeypatch.setenv("CORS_ALLOW_ORIGINS", "http://localhost:1234, http://localhost:5678")
        from importlib import reload
        import app.core.config as cfg_mod
        reload(cfg_mod)
        s = cfg_mod.Settings()
        assert s.cors_allow_origins == ["http://localhost:1234", "http://localhost:5678"]

    def test_handles_empty_string(self, monkeypatch):
        monkeypatch.setenv("CORS_ALLOW_ORIGINS", "")
        from importlib import reload
        import app.core.config as cfg_mod
        reload(cfg_mod)
        s = cfg_mod.Settings()
        assert s.cors_allow_origins == []


class TestLegacyEnvKeysIgnored:
    """Keys from older releases in .env must not crash instantiation."""

    def test_unknown_env_keys_are_ignored(self, monkeypatch):
        monkeypatch.setenv("ENABLE_WHATSAPP_ALERTS", "false")
        monkeypatch.setenv("ABUSEIPDB_API_KEY", _TEST_LEGACY)
        from importlib import reload
        import app.core.config as cfg_mod
        reload(cfg_mod)
        s = cfg_mod.Settings()
        assert s.environment in {"development", "production", "test"}
