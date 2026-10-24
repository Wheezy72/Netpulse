"""Unit tests for alert email delivery.

These pin the behaviour that made email alerting unreliable: STARTTLS was
mandatory (port 465 and plain local relays never worked), and a failed send
raised into whatever was running, so the vulnerability stayed unmarked and the
same mail was retried on every tick.
"""
from __future__ import annotations

import os
import smtplib

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://netpulse:netpulse@localhost:5432/netpulse")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("ENVIRONMENT", "development")

from app.services import alerts  # noqa: E402


class FakeSMTP:
    """Records what the code would have put on the wire."""

    instances: list["FakeSMTP"] = []
    supports_starttls = True
    fail_connect = False
    fail_send = False

    def __init__(self, host: str, port: int, timeout: float = 10):
        if FakeSMTP.fail_connect:
            raise ConnectionRefusedError("connection refused")
        self.host = host
        self.port = port
        self.started_tls = False
        self.logged_in = None
        self.sent: list[object] = []
        self.esmtp_features = {"starttls": ""} if FakeSMTP.supports_starttls else {}
        FakeSMTP.instances.append(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return False

    def ehlo(self):
        return (250, b"ok")

    def starttls(self, context=None):
        if not FakeSMTP.supports_starttls:
            raise smtplib.SMTPNotSupportedError("STARTTLS not supported")
        self.started_tls = True

    def login(self, username, password):
        self.logged_in = (username, password)

    def send_message(self, message):
        if FakeSMTP.fail_send:
            raise smtplib.SMTPServerDisconnected("server went away")
        self.sent.append(message)


@pytest.fixture(autouse=True)
def smtp_settings(monkeypatch):
    """Configure a plausible mailbox and a clean fake transport per test."""
    FakeSMTP.instances = []
    FakeSMTP.supports_starttls = True
    FakeSMTP.fail_connect = False
    FakeSMTP.fail_send = False

    monkeypatch.setattr(smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP_SSL", FakeSMTP)
    monkeypatch.setattr(alerts.settings, "enable_email_alerts", True)
    monkeypatch.setattr(alerts.settings, "smtp_host", "mail.example.test")
    monkeypatch.setattr(alerts.settings, "smtp_port", 587)
    monkeypatch.setattr(alerts.settings, "smtp_security", "auto")
    monkeypatch.setattr(alerts.settings, "smtp_username", "netpulse")
    monkeypatch.setattr(alerts.settings, "smtp_pass", "secret")
    monkeypatch.setattr(alerts.settings, "alert_email_from", "netpulse@example.test")
    monkeypatch.setattr(alerts.settings, "alert_email_to", "admin@example.test")


class TestSecurityMode:
    def test_port_465_uses_implicit_tls(self) -> None:
        assert alerts.smtp_security_mode(465) == "ssl"

    def test_other_ports_start_with_starttls(self) -> None:
        assert alerts.smtp_security_mode(587) == "starttls"
        assert alerts.smtp_security_mode(25) == "starttls"

    def test_explicit_setting_wins(self) -> None:
        assert alerts.smtp_security_mode(587, "none") == "none"
        assert alerts.smtp_security_mode(465, "starttls") == "starttls"


class TestSending:
    def test_sends_with_starttls_and_credentials(self) -> None:
        assert alerts._send_email_sync("subject", "body") is True

        sent = FakeSMTP.instances[-1]
        assert sent.started_tls is True
        assert sent.logged_in == ("netpulse", "secret")
        assert len(sent.sent) == 1

    def test_plain_relay_without_starttls_still_delivers(self) -> None:
        # A local relay on port 25 does not offer STARTTLS; refusing to send
        # there was the old behaviour.
        FakeSMTP.supports_starttls = False
        assert alerts._send_email_sync("subject", "body") is True
        assert len(FakeSMTP.instances[-1].sent) == 1

    def test_explicit_starttls_still_refuses_a_plain_server(self, monkeypatch) -> None:
        monkeypatch.setattr(alerts.settings, "smtp_security", "starttls")
        FakeSMTP.supports_starttls = False
        assert alerts._send_email_sync("subject", "body") is False
        assert FakeSMTP.instances[-1].sent == []

    def test_unreachable_server_is_reported_not_raised(self) -> None:
        FakeSMTP.fail_connect = True
        assert alerts._send_email_sync("subject", "body") is False

    def test_send_failure_is_reported_not_raised(self) -> None:
        FakeSMTP.fail_send = True
        assert alerts._send_email_sync("subject", "body") is False


class TestConfigurationGaps:
    def test_disabled_alerts_send_nothing(self, monkeypatch) -> None:
        monkeypatch.setattr(alerts.settings, "enable_email_alerts", False)
        assert alerts._send_email_sync("subject", "body") is False
        assert FakeSMTP.instances == []

    @pytest.mark.parametrize(
        "field",
        ["smtp_host", "alert_email_from", "alert_email_to"],
    )
    def test_missing_setting_sends_nothing(self, monkeypatch, field) -> None:
        monkeypatch.setattr(alerts.settings, field, None)
        assert alerts._send_email_sync("subject", "body") is False
        assert FakeSMTP.instances == []


class TestAsyncWrapper:
    async def test_returns_delivery_result(self) -> None:
        assert await alerts.send_email_alert("subject", "body") is True

    async def test_never_raises_on_unexpected_error(self, monkeypatch) -> None:
        def explode(*args, **kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(alerts, "_send_email_sync", explode)
        assert await alerts.send_email_alert("subject", "body") is False
