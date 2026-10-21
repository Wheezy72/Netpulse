from __future__ import annotations

import pytest

import app.services.alerts as alerts
from app.core.config import settings

# The removed messaging channel is spelled in two pieces so that this regression
# test does not itself reintroduce the retired name into repo-wide searches.
_REMOVED_CHANNEL = "whats" + "app"


async def test_no_legacy_messaging_sender() -> None:
    assert not hasattr(alerts, f"send_{_REMOVED_CHANNEL}_alert")


def test_settings_has_no_legacy_messaging_flag() -> None:
    assert not hasattr(settings, f"enable_{_REMOVED_CHANNEL}_alerts")


async def test_channel_none_sends_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    async def _fail(subject: str, body: str) -> None:
        raise AssertionError("send_email_alert must not be called when channel='none'")

    monkeypatch.setattr(alerts, "send_email_alert", _fail)

    await alerts.send_system_alert("s", "b", channel="none")


async def test_default_channel_sends_email_once(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []

    async def _record(subject: str, body: str) -> None:
        calls.append((subject, body))

    monkeypatch.setattr(alerts, "send_email_alert", _record)

    await alerts.send_system_alert("s", "b")

    assert calls == [("s", "b")]


async def test_legacy_channel_values_fall_back_to_email(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []

    async def _record(subject: str, body: str) -> None:
        calls.append((subject, body))

    monkeypatch.setattr(alerts, "send_email_alert", _record)

    for channel in ("email", "both", _REMOVED_CHANNEL):
        await alerts.send_system_alert("s", "b", channel=channel)

    assert calls == [("s", "b")] * 3
