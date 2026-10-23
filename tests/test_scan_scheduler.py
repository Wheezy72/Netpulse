"""Rules for the in-process scan scheduler.

The Scheduler tab saved settings that nothing read. These tests pin the part
that decides whether a saved schedule is due, plus the scan-type mapping, so
the tab cannot quietly become a dead control again.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from app.services.nmap_capabilities import available_profiles
from app.services.scan_scheduler import (
    PROFILE_FOR_SCAN_TYPE,
    _parse_time,
    is_due,
)


def test_parse_time_falls_back_to_two_am() -> None:
    assert _parse_time(None) == (2, 0)
    assert _parse_time("") == (2, 0)
    assert _parse_time("nonsense") == (2, 0)
    assert _parse_time("06:30") == (6, 30)


def test_daily_fires_after_its_slot_only_once() -> None:
    at = datetime(2026, 10, 23, 12, 0)
    schedule = {"frequency": "daily", "time": "02:00", "last_run": None}

    assert is_due(schedule, at) is True

    schedule["last_run"] = datetime(2026, 10, 23, 2, 0, 5).isoformat()
    assert is_due(schedule, at) is False


def test_daily_waits_for_today_slot() -> None:
    early = datetime(2026, 10, 23, 1, 0)
    schedule = {"frequency": "daily", "time": "02:00", "last_run": None}
    assert is_due(schedule, early) is False


def test_disabled_schedule_is_not_read_here() -> None:
    """`enabled` is checked by the caller, not by the due-time rule."""
    at = datetime(2026, 10, 23, 12, 0)
    schedule = {"enabled": False, "frequency": "daily", "time": "02:00"}
    assert is_due(schedule, at) is True


def test_hourly_waits_for_the_configured_minute() -> None:
    schedule = {"frequency": "hourly", "time": "00:45", "last_run": None}
    assert is_due(schedule, datetime(2026, 10, 23, 12, 30)) is False
    assert is_due(schedule, datetime(2026, 10, 23, 12, 45)) is True


def test_hourly_respects_one_hour_spacing() -> None:
    # Both checks happen after the :45 minute gate, so this isolates spacing.
    last = datetime(2026, 10, 23, 15, 10)
    schedule = {"frequency": "hourly", "time": "00:45", "last_run": last.isoformat()}
    assert is_due(schedule, datetime(2026, 10, 23, 15, 50)) is False
    assert is_due(schedule, datetime(2026, 10, 23, 16, 50)) is True


def test_weekly_needs_six_days_between_runs() -> None:
    last = datetime(2026, 10, 20, 2, 0)
    schedule = {"frequency": "weekly", "time": "02:00", "last_run": last.isoformat()}
    assert is_due(schedule, last + timedelta(days=2)) is False
    assert is_due(schedule, last + timedelta(days=7)) is True


def test_monthly_needs_most_of_a_month() -> None:
    last = datetime(2026, 10, 1, 2, 0)
    schedule = {"frequency": "monthly", "time": "02:00", "last_run": last.isoformat()}
    assert is_due(schedule, datetime(2026, 10, 20, 12, 0)) is False
    assert is_due(schedule, datetime(2026, 11, 1, 12, 0)) is True


def test_scan_type_mapping_matches_real_nmap_profiles() -> None:
    known = {profile["id"] for profile in available_profiles()}
    assert set(PROFILE_FOR_SCAN_TYPE.values()) <= known
