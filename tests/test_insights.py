"""Unit tests for the insight endpoints (reachability probe + health summary).

The scoring rules are pure and tested directly. The probe is exercised against a
real local socket, so it needs no network access beyond loopback.
"""
from __future__ import annotations

import asyncio
import os
import socket

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://netpulse:netpulse@localhost:5432/netpulse")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("ENVIRONMENT", "development")

from app.api.routes.insights import (  # noqa: E402
    _probe_tcp,
    bucket_for_severity,
    compute_health_score,
    health_status_for,
    network_health,
    recommendation_for,
)
from app.models.vulnerability import VulnerabilitySeverity  # noqa: E402


def _free_port() -> int:
    """A port that was just bound and released, so nothing is listening on it."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class TestHealthScore:
    def test_clean_fleet_scores_full_marks(self) -> None:
        assert compute_health_score(critical_issues=0, warning_issues=0, offline_ratio=0.0) == 100

    def test_critical_issues_dominate(self) -> None:
        assert compute_health_score(critical_issues=3, warning_issues=0, offline_ratio=0.0) == 76

    def test_deductions_are_capped(self) -> None:
        # 100 criticals must not be able to push the score below the cap floor.
        score = compute_health_score(critical_issues=100, warning_issues=0, offline_ratio=0.0)
        assert score == 40

    def test_offline_ratio_deduction(self) -> None:
        assert compute_health_score(critical_issues=0, warning_issues=0, offline_ratio=0.5) == 90

    def test_score_stays_in_range(self) -> None:
        worst = compute_health_score(critical_issues=50, warning_issues=50, offline_ratio=1.0)
        assert 0 <= worst <= 100
        assert worst == 0

    def test_negative_ratio_is_clamped(self) -> None:
        assert compute_health_score(critical_issues=0, warning_issues=0, offline_ratio=-5.0) == 100


class TestHealthStatus:
    @pytest.mark.parametrize(
        ("score", "expected"),
        [(100, "healthy"), (85, "healthy"), (84, "degraded"), (60, "degraded"), (59, "critical"), (0, "critical")],
    )
    def test_boundaries(self, score: int, expected: str) -> None:
        assert health_status_for(score) == expected


class TestSeverityBuckets:
    def test_critical_bucket(self) -> None:
        assert bucket_for_severity(VulnerabilitySeverity.CRITICAL) == "critical"
        assert bucket_for_severity(VulnerabilitySeverity.HIGH) == "critical"

    def test_warning_bucket(self) -> None:
        assert bucket_for_severity(VulnerabilitySeverity.MEDIUM) == "warning"

    def test_informational_findings_do_not_count(self) -> None:
        assert bucket_for_severity(VulnerabilitySeverity.LOW) is None
        assert bucket_for_severity(VulnerabilitySeverity.INFO) is None

    def test_every_severity_gets_a_recommendation(self) -> None:
        for severity in VulnerabilitySeverity:
            assert recommendation_for(severity)


class TestTcpProbe:
    async def test_measures_a_live_listener(self) -> None:
        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            writer.close()

        server = await asyncio.start_server(handle, "127.0.0.1", 0)
        port = int(server.sockets[0].getsockname()[1])

        try:
            latency_ms, error, verdict, reachable = await _probe_tcp("127.0.0.1", port, 2.0)
        finally:
            server.close()
            await server.wait_closed()

        assert error is None
        assert latency_ms is not None
        assert latency_ms >= 0
        assert verdict == "open"
        assert reachable is True

    async def test_reports_refused_connection_as_closed(self) -> None:
        # A refused connection is a healthy answer: the machine is up. Windows
        # retries the SYN before reporting the refusal (~2s), so the timeout has
        # to be comfortably above that or the verdict flips to "filtered".
        latency_ms, error, verdict, reachable = await _probe_tcp("127.0.0.1", _free_port(), 6.0)
        assert latency_ms is None
        assert error
        assert verdict == "closed"
        assert reachable is True

    async def test_reports_unresolvable_host(self) -> None:
        latency_ms, error, _verdict, _reachable = await _probe_tcp("host.invalid.", 80, 2.0)
        assert latency_ms is None
        assert error

    async def test_timeout_says_whether_the_host_answered_at_all(self, monkeypatch) -> None:
        """A dropped SYN and a powered-off machine must not read the same.

        A listening socket still completes the handshake at the OS level, so a
        filtered port is simulated at the point the connection stalls.
        """
        import app.api.routes.insights as insights

        async def _stall(*_args, **_kwargs):
            raise asyncio.TimeoutError

        monkeypatch.setattr(insights.asyncio, "open_connection", _stall)

        async def _answers(_host: str) -> bool:
            return True

        monkeypatch.setattr(insights, "_host_answers", _answers)
        latency, error, verdict, reachable = await _probe_tcp("10.0.0.5", 8080, 0.4)
        assert latency is None
        assert error and "No answer" in error
        assert verdict == "filtered"
        assert reachable is True

        async def _silent_host(_host: str) -> bool:
            return False

        monkeypatch.setattr(insights, "_host_answers", _silent_host)
        latency, error, verdict, reachable = await _probe_tcp("10.0.0.5", 8080, 0.4)
        assert latency is None
        assert error and "ping" in error
        assert verdict == "unreachable"
        assert reachable is False


class TestInsightsApiModule:
    """Guard the wiring of the endpoints the Diagnostics and Toolbox views call."""

    def _load(self):
        import importlib.util
        from pathlib import Path

        spec = importlib.util.spec_from_file_location(
            "netpulse_insights_route",
            Path(__file__).parent.parent / "app" / "api" / "routes" / "insights.py",
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_expected_routes_are_registered(self) -> None:
        pytest.importorskip("fastapi")
        pytest.importorskip("sqlalchemy")

        module = self._load()
        registered = {
            (route.path, method)
            for route in module.router.routes
            for method in getattr(route, "methods", set())
        }
        assert ("/tcp-probe", "POST") in registered
        assert ("/health", "GET") in registered

    async def test_rejects_a_malformed_host(self) -> None:
        pytest.importorskip("fastapi")
        pytest.importorskip("sqlalchemy")
        from fastapi import HTTPException

        module = self._load()
        with pytest.raises(HTTPException):
            await module.tcp_probe(module.TcpProbeRequest(host="10.0.0.1; rm -rf /", port=80))

    async def test_rejects_a_cidr_target(self) -> None:
        pytest.importorskip("fastapi")
        pytest.importorskip("sqlalchemy")
        from fastapi import HTTPException

        module = self._load()
        with pytest.raises(HTTPException):
            await module.tcp_probe(module.TcpProbeRequest(host="10.0.0.0/24", port=80))


@pytest.fixture
async def db_session():
    """In-memory SQLite session, or skip when the async stack is unavailable."""
    pytest.importorskip("sqlalchemy")
    pytest.importorskip("greenlet", reason="SQLAlchemy's async extension requires greenlet")
    pytest.importorskip("aiosqlite")

    from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine

    from app.db.base import Base
    from app.models.device import Device  # noqa: F401 - registers the mapper
    from app.models.vulnerability import Vulnerability  # noqa: F401 - registers the mapper

    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    maker = async_sessionmaker(engine, expire_on_commit=False)
    async with maker() as session:
        yield session

    await engine.dispose()


class TestNetworkHealth:
    """Aggregation over a real (SQLite) session, so the SQL itself is exercised."""

    async def test_empty_inventory_is_healthy(self, db_session) -> None:
        pytest.importorskip("fastapi")

        health = await network_health(db_session)

        assert health.total_devices == 0
        assert health.online_devices == 0
        assert health.offline_devices == 0
        assert health.critical_issues == 0
        assert health.warning_issues == 0
        assert health.bottlenecks == []
        assert health.health_score == 100
        assert health.status == "healthy"
        assert health.online_window_minutes > 0

    async def test_counts_findings_and_flags_the_worst_host(self, db_session) -> None:
        pytest.importorskip("fastapi")
        from datetime import datetime, timedelta, timezone

        from app.models.device import Device
        from app.models.vulnerability import Vulnerability, VulnerabilitySeverity

        now = datetime.now(timezone.utc)
        fresh = Device(ip_address="10.0.0.5", hostname="nas", device_type="NAS", last_seen=now)
        stale = Device(ip_address="10.0.0.6", hostname="printer", last_seen=now - timedelta(hours=3))
        db_session.add_all([fresh, stale])
        await db_session.commit()

        db_session.add_all(
            [
                Vulnerability(
                    device_id=fresh.id,
                    source="nmap",
                    title="Exposed SMB",
                    severity=VulnerabilitySeverity.CRITICAL,
                    description="test fixture",
                ),
                Vulnerability(
                    device_id=fresh.id,
                    source="nmap",
                    title="Weak TLS",
                    severity=VulnerabilitySeverity.MEDIUM,
                    description="test fixture",
                ),
                # Low severity must not be counted as an issue.
                Vulnerability(
                    device_id=fresh.id,
                    source="nmap",
                    title="Verbose banner",
                    severity=VulnerabilitySeverity.LOW,
                    description="test fixture",
                ),
            ]
        )
        await db_session.commit()

        health = await network_health(db_session)

        assert health.total_devices == 2
        assert health.online_devices + health.offline_devices == 2
        assert health.critical_issues == 1
        assert health.warning_issues == 1
        assert len(health.bottlenecks) == 1

        flagged = health.bottlenecks[0]
        assert flagged.ip_address == "10.0.0.5"
        assert flagged.severity == "critical"
        assert "Exposed SMB" in flagged.issues
        assert flagged.recommendation

    async def test_resolved_findings_are_ignored(self, db_session) -> None:
        pytest.importorskip("fastapi")
        from app.models.device import Device
        from app.models.vulnerability import Vulnerability, VulnerabilitySeverity

        device = Device(ip_address="10.0.0.9")
        db_session.add(device)
        await db_session.commit()

        db_session.add(
            Vulnerability(
                device_id=device.id,
                source="nmap",
                title="Fixed already",
                severity=VulnerabilitySeverity.CRITICAL,
                description="test fixture",
                is_resolved=True,
            )
        )
        await db_session.commit()

        health = await network_health(db_session)

        assert health.critical_issues == 0
        assert health.bottlenecks == []
