from __future__ import annotations

"""
Celery task definitions.

These tasks wrap the core service functions used for:
- Latency monitoring (Pulse).
- Script execution (Brain).
- Passive ARP discovery and packet capture (Eye/Vault).
- Vulnerability alerting (notifications).
- Scheduled reminders (e.g. scan reminders).
"""

import asyncio

from celery.utils.log import get_task_logger
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.celery_app import celery_app
from app.core.config import settings
from app.services.alerts import process_vulnerability_alerts, send_system_alert
from app.services.latency_monitor import monitor_latency
from app.services.packet_capture import capture_to_pcap
from app.services.recon import passive_arp_discovery
from app.services.script_executor import execute_script

logger = get_task_logger(__name__)


def _create_session_factory():
    """Create a fresh async engine and session factory for a Celery task.

    This avoids reusing an async engine across multiple event loops, which can
    cause 'Future attached to a different loop' errors when tasks are invoked
    repeatedly via asyncio.run().
    """
    engine = create_async_engine(settings.database_url, echo=False, future=True)
    factory = sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)
    return engine, factory


@celery_app.task(name="app.tasks.monitor_latency_task")
def monitor_latency_task() -> None:
    """Celery task wrapper for the Pulse module's latency monitoring."""
    async def _run() -> None:
        engine, factory = _create_session_factory()
        try:
            async with factory() as session:
                await monitor_latency(session)
        finally:
            await engine.dispose()

    asyncio.run(_run())


@celery_app.task(name="app.tasks.execute_script_job_task")
def execute_script_job_task(job_id: int) -> None:
    """Celery task that executes a ScriptJob by ID."""
    async def _run() -> None:
        engine, factory = _create_session_factory()
        try:
            async with factory() as session:
                await execute_script(session, job_id)
        finally:
            await engine.dispose()

    asyncio.run(_run())


@celery_app.task(name="app.tasks.passive_arp_discovery_task")
def passive_arp_discovery_task() -> None:
    """Celery task that performs short passive ARP discovery.

    Uses the OS default interface instead of hard-coding 'eth0' to avoid
    failures on systems where that interface name does not exist.
    """
    async def _run() -> None:
        engine, factory = _create_session_factory()
        try:
            async with factory() as session:
                try:
                    await passive_arp_discovery(session, iface=None, duration=10)
                except ValueError as exc:
                    # Interface not found or not usable; log and skip rather than crashing.
                    logger.warning("Passive ARP discovery skipped: %s", exc)
        finally:
            await engine.dispose()

    asyncio.run(_run())


@celery_app.task(name="app.tasks.packet_capture_recent_task")
def packet_capture_recent_task(
    duration_seconds: int = 300,
    bpf_filter: str | None = None,
) -> int:
    """Celery task that performs a time-bounded packet capture and returns a capture ID."""
    async def _run() -> int:
        engine, factory = _create_session_factory()
        try:
            async with factory() as session:
                capture_id = await capture_to_pcap(
                    session,
                    duration_seconds=duration_seconds,
                    iface=None,
                    bpf_filter=bpf_filter,
                )
                return capture_id
        finally:
            await engine.dispose()

    return asyncio.run(_run())


@celery_app.task(name="app.tasks.vulnerability_alert_task")
def vulnerability_alert_task() -> None:
    """Celery task that scans for new high/critical vulnerabilities and sends alerts."""
    async def _run() -> None:
        engine, factory = _create_session_factory()
        try:
            async with factory() as session:
                await process_vulnerability_alerts(session)
        finally:
            await engine.dispose()

    asyncio.run(_run())


@celery_app.task(name="app.tasks.scheduled_scan_reminder_task")
def scheduled_scan_reminder_task() -> None:
    """
    Celery task that sends a reminder about scheduled scans.

    This does not perform a scan itself; it simply nudges operators that
    it's time to run (or verify) their scheduled scan playbooks.
    """
    async def _run() -> None:
        subject = "[NetPulse] Scheduled scan reminder"
        body = (
            "This is your scheduled reminder to review and run your scan playbooks.\n"
            "Typical actions:\n"
            "  - Verify recon targets are up to date.\n"
            "  - Run Nmap profiles against critical segments.\n"
            "  - Review the dashboard for new vulnerabilities or anomalies."
        )
        await send_system_alert(subject, body, event_type="scan")

    asyncio.run(_run())