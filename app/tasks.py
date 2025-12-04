from __future__ import annotations

"""
Celery task definitions.

These tasks wrap the core service functions used for:
- Latency monitoring (Pulse).
- Script execution (Brain).
- Passive ARP discovery and packet capture (Eye/Vault).
"""

import asyncio

from celery.utils.log import get_task_logger
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.celery_app import celery_app
from app.db.session import async_session_factory
from app.services.latency_monitor import monitor_latency
from app.services.packet_capture import capture_to_pcap
from app.services.recon import passive_arp_discovery
from app.services.script_executor import execute_script

logger = get_task_logger(__name__)


async def _get_session() -> AsyncSession:
    async with async_session_factory() as session:
        yield session


@celery_app.task(name="app.tasks.monitor_latency_task")
def monitor_latency_task() -> None:
    """Celery task wrapper for the Pulse module's latency monitoring."""
    async def _run() -> None:
        async with async_session_factory() as session:
            await monitor_latency(session)

    asyncio.run(_run())


@celery_app.task(name="app.tasks.execute_script_job_task")
def execute_script_job_task(job_id: int) -> None:
    """Celery task that executes a ScriptJob by ID."""
    async def _run() -> None:
        async with async_session_factory() as session:
            await execute_script(session, job_id)

    asyncio.run(_run())


@celery_app.task(name="app.tasks.passive_arp_discovery_task")
def passive_arp_discovery_task() -> None:
    """Celery task that performs short passive ARP discovery on eth0."""
    async def _run() -> None:
        async with async_session_factory() as session:
            await passive_arp_discovery(session, iface="eth0", duration=10)

    asyncio.run(_run())


@celery_app.task(name="app.tasks.packet_capture_recent_task")
def packet_capture_recent_task(
    duration_seconds: int = 300,
    bpf_filter: str | None = None,
) -> int:
    """Celery task that performs a time-bounded packet capture and returns a capture ID."""
    async def _run() -> int:
        async with async_session_factory() as session:
            capture_id = await capture_to_pcap(
                session,
                duration_seconds=duration_seconds,
                iface="eth0",
                bpf_filter=bpf_filter,
            )
            return capture_id

    return asyncio.run(_run())