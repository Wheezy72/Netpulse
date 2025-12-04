from __future__ import annotations

import asyncio

from celery.utils.log import get_task_logger
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.celery_app import celery_app
from app.db.session import async_session_factory
from app.services.latency_monitor import monitor_latency
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