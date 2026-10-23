from __future__ import annotations

"""Execute the scan schedules saved from Settings → Scheduler.

The settings tab used to persist a `scan_schedule` JSON blob that nothing in
the codebase ever read, so the controls looked wired up and never fired. This
module is the missing reader. It runs from the in-process scheduler loop (the
same place that handles alerts), so it works without a Celery worker.

A schedule counts as due based on the frequency, the configured local time and
the `last_run` stamp stored beside the schedule itself. The stamp lives in the
JSON blob rather than a new column so an existing database needs no migration.
"""

import asyncio
import logging
from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.session import async_session_factory
from app.models.network_segment import NetworkSegment
from app.models.scan_job import ScanJob, ScanJobStatus
from app.models.user import User, UserRole
from app.models.user_settings import UserSettings
from app.services.nmap_capabilities import detect_capabilities, plan_command
from app.services.nmap_runner import run_scan_job
from app.services.scan_policy import is_restricted_target, validate_target

logger = logging.getLogger("netpulse.scan_scheduler")

# The Scheduler tab offers these labels; nmap has its own profile ids.
PROFILE_FOR_SCAN_TYPE = {
    "quick": "quick",
    "full": "full",
    "vuln": "vuln",
    "service": "services",
}

# Keep a reference so a queued run is not garbage-collected mid-flight.
_running: set[asyncio.Task] = set()


def _parse_time(value: str | None) -> tuple[int, int]:
    try:
        hour, minute = (value or "02:00").split(":", 1)
        return min(max(int(hour), 0), 23), min(max(int(minute), 0), 59)
    except (TypeError, ValueError):
        return 2, 0


def _as_datetime(value: object) -> datetime | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value)
    except ValueError:
        return None


def is_due(schedule: dict, now: datetime | None = None) -> bool:
    """Whether a saved schedule should fire at *now*.

    Kept pure so the rules are testable without a database.
    """
    now = now or datetime.now()
    last_run = _as_datetime(schedule.get("last_run"))

    frequency = str(schedule.get("frequency") or "daily").lower()
    hour, minute = _parse_time(schedule.get("time"))

    if frequency == "hourly":
        # Hourly means every hour, on the configured minute.
        if now.minute < minute:
            return False
        return last_run is None or now - last_run >= timedelta(hours=1)

    slot = now.replace(hour=hour, minute=minute, second=0, microsecond=0)

    if frequency == "weekly":
        # A slot in the future has not happened yet today.
        if now < slot:
            return False
        return last_run is None or now - last_run >= timedelta(days=6, hours=12)

    if frequency == "monthly":
        if now < slot:
            return False
        return last_run is None or now - last_run >= timedelta(days=27)

    # daily
    if now < slot:
        return False
    return last_run is None or last_run < slot


async def _targets_for(session: AsyncSession, schedule: dict) -> list[str]:
    """Resolve the configured segment ids to CIDRs.

    An empty selection means "everything that is configured and active" — the
    alternative, silently scanning nothing, is what made the tab dead in the
    first place.
    """
    segment_ids = [
        int(value)
        for value in (schedule.get("segments") or [])
        if isinstance(value, (int, str)) and str(value).isdigit()
    ]

    stmt = select(NetworkSegment)
    if segment_ids:
        stmt = stmt.where(NetworkSegment.id.in_(segment_ids))
    else:
        stmt = stmt.where(NetworkSegment.is_active.is_(True))

    rows = list((await session.execute(stmt)).scalars().all())

    if rows:
        candidates = [(row.cidr or "").strip() for row in rows]
    else:
        # No segments configured at all: use the same attached subnets a manual
        # discovery sweep uses, so an out-of-the-box schedule still does work.
        from app.services.device_discovery import local_subnets

        candidates, _iface = local_subnets()

    targets: list[str] = []
    for cidr in candidates:
        if not cidr or cidr in targets:
            continue
        if not validate_target(cidr):
            logger.warning("Scheduled scan skipped %r: invalid target.", cidr)
            continue
        if is_restricted_target(cidr):
            logger.info("Scheduled scan skipped %r: restricted segment.", cidr)
            continue
        targets.append(cidr)
    return targets


def _remember(schedule: dict, **updates: str) -> dict:
    """Return a new dict: SQLAlchemy only notices a JSON column when the
    attribute is reassigned, not when the existing dict is mutated in place."""
    return {**schedule, **updates}


async def run_due_scheduled_scans(session: AsyncSession) -> int:
    """Queue every schedule that is due, returning how many scans started."""
    caps = detect_capabilities()
    if not caps.available:
        logger.warning("Scheduled scans waiting: nmap is not installed.")
        return 0

    result = await session.execute(
        select(UserSettings)
        .join(User, User.id == UserSettings.user_id)
        .where(User.role == UserRole.ADMIN)
    )
    rows = list(result.scalars().all())

    started = 0
    for settings_row in rows:
        schedule = settings_row.scan_schedule
        if not isinstance(schedule, dict) or not schedule.get("enabled"):
            continue
        if not is_due(schedule):
            continue

        profile = PROFILE_FOR_SCAN_TYPE.get(str(schedule.get("scan_type") or "quick"), "quick")
        targets = await _targets_for(session, schedule)
        if not targets:
            settings_row.scan_schedule = _remember(
                schedule,
                last_run=datetime.now().isoformat(),
                last_result="Nothing to scan: no valid network segments are configured.",
            )
            await session.commit()
            continue

        queued_ids: list[str] = []
        for target in targets:
            try:
                plan = plan_command(profile, target, caps)
            except Exception as exc:  # unknown profile / unavailable nmap
                logger.warning("Scheduled scan plan failed for %s: %s", target, exc)
                continue

            job = ScanJob(
                target=target,
                profile=profile,
                arguments={
                    "profile": plan.profile,
                    "safe_args": plan.argv,
                    "rendered_command": plan.display,
                    "scheduled": True,
                },
                status=ScanJobStatus.PENDING,
                requested_by_user_id=settings_row.user_id,
            )
            session.add(job)
            await session.commit()
            await session.refresh(job)
            queued_ids.append(job.id)

            async def _run(scan_id: str = job.id, argv: list[str] = list(plan.argv)) -> None:
                async with async_session_factory() as run_session:  # type: ignore[union-attr]
                    scan_job = await run_session.get(ScanJob, scan_id)
                    if scan_job is None:
                        return
                    await run_scan_job(run_session, scan_job, safe_args=argv)

            task = asyncio.create_task(_run())
            _running.add(task)
            task.add_done_callback(_running.discard)

        settings_row.scan_schedule = _remember(
            schedule,
            last_run=datetime.now().isoformat(),
            last_result=(
                f"Queued {len(queued_ids)} scan(s) across {', '.join(targets)}."
                if queued_ids
                else "Due, but no scan could be planned."
            ),
        )
        await session.commit()

        if queued_ids:
            started += len(queued_ids)
            logger.info(
                "Scheduled scan queued %s job(s) for user %s across %s.",
                len(queued_ids),
                settings_row.user_id,
                ", ".join(targets),
            )

    return started
