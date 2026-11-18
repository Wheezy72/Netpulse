"""Deleting device rows without leaving orphans behind.

Metrics and vulnerabilities point at a device with no ``ON DELETE`` action, so
the database refuses the parent delete until they are gone; ports cascade but
are removed explicitly for the same reason. Script jobs survive while losing
their device link: a run that happened is history, and an address that no longer
exists is not worth keeping a pointer to.

Both the proxy-ARP repair and the per-network purge go through here, so the
order of those statements is written once.
"""
from __future__ import annotations

from typing import Sequence

from sqlalchemy import delete, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.device import Device
from app.models.device_port import DevicePort
from app.models.metric import Metric
from app.models.script_job import ScriptJob
from app.models.vulnerability import Vulnerability


async def delete_devices(session: AsyncSession, device_ids: Sequence[int]) -> int:
    """Delete these rows and their children, then commit. Returns rows deleted."""
    doomed = list(dict.fromkeys(device_ids))
    if not doomed:
        return 0

    await session.execute(delete(Metric).where(Metric.device_id.in_(doomed)))
    await session.execute(delete(Vulnerability).where(Vulnerability.device_id.in_(doomed)))
    await session.execute(delete(DevicePort).where(DevicePort.device_id.in_(doomed)))
    await session.execute(
        update(ScriptJob).where(ScriptJob.device_id.in_(doomed)).values(device_id=None)
    )
    result = await session.execute(delete(Device).where(Device.id.in_(doomed)))
    await session.commit()

    if result.rowcount is not None and result.rowcount >= 0:
        return int(result.rowcount)
    return len(doomed)
