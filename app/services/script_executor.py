from __future__ import annotations

import asyncio
import importlib.util
import inspect
import textwrap
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.script_job import ScriptJob, ScriptJobStatus


@dataclass
class NetworkTools:
    """Network helper methods exposed to user scripts.

    The initial implementation is deliberately minimal; it can be extended
    with higher-level helpers (SNMP, HTTP, etc.) as needed.
    """

    async def tcp_rst(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        count: int = 3,
    ) -> None:
        """Send TCP RST packets to tear down a connection.

        This is a placeholder implementation. In a production deployment,
        you would implement this using Scapy or raw sockets, and potentially
        enforce strict safety checks.
        """
        # To be implemented with Scapy or raw sockets.
        # For now, this method is a no-op to keep the service safe by default.
        await asyncio.sleep(0)


@dataclass
class ScriptContext:
    db: AsyncSession
    logger: Callable[[str], None]
    network: NetworkTools
    job_id: int
    params: Dict[str, Any]


async def _load_script_callable(script_path: Path) -> Callable[[ScriptContext], Any]:
    """Load the `run` callable from a Python module located at script_path."""
    if not script_path.exists():
        raise FileNotFoundError(f"Script not found at {script_path}")

    module_name = f"netpulse_script_{script_path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, str(script_path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load spec for script {script_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[call-arg]

    if not hasattr(module, "run"):
        raise AttributeError("Script must define a top-level 'run(ctx)' function")

    run_callable = getattr(module, "run")
    if not callable(run_callable):
        raise TypeError("'run' attribute in script is not callable")

    return run_callable


async def execute_script(
    db: AsyncSession,
    job_id: int,
) -> None:
    """Core logic for executing a ScriptJob.

    The lifecycle:

    - Load ScriptJob from DB.
    - Transition to RUNNING.
    - Build ScriptContext.
    - Invoke script's `run(ctx)` (async or sync).
    - Capture result and logs.
    - Update ScriptJob status and timestamps.
    """
    job = await db.get(ScriptJob, job_id)
    if job is None:
        return

    logs: list[str] = []

    def log(message: str) -> None:
        message = textwrap.shorten(message, width=2000, placeholder="...")
        logs.append(message)

    job.status = ScriptJobStatus.RUNNING
    job.started_at = datetime.utcnow()
    await db.commit()
    await db.refresh(job)

    context = ScriptContext(
        db=db,
        logger=log,
        network=NetworkTools(),
        job_id=job.id,
        params=job.params or {},
    )

    try:
        script_path = Path(job.script_path)
        run_callable = await _load_script_callable(script_path)

        if inspect.iscoroutinefunction(run_callable):
            result = await run_callable(context)  # type: ignore[arg-type]
        else:
            # Run sync functions in a thread to avoid blocking the event loop.
            result = await asyncio.to_thread(run_callable, context)  # type: ignore[arg-type]

        job.result = result if isinstance(result, dict) else {"result": str(result)}
        job.status = ScriptJobStatus.SUCCESS
    except Exception as exc:  # noqa: BLE001
        log(f"Script execution failed: {exc!r}")
        job.status = ScriptJobStatus.FAILED
    finally:
        # Persist logs and final status
        existing_logs = (job.logs or "").strip()
        combined = "\n".join(logs)
        job.logs = f"{existing_logs}\n{combined}".strip() if existing_logs else combined
        job.finished_at = datetime.utcnow()

        await db.commit()
        await db.refresh(job)