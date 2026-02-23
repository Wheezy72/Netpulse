from __future__ import annotations

import asyncio
import shutil
import time
from datetime import datetime
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.scan_job import ScanJob, ScanJobStatus

SCANS_DIR = Path("data/scans")
SCANS_DIR.mkdir(parents=True, exist_ok=True)


def _artifact_path_for_scan(scan_id: str) -> Path:
    return SCANS_DIR / f"scan_{scan_id}.txt"


async def run_scan_job(
    db: AsyncSession,
    job: ScanJob,
    safe_args: list[str],
    save_results: bool = True,
    timeout_seconds: int = 300,
) -> None:
    """Execute nmap and stream output to the scan artifact file.

    The artifact file is always created so that the WebSocket tail endpoint can
    stream output live. If `save_results` is False we still write the artifact,
    but callers may choose to delete it later.
    """

    artifact_path = _artifact_path_for_scan(job.id)
    artifact_path.parent.mkdir(parents=True, exist_ok=True)

    if not shutil.which("nmap"):
        job.status = ScanJobStatus.FAILED
        job.completed_at = datetime.utcnow()
        job.result_summary = {
            "error": "nmap is not installed on this system",
        }
        job.artifact_path = str(artifact_path)
        await db.commit()

        artifact_path.write_text("nmap is not installed on this system\n")
        return

    # Ensure the artifact exists early for WS streaming.
    header = "\n".join(
        [
            f"Command: {' '.join(safe_args)}",
            f"Target: {job.target}",
            f"Profile: {job.profile}",
            f"Time: {datetime.utcnow().isoformat()}Z",
            "=" * 60,
            "",
        ]
    )
    artifact_path.write_text(header)

    job.status = ScanJobStatus.RUNNING
    job.started_at = job.started_at or datetime.utcnow()
    job.artifact_path = str(artifact_path)
    job.result_summary = None
    await db.commit()

    proc = await asyncio.create_subprocess_exec(
        *safe_args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    queue: asyncio.Queue[str] = asyncio.Queue()

    async def _read_stream(stream: asyncio.StreamReader | None) -> None:
        if stream is None:
            return
        while True:
            chunk = await stream.readline()
            if not chunk:
                return
            await queue.put(chunk.decode(errors="replace"))

    stdout_task = asyncio.create_task(_read_stream(proc.stdout))
    stderr_task = asyncio.create_task(_read_stream(proc.stderr))

    pending = ""
    last_flush = time.monotonic()

    def _flush_to_file() -> None:
        nonlocal pending, last_flush
        if not pending:
            return
        with artifact_path.open("a", encoding="utf-8", errors="replace") as f:
            f.write(pending)
        pending = ""
        last_flush = time.monotonic()

    try:
        async with asyncio.timeout(timeout_seconds):
            while True:
                try:
                    chunk = await asyncio.wait_for(queue.get(), timeout=0.25)
                    pending += chunk
                except TimeoutError:
                    chunk = ""

                now = time.monotonic()
                if pending and (len(pending) >= 8192 or now - last_flush >= 0.75):
                    _flush_to_file()

                if proc.returncode is not None and queue.empty() and stdout_task.done() and stderr_task.done():
                    break

                if proc.returncode is None and stdout_task.done() and stderr_task.done():
                    await proc.wait()
    except asyncio.TimeoutError:
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except TimeoutError:
            proc.kill()
            await proc.wait()

        _flush_to_file()
        with artifact_path.open("a", encoding="utf-8", errors="replace") as f:
            f.write(f"\n[timeout] Scan timed out after {timeout_seconds} seconds\n")

        job.status = ScanJobStatus.FAILED
        job.completed_at = datetime.utcnow()
        job.result_summary = {"error": "timeout", "timeout_seconds": timeout_seconds}
        await db.commit()
        return
    finally:
        await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)

    _flush_to_file()

    await proc.wait()

    job.completed_at = datetime.utcnow()
    job.result_summary = {"exit_code": proc.returncode}

    if proc.returncode == 0:
        job.status = ScanJobStatus.COMPLETED
    else:
        job.status = ScanJobStatus.FAILED

    await db.commit()

    if proc.returncode == 0:
        try:
            from app.core.celery_app import celery_app

            celery_app.send_task("app.tasks.analyze_scan_results", args=[job.id])
        except Exception:
            # Scan completion should not fail if the broker/worker is unavailable.
            pass

    # For now, we keep the artifact even when save_results is False because it
    # is useful for postmortem/debugging. Future: cleanup job.
    _ = save_results
