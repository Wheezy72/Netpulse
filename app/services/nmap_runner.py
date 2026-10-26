from __future__ import annotations

import asyncio
import shutil
import time
from datetime import datetime
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.paths import SCANS_DIR as SCANS_DIR_PATH
from app.core.paths import ensure_dir
from app.models.scan_job import ScanJob, ScanJobStatus
from app.services.nmap_capabilities import NMAP_INSTALL_HINT
from app.services.nmap_results import parse_nmap_text
from app.services.proc import EOF, ChildProcess

SCANS_DIR = ensure_dir(SCANS_DIR_PATH)


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

    # nmap is a hard requirement: fail the job with a readable explanation
    # rather than silently substituting a weaker scanner.
    if not shutil.which("nmap"):
        artifact_path.write_text(
            "\n".join(
                [
                    "Scan aborted: nmap is not installed on this host.",
                    f"Target: {job.target}",
                    f"Requested command: {' '.join(safe_args)}",
                    "",
                    NMAP_INSTALL_HINT,
                    "",
                ]
            ),
            encoding="utf-8",
        )
        job.status = ScanJobStatus.FAILED
        job.completed_at = datetime.utcnow()
        job.result_summary = {"error": "nmap_missing"}
        job.artifact_path = str(artifact_path)
        await db.commit()
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

    # ChildProcess rather than asyncio.create_subprocess_exec: under
    # ``uvicorn --reload`` on Windows the loop is a SelectorEventLoop, where
    # asyncio's subprocess API raises a bare NotImplementedError and every scan
    # died before nmap even started. stderr is merged so scan errors land in the
    # artifact next to the progress output.
    child = ChildProcess(safe_args, merge_stderr=True, stream=True)
    scan_started = time.monotonic()
    elapsed: float | None = None

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
                    chunk = await asyncio.wait_for(child.lines.get(), timeout=0.25)
                except TimeoutError:
                    chunk = ""

                if chunk is EOF:
                    break
                pending += chunk

                now = time.monotonic()
                if pending and (len(pending) >= 8192 or now - last_flush >= 0.75):
                    _flush_to_file()

            returncode = await child.wait()
            elapsed = time.monotonic() - scan_started
    except TimeoutError:
        child.terminate()
        try:
            await asyncio.wait_for(child.wait(), timeout=5)
        except TimeoutError:
            child.kill()
            await child.wait()

        _flush_to_file()
        with artifact_path.open("a", encoding="utf-8", errors="replace") as f:
            f.write(f"\n[timeout] Scan timed out after {timeout_seconds} seconds\n")

        job.status = ScanJobStatus.FAILED
        job.completed_at = datetime.utcnow()
        job.result_summary = {"error": "timeout", "timeout_seconds": timeout_seconds}
        await db.commit()
        return
    finally:
        await child.drain()

    _flush_to_file()

    # The findings are parsed here, not in a follow-up task: a scan that has to
    # queue behind other work used to report nothing when the page closed, and
    # the task it deferred to had been deleted long ago. The artifact is already
    # on disk, so parsing costs one file read and makes the result durable.
    findings = parse_nmap_text(artifact_path.read_text(encoding="utf-8", errors="replace"))
    summary: dict[str, object] = {"exit_code": returncode, **findings}
    if elapsed is not None:
        summary["duration_seconds"] = round(elapsed, 2)

    job.completed_at = datetime.utcnow()
    job.result_summary = summary

    if returncode == 0:
        job.status = ScanJobStatus.COMPLETED
    else:
        job.status = ScanJobStatus.FAILED

    await db.commit()

    # For now, we keep the artifact even when save_results is False because it
    # is useful for postmortem/debugging. Future: cleanup job.
    _ = save_results
