from __future__ import annotations

import re
import shlex
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, get_current_user, require_admin
from app.db.session import async_session_factory
from app.models.scan_job import ScanJob, ScanJobStatus
from app.models.user import User
from app.services.nmap_runner import run_scan_job

router = APIRouter()

SCANS_DIR = Path("data/scans")
SCANS_DIR.mkdir(parents=True, exist_ok=True)

# A conservative allowlist for user-provided nmap flags.
ALLOWED_NMAP_FLAGS: set[str] = {
    "-sS",
    "-sT",
    "-sU",
    "-sV",
    "-sC",
    "-sn",
    "-O",
    "-A",
    "-F",
    "-p-",
    "-Pn",
    "-n",
    "-R",
    "-v",
    "-vv",
    "--open",
    "--reason",
    "--osscan-guess",
    "--osscan-limit",
}
ALLOWED_TIMING: set[str] = {f"-T{i}" for i in range(0, 6)}
ALLOWED_NMAP_FLAGS |= ALLOWED_TIMING

ALLOWED_VALUE_FLAGS: set[str] = {
    "-p",
    "--min-rate",
    "--max-rate",
    "--host-timeout",
    "--script-timeout",
    "--script-args",
    "--max-retries",
    "--version-intensity",
    "--top-ports",
    "--script",
}

# Allow any built-in NSE script name (admins only) but block obvious injection / path traversal.
SCRIPT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*\*?$")


class NmapCommandRequest(BaseModel):
    command: str
    target: str
    save_results: bool = True


class ScanResult(BaseModel):
    id: str
    command: str
    target: str
    scan_type: str
    started_at: str
    completed_at: Optional[str] = None
    status: str
    output: Optional[str] = None
    file_path: Optional[str] = None
    result_summary: Optional[Dict[str, Any]] = None
    ai_briefing: Optional[str] = None


def _read_artifact_tail(path: str | None, max_bytes: int = 64_000) -> str | None:
    if not path:
        return None
    try:
        p = Path(path)
        if not p.exists() or not p.is_file():
            return None
        size = p.stat().st_size
        with p.open("rb") as f:
            if size > max_bytes:
                f.seek(size - max_bytes)
            data = f.read()
        return data.decode(errors="replace")
    except Exception:
        return None


def _job_to_scan_result(job: ScanJob, include_output: bool = True) -> ScanResult:
    output = _read_artifact_tail(job.artifact_path) if include_output else None

    command = (job.arguments or {}).get("command") or ""
    summary: Dict[str, Any] | None = job.result_summary if isinstance(job.result_summary, dict) else None
    ai_briefing: str | None = None
    if summary:
        ai_briefing = summary.get("ai_briefing")

    return ScanResult(
        id=job.id,
        command=command,
        target=job.target,
        scan_type=job.profile,
        started_at=(job.started_at or job.created_at).isoformat(),
        completed_at=job.completed_at.isoformat() if job.completed_at else None,
        status=job.status.value,
        output=output,
        file_path=job.artifact_path,
        result_summary=summary,
        ai_briefing=ai_briefing,
    )


def _validate_target(target: str) -> bool:
    # Basic safety check; allows IP/hostname/CIDR-ish patterns.
    target = target.strip()
    if not target or len(target) > 255:
        return False
    if any(ch.isspace() for ch in target):
        return False
    if target.startswith("-"):
        return False
    # Avoid command injection primitives; nmap gets target as its own arg anyway.
    for bad in [";", "|", "&", "`", "$", "\n", "\r"]:
        if bad in target:
            return False
    return True


def _validate_script_list(value: str) -> None:
    scripts = [s.strip() for s in value.split(",") if s.strip()]
    if not scripts:
        raise HTTPException(status_code=400, detail="--script value is empty")

    for script in scripts:
        # Disallow paths / traversal regardless of pattern.
        if "/" in script or "\\" in script or ".." in script:
            raise HTTPException(status_code=400, detail=f"Invalid NSE script: {script}")
        if not SCRIPT_NAME_PATTERN.match(script):
            raise HTTPException(status_code=400, detail=f"Invalid NSE script: {script}")


def _parse_safe_nmap_args(command: str, target: str) -> list[str]:
    tokens = shlex.split(command)
    if not tokens:
        raise HTTPException(status_code=400, detail="Command is required")

    # Allow users to omit the leading 'nmap'.
    if tokens[0] == "nmap":
        tokens = tokens[1:]

    safe: list[str] = ["nmap"]

    i = 0
    while i < len(tokens):
        tok = tokens[i]

        # Never accept an additional target from the command string.
        if not tok.startswith("-"):
            i += 1
            continue

        # Flag with inline value: --flag=value
        if tok.startswith("--") and "=" in tok:
            flag, value = tok.split("=", 1)
            if flag not in ALLOWED_VALUE_FLAGS:
                raise HTTPException(status_code=400, detail=f"Disallowed flag: {flag}")
            if flag == "--script":
                _validate_script_list(value)
            safe.append(f"{flag}={value}")
            i += 1
            continue

        # Flag with separate value.
        if tok in ALLOWED_VALUE_FLAGS:
            if i + 1 >= len(tokens):
                raise HTTPException(status_code=400, detail=f"Missing value for flag: {tok}")
            value = tokens[i + 1]
            if tok == "--script":
                _validate_script_list(value)
            safe.extend([tok, value])
            i += 2
            continue

        # Simple flags.
        if tok in ALLOWED_NMAP_FLAGS:
            safe.append(tok)
            i += 1
            continue

        raise HTTPException(status_code=400, detail=f"Disallowed flag: {tok}")

    safe.append(target)
    return safe


def get_scan_type_from_command(command: str) -> str:
    if "--script" in command or "-sC" in command:
        return "Script Scan"
    if "-sV" in command:
        return "Version Detection"
    if "-sn" in command:
        return "Ping Sweep"
    if "-p-" in command:
        return "Full Port Scan"
    if "-A" in command:
        return "Aggressive Scan"
    return "Custom Scan"


@router.post("/execute", response_model=ScanResult)
async def execute_nmap(
    request: NmapCommandRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(require_admin),
) -> ScanResult:
    if not shutil.which("nmap"):
        raise HTTPException(status_code=503, detail="nmap is not installed on this system")

    if not _validate_target(request.target):
        raise HTTPException(status_code=400, detail="Invalid target format")

    safe_args = _parse_safe_nmap_args(request.command, request.target)
    command_str = " ".join(safe_args)

    job = ScanJob(
        target=request.target,
        profile=get_scan_type_from_command(command_str),
        arguments={
            "command": request.command,
            "safe_args": safe_args,
            "rendered_command": command_str,
        },
        status=ScanJobStatus.PENDING,
        requested_by_user_id=current_user.id,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    scan_id = job.id

    async def _run() -> None:
        async with async_session_factory() as session:
            scan_job = await session.get(ScanJob, scan_id)
            if scan_job is None:
                return
            await run_scan_job(
                session,
                scan_job,
                safe_args=safe_args,
                save_results=request.save_results,
            )

    background_tasks.add_task(_run)

    return _job_to_scan_result(job, include_output=False)


@router.get("/result/{scan_id}", response_model=ScanResult)
async def get_scan_result(
    scan_id: str,
    include_output: bool = True,
    db: AsyncSession = Depends(db_session),
    _user: User = Depends(get_current_user),
) -> ScanResult:
    job = await db.get(ScanJob, scan_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    return _job_to_scan_result(job, include_output=include_output)


@router.get("/history", response_model=List[ScanResult])
async def get_scan_history(
    db: AsyncSession = Depends(db_session),
    _user: User = Depends(get_current_user),
) -> List[ScanResult]:
    result = await db.execute(select(ScanJob).order_by(ScanJob.created_at.desc()).limit(50))
    jobs = list(result.scalars().all())
    return [_job_to_scan_result(job, include_output=False) for job in jobs]


@router.delete("/history")
async def clear_scan_history(
    db: AsyncSession = Depends(db_session),
    _user: User = Depends(require_admin),
) -> Dict[str, str]:
    await db.execute(delete(ScanJob))
    await db.commit()
    return {"message": "Scan history cleared"}


@router.get("/files")
async def list_scan_files(
    _user: User = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    candidates = list(SCANS_DIR.glob("scan_*.txt"))
    files: list[dict[str, Any]] = []
    for file in sorted(candidates, key=lambda f: f.stat().st_mtime, reverse=True):
        scan_id = ""
        if file.name.startswith("scan_"):
            stem = file.stem
            scan_id = stem.split("_", 1)[1] if "_" in stem else ""
        files.append(
            {
                "filename": file.name,
                "scan_id": scan_id,
                "size": file.stat().st_size,
                "modified": file.stat().st_mtime,
            }
        )
    return files[:100]


@router.get("/files/{filename}")
async def download_scan_file(
    filename: str,
    _user: User = Depends(get_current_user),
) -> FileResponse:
    if not (filename.startswith("scan_") and filename.endswith(".txt")):
        raise HTTPException(status_code=400, detail="Invalid filename")
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")

    file_path = SCANS_DIR / filename
    if not file_path.exists() or not file_path.is_file():
        raise HTTPException(status_code=404, detail="File not found")

    return FileResponse(path=str(file_path), filename=filename, media_type="text/plain")


@router.get("/presets")
async def get_nmap_presets(
    _user: User = Depends(get_current_user),
) -> List[Dict[str, str]]:
    return [
        {"id": "quick", "name": "Quick Scan", "command": "nmap -T4 -F", "description": "Fast scan"},
        {"id": "services", "name": "Services", "command": "nmap -sV -sC -T4", "description": "Service detection"},
        {"id": "full", "name": "Full Port Scan", "command": "nmap -sS -sV -p- -T4", "description": "All TCP ports"},
        {"id": "vuln", "name": "Vulnerability Scan", "command": "nmap -sV --script=vuln", "description": "Common vulns"},
    ]
