from __future__ import annotations

import re
import shlex
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
from app.services.nmap_capabilities import (
    CATALOG_VERSION,
    NMAP_INSTALL_HINT,
    NmapUnavailableError,
    available_profiles,
    detect_capabilities,
    plan_command,
)
from app.services.nmap_runner import run_scan_job
from app.services.scan_policy import is_restricted_target, validate_target

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
    "--max-retries",
    "--version-intensity",
    "--top-ports",
    "--script",
}

# Allow any built-in NSE script name (admins only) but block obvious injection / path traversal.
SCRIPT_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*\*?$")


class NmapCommandRequest(BaseModel):
    command: str | None = None
    profile: str | None = None
    target: str
    save_results: bool = True


class NmapPlanRequest(BaseModel):
    profile: str
    target: str
    ports: str | None = None


class NmapPlanResponse(BaseModel):
    profile: str
    argv: List[str]
    display: str
    notes: List[str]
    vuln_scripts: List[str]


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

    args = job.arguments or {}
    # Planner-driven jobs store the rendered command instead of raw input.
    command = args.get("command") or args.get("rendered_command") or ""
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
    """Basic safety check for a user-supplied target.

    Thin delegate to app.services.scan_policy so the API layer and the
    discovery service validate targets exactly the same way.
    """
    return validate_target(target)
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
            parts = tok.split("=", 1)
            flag = parts[0]
            value = parts[1]
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


# Scan types that craft packets by hand and therefore need raw sockets.
_RAW_SCAN_TYPES = {"-sS", "-sA", "-sW", "-sM", "-sZ", "-sN", "-sF", "-sX"}


def _apply_unprivileged_mode(args: list[str]) -> list[str]:
    """Adapt a safe argv to a box where nmap cannot open raw sockets.

    A Windows install with the Npcap driver stopped (or any unprivileged Unix
    user) makes `nmap -sn`/`-sS` die with "dnet: Failed to open device", which
    the UI can only show as "scan failed". nmap itself can still work there:
    `--unprivileged` switches host discovery and port scanning to connect(),
    and `-Pn` stops it from attempting a raw ping probe first.

    The target is always the last element, so it survives the rewrite.
    """
    body, target = args[:-1], args[-1]

    if "-sn" in body:
        # A ping sweep has no ports to scan; only host discovery applies.
        cleaned = [tok for tok in body if tok != "-PE"]
        if "--unprivileged" not in cleaned:
            cleaned.append("--unprivileged")
        return [*cleaned, target]

    rewritten: list[str] = []
    has_connect_scan = False
    for tok in body:
        if tok in _RAW_SCAN_TYPES:
            if not has_connect_scan:
                rewritten.append("-sT")
                has_connect_scan = True
            continue
        if tok == "-sT":
            has_connect_scan = True
        rewritten.append(tok)

    if not has_connect_scan:
        # Insert right after the binary name so later flags keep their order.
        rewritten.insert(1, "-sT")
    if "-Pn" not in rewritten:
        rewritten.append("-Pn")
    if "--unprivileged" not in rewritten:
        rewritten.append("--unprivileged")

    return [*rewritten, target]


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


def _is_restricted_segment(target: str) -> bool:
    """True when the target sits inside a restricted/fragile VLAN CIDR.

    Thin delegate to app.services.scan_policy; the rule itself (including
    the legacy medical_iot_vlan_cidrs fallback) lives there so the nmap
    pipeline and device discovery cannot drift apart.
    """
    return is_restricted_target(target)
def _contains_active_syn_flags(command: str) -> bool:
    """Return True if the command contains flags that trigger active SYN probing."""
    # -sS (SYN stealth), -sA (ACK), -sW (Window), -sM (Maimon) – all send raw packets.
    active_flags = {"-sS", "-sA", "-sW", "-sM", "-sZ"}
    tokens = set(shlex.split(command))
    return bool(tokens & active_flags)


@router.get("/capabilities")
async def get_nmap_capabilities(
    _user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """What this nmap install supports, from the cached capability probe."""
    caps = detect_capabilities()
    return {
        "available": caps.available,
        "version": caps.version,
        "privileged": caps.privileged,
        "script_categories": sorted(caps.script_categories),
        "vuln_script_count": len(caps.vuln_scripts),
        "catalog_version": CATALOG_VERSION,
        "scripts_dir": caps.scripts_dir,
        "detected_at": caps.detected_at,
    }


@router.get("/profiles")
async def get_nmap_profiles(
    _user: User = Depends(get_current_user),
) -> List[Dict[str, str]]:
    """Named scan profiles the planner accepts."""
    return available_profiles()


@router.post("/plan")
async def plan_nmap_command(
    request: NmapPlanRequest,
    _user: User = Depends(get_current_user),
) -> NmapPlanResponse:
    """Preview the exact argv a profile would run, without executing it."""
    if not _validate_target(request.target):
        raise HTTPException(status_code=400, detail="Invalid target format")

    caps = detect_capabilities()
    try:
        plan = plan_command(request.profile, request.target, caps, ports=request.ports)
    except NmapUnavailableError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    return NmapPlanResponse(
        profile=plan.profile,
        argv=plan.argv,
        display=plan.display,
        notes=plan.notes,
        vuln_scripts=plan.vuln_scripts,
    )


@router.post("/execute", response_model=ScanResult)
async def execute_nmap(
    request: NmapCommandRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(require_admin),
) -> ScanResult:
    if not _validate_target(request.target):
        raise HTTPException(status_code=400, detail="Invalid target format")

    has_command = bool(request.command and request.command.strip())
    has_profile = bool(request.profile and request.profile.strip())
    if has_command == has_profile:
        raise HTTPException(
            status_code=400,
            detail="Provide exactly one of 'command' or 'profile'",
        )

    caps = detect_capabilities()
    if not caps.available:
        # Do not enqueue a job that is guaranteed to fail.
        raise HTTPException(status_code=503, detail=NMAP_INSTALL_HINT)

    if has_profile:
        try:
            plan = plan_command(request.profile or "", request.target, caps)
        except NmapUnavailableError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        # Block active SYN scans against restricted/fragile VLAN segments.
        # These segments must only be monitored passively (ARP / Zeek); the
        # planner emits -sS only when raw-socket privileges are available.
        if _is_restricted_segment(request.target) and "-sS" in plan.argv:
            raise HTTPException(
                status_code=403,
                detail=(
                    "Active scanning is strictly prohibited on designated fragile or restricted subnets. "
                    "Use passive discovery methods instead."
                ),
            )

        safe_args = plan.argv
        command_str = plan.display
        job_profile = next(
            (item["label"] for item in available_profiles() if item["id"] == plan.profile),
            plan.profile,
        )
        job_arguments: Dict[str, Any] = {
            "profile": plan.profile,
            "safe_args": safe_args,
            "rendered_command": command_str,
        }
    else:
        # Block active SYN scans against restricted/fragile VLAN segments.
        # These segments must only be monitored passively (ARP / Zeek).
        if _is_restricted_segment(request.target) and _contains_active_syn_flags(request.command or ""):
            raise HTTPException(
                status_code=403,
                detail=(
                    "Active scanning is strictly prohibited on designated fragile or restricted subnets. "
                    "Use passive discovery methods instead."
                ),
            )

        safe_args = _parse_safe_nmap_args(request.command or "", request.target)
        if not caps.privileged:
            safe_args = _apply_unprivileged_mode(safe_args)
        command_str = " ".join(safe_args)
        job_profile = get_scan_type_from_command(command_str)
        job_arguments = {
            "command": request.command,
            "safe_args": safe_args,
            "rendered_command": command_str,
        }

    job = ScanJob(
        target=request.target,
        profile=job_profile,
        arguments=job_arguments,
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
