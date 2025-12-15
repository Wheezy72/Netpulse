from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, require_role
from app.core.config import settings
from app.models.script_job import ScriptJob, ScriptJobStatus
from app.models.user import UserRole
from app.tasks import execute_script_job_task

# Scripts API: business-grade endpoints for managing Smart Scripts and
# their execution lifecycle. Uploads are restricted to operators/admins
# and prebuilt scripts are governed by an allowlist in settings.
router = APIRouter()


def _sanitize_filename(filename: str) -> str:
    """Normalize an uploaded filename to a filesystem-safe variant."""
    base = os.path.basename(filename)
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", base)


class RunPrebuiltScriptRequest(BaseModel):
    """Request body for triggering a prebuilt Smart Script."""

    script_name: str
    # Arbitrary parameters passed to the script via ctx.params
    params: Optional[Dict[str, Any]] = None
    # Optional association to a Device so we can show per-host history
    device_id: Optional[int] = None


class PrebuiltScriptSettingsItem(BaseModel):
    """Single prebuilt script and its policy flags."""

    name: str
    allowed: bool
    lab_only: bool


class PrebuiltScriptSettingsResponse(BaseModel):
    scripts: list[PrebuiltScriptSettingsItem]


class PrebuiltScriptSettingsUpdateRequest(BaseModel):
    scripts: list[PrebuiltScriptSettingsItem]


@router.post(
    "/upload",
    status_code=status.HTTP_201_CREATED,
    summary="Upload and execute a Python script",
    dependencies=[Depends(require_role(UserRole.OPERATOR, UserRole.ADMIN))],
)
async def upload_script(
    file: UploadFile,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    """Persist an uploaded Python file and enqueue it as a ScriptJob.

    In business environments, uploading arbitrary scripts should be reserved
    for trusted operators or automation pipelines.
    """
    if not file.filename.endswith(".py"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Only .py files are allowed",
        )

    scripts_dir = Path(settings.scripts_base_dir) / settings.scripts_uploads_subdir
    scripts_dir.mkdir(parents=True, exist_ok=True)

    sanitized = _sanitize_filename(file.filename)
    destination = scripts_dir / sanitized

    content = await file.read()
    destination.write_bytes(content)

    job = ScriptJob(
        script_name=file.filename,
        script_path=str(destination),
        status=ScriptJobStatus.PENDING,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    # Enqueue Celery job in the background (non-blocking for HTTP request)
    background_tasks.add_task(execute_script_job_task.delay, job.id)

    return {"job_id": job.id, "script_name": job.script_name}


@router.get(
    "/settings",
    response_model=PrebuiltScriptSettingsResponse,
    summary="Get prebuilt script allowlist configuration",
    dependencies=[Depends(require_role(UserRole.VIEWER, UserRole.OPERATOR, UserRole.ADMIN))],
)
async def get_prebuilt_script_settings() -> PrebuiltScriptSettingsResponse:
    """Return all prebuilt scripts and their allowlist flags.

    This inspects the prebuilt scripts directory and marks each file as
    allowed / lab-only based on the current Settings values.
    """
    scripts_dir = Path(settings.scripts_base_dir) / settings.scripts_prebuilt_subdir
    scripts_dir.mkdir(parents=True, exist_ok=True)

    files = sorted(p.name for p in scripts_dir.glob("*.py"))
    items: list[PrebuiltScriptSettingsItem] = []
    for name in files:
        items.append(
            PrebuiltScriptSettingsItem(
                name=name,
                allowed=name in settings.allowed_prebuilt_scripts,
                lab_only=name in settings.lab_only_prebuilt_scripts,
            )
        )

    return PrebuiltScriptSettingsResponse(scripts=items)


@router.put(
    "/settings",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Update prebuilt script allowlist configuration",
    dependencies=[Depends(require_role(UserRole.ADMIN))],
)
async def update_prebuilt_script_settings(
    payload: PrebuiltScriptSettingsUpdateRequest,
) -> None:
    """Update the in-memory allowlist configuration for prebuilt scripts.

    Changes take effect immediately for new script runs but are not persisted
    across process restarts; for persistent policy, also update environment
    variables or configuration.
    """
    allowed = [item.name for item in payload.scripts if item.allowed]
    lab_only = [item.name for item in payload.scripts if item.lab_only]

    settings.allowed_prebuilt_scripts = allowed
    settings.lab_only_prebuilt_scripts = lab_only


@router.post(
    "/prebuilt/run",
    status_code=status.HTTP_201_CREATED,
    summary="Run a prebuilt script by name",
    dependencies=[Depends(require_role(UserRole.OPERATOR, UserRole.ADMIN))],
)
async def run_prebuilt_script(
    payload: RunPrebuiltScriptRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    """Execute a script from the prebuilt scripts directory with optional parameters.

    A business-grade allowlist is enforced via Settings.allowed_prebuilt_scripts.
    Lab-only scripts can be separated using Settings.lab_only_prebuilt_scripts.
    """
    scripts_dir = Path(settings.scripts_base_dir) / settings.scripts_prebuilt_subdir
    script_path = scripts_dir / payload.script_name

    # Enforce allowlist for business environments. You can tune this via env vars.
    if payload.script_name not in settings.allowed_prebuilt_scripts:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This script is not allowed by current policy",
        )

    if not script_path.exists():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Prebuilt script not found",
        )

    job = ScriptJob(
        script_name=payload.script_name,
        script_path=str(script_path),
        status=ScriptJobStatus.PENDING,
        params=payload.params or {},
        device_id=payload.device_id,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    # Fire-and-forget Celery job; status can be polled via /scripts/{job_id}
    background_tasks.add_task(execute_script_job_task.delay, job.id)

    return {"job_id": job.id, "script_name": job.script_name}


@router.get(
    "/{job_id}",
    summary="Get script job status",
)
async def get_script_job(
    job_id: int,
    db: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
    """Return ScriptJob metadata, including logs and structured result."""
    job = await db.get(ScriptJob, job_id)
    if job is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Job not found")

    return {
        "id": job.id,
        "script_name": job.script_name,
        "status": job.status.value,
        "created_at": job.created_at,
        "started_at": job.started_at,
        "finished_at": job.finished_at,
        "logs": job.logs,
        "result": job.result,
    }