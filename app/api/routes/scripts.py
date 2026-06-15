from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, require_admin, require_compliance_role
from app.core.config import settings
from app.models.script_job import ScriptJob, ScriptJobStatus
from app.models.user import User
from app.tasks import execute_script_job_task

router = APIRouter()


def _sanitize_filename(filename: str) -> str:
    """Normalize an uploaded filename to a filesystem-safe variant."""
    base = os.path.basename(filename)
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", base)


class RunPrebuiltScriptRequest(BaseModel):
    script_name: str
    params: Optional[Dict[str, Any]] = None
    device_id: Optional[int] = None


class PrebuiltScriptSettingsItem(BaseModel):
    name: str
    allowed: bool


class PrebuiltScriptSettingsResponse(BaseModel):
    scripts: list[PrebuiltScriptSettingsItem]


class PrebuiltScriptSettingsUpdateRequest(BaseModel):
    scripts: list[PrebuiltScriptSettingsItem]


@router.post(
    "/upload",
    status_code=status.HTTP_201_CREATED,
    summary="Upload and execute a Python script",
)
async def upload_script(
    file: UploadFile,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(db_session),
    _user: User = Depends(require_admin),
) -> dict[str, Any]:
    """Persist an uploaded Python file and enqueue it as a ScriptJob."""
    if not file.filename.endswith(".py"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Only .py files are allowed")

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

    background_tasks.add_task(execute_script_job_task.delay, job.id)
    return {"job_id": job.id, "script_name": job.script_name}


@router.get(
    "/settings",
    response_model=PrebuiltScriptSettingsResponse,
    summary="Get prebuilt script allowlist configuration",
)
async def get_prebuilt_script_settings(
    _user: User = Depends(require_compliance_role()),
) -> PrebuiltScriptSettingsResponse:
    scripts_dir = Path(settings.scripts_base_dir) / settings.scripts_prebuilt_subdir
    scripts_dir.mkdir(parents=True, exist_ok=True)

    files = sorted(p.name for p in scripts_dir.glob("*.py"))
    items = [
        PrebuiltScriptSettingsItem(
            name=name,
            allowed=(not settings.allowed_prebuilt_scripts or name in settings.allowed_prebuilt_scripts),
        )
        for name in files
    ]

    return PrebuiltScriptSettingsResponse(scripts=items)


@router.put(
    "/settings",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Update prebuilt script allowlist configuration",
)
async def update_prebuilt_script_settings(
    payload: PrebuiltScriptSettingsUpdateRequest,
    _user: User = Depends(require_admin),
) -> None:
    allowed = [item.name for item in payload.scripts if item.allowed]
    settings.allowed_prebuilt_scripts = allowed


@router.post(
    "/prebuilt/run",
    status_code=status.HTTP_201_CREATED,
    summary="Run a prebuilt script by name",
)
async def run_prebuilt_script(
    payload: RunPrebuiltScriptRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(db_session),
    _user: User = Depends(require_admin),
) -> dict[str, Any]:
    scripts_dir = Path(settings.scripts_base_dir) / settings.scripts_prebuilt_subdir
    script_path = scripts_dir / payload.script_name

    if settings.allowed_prebuilt_scripts and payload.script_name not in settings.allowed_prebuilt_scripts:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="This script is not allowed by current policy")

    if not script_path.exists():
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Prebuilt script not found")

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

    background_tasks.add_task(execute_script_job_task.delay, job.id)
    return {"job_id": job.id, "script_name": job.script_name}

)
async def get_script_job(
    job_id: int,
    db: AsyncSession = Depends(db_session),
    _user: User = Depends(require_compliance_role()),
) -> dict[str, Any]:
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

