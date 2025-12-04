from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, UploadFile, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session
from app.core.config import settings
from app.models.script_job import ScriptJob, ScriptJobStatus
from app.tasks import execute_script_job_task

router = APIRouter()


def _sanitize_filename(filename: str) -> str:
    base = os.path.basename(filename)
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", base)


@router.post(
    "/upload",
    status_code=status.HTTP_201_CREATED,
    summary="Upload and execute a Python script",
)
async def upload_script(
    file: UploadFile,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(db_session),
) -> dict[str, Any]:
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
    "/{job_id}",
    summary="Get script job status",
)
async def get_script_job(
    job_id: int,
    db: AsyncSession = Depends(db_session),
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