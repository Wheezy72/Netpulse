from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, UploadFile, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, get_current_user
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
)
async def get_prebuilt_script_settings() -> PrebuiltScriptSettingsResponse:
    """Return all prebuilt scripts and their allowlist flags.

    This inspects the prebuilt scripts directory and marks each file as
    allowed based on the current Settings values.
    """
    scripts_dir = Path(settings.scripts_base_dir) / settings.scripts_prebuilt_subdir
    scripts_dir.mkdir(parents=True, exist_ok=True)

    files = sorted(p.name for p in scripts_dir.glob("*.py"))
    items: list[PrebuiltScriptSettingsItem] = []
    for name in files:
        items.append(
            PrebuiltScriptSettingsItem(
                name=name,
                allowed=(
                    not settings.allowed_prebuilt_scripts
                    or name in settings.allowed_prebuilt_scripts
                ),
            )
        )

    return PrebuiltScriptSettingsResponse(scripts=items)


@router.put(
    "/settings",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Update prebuilt script allowlist configuration",
)
async def update_prebuilt_script_settings(
    payload: PrebuiltScriptSettingsUpdateRequest,
) -> None:
    """Update the in-memory allowlist configuration for prebuilt scripts.

    Changes take effect immediately for new script runs but are not persisted
    across process restarts; for persistent policy, also update environment
    variables or configuration.
    """
    # If everything is allowed, admins can choose to leave the list empty.
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
) -> dict[str, Any]:
    """Execute a script from the prebuilt scripts directory with optional parameters.

    An allowlist can be enforced via Settings.allowed_prebuilt_scripts. If the list
    is empty, any script present in the prebuilt directory is eligible to run.
    """
    scripts_dir = Path(settings.scripts_base_dir) / settings.scripts_prebuilt_subdir
    script_path = scripts_dir / payload.script_name

    # Enforce allowlist if it is explicitly configured.
    # If the list is empty, allow any script present in the prebuilt directory.
    if settings.allowed_prebuilt_scripts and payload.script_name not in settings.allowed_prebuilt_scripts:
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


class AIScriptRequest(BaseModel):
    description: str
    target: Optional[str] = None


class AIScriptResponse(BaseModel):
    script: str
    filename: str
    explanation: str


SCRIPT_TEMPLATE = '''"""Auto-generated NetPulse script: {title}

Generated from description: {description}
"""


async def run(ctx):
    """Main entry point called by NetPulse script executor.

    Available context:
      ctx.db      - async SQLAlchemy session
      ctx.logger  - logging callback (ctx.logger("message"))
      ctx.params  - dict of parameters passed at invocation
      ctx.job_id  - current ScriptJob ID
    """
{body}
'''


def _generate_script_fallback(description: str, target: str | None) -> tuple[str, str, str]:
    desc_lower = description.lower()
    title = description[:60]

    if any(w in desc_lower for w in ["ping", "alive", "up"]):
        body = (
            '    import subprocess\n'
            f'    target = ctx.params.get("target", "{target or "192.168.1.1"}")\n'
            '    ctx.logger(f"Pinging {{target}}...")\n'
            '    result = subprocess.run(["ping", "-c", "4", target], capture_output=True, text=True, timeout=30)\n'
            '    ctx.logger(result.stdout)\n'
            '    return {"target": target, "output": result.stdout, "returncode": result.returncode}\n'
        )
        explanation = "Runs a simple ping test against the specified target and returns the output."
    elif any(w in desc_lower for w in ["scan", "nmap", "port"]):
        body = (
            '    import subprocess\n'
            f'    target = ctx.params.get("target", "{target or "192.168.1.0/24"}")\n'
            '    ctx.logger(f"Running nmap scan on {{target}}...")\n'
            '    result = subprocess.run(["nmap", "-T4", "-F", target], capture_output=True, text=True, timeout=120)\n'
            '    ctx.logger(result.stdout)\n'
            '    return {"target": target, "output": result.stdout}\n'
        )
        explanation = "Performs a quick Nmap scan of the top 100 ports on the target."
    elif any(w in desc_lower for w in ["device", "inventory", "list"]):
        body = (
            "    from sqlalchemy import text\n"
            '    ctx.logger("Fetching device inventory...")\n'
            '    result = await ctx.db.execute(text("SELECT id, hostname, ip_address, device_type, last_seen FROM devices ORDER BY last_seen DESC"))\n'
            "    devices = [dict(row._mapping) for row in result.fetchall()]\n"
            '    ctx.logger(f"Found {len(devices)} devices")\n'
            "    for d in devices:\n"
            "        hostname = d.get('hostname', 'unknown')\n"
            "        ip = d['ip_address']\n"
            '        ctx.logger(f"  {hostname} - {ip}")\n'
            '    return {"devices": [str(d) for d in devices], "count": len(devices)}\n'
        )
        explanation = "Queries the database for all discovered devices and lists them."
    elif any(w in desc_lower for w in ["dns", "resolve", "lookup"]):
        t = target or "google.com"
        body = (
            "    import socket\n"
            f'    target = ctx.params.get("target", "{t}")\n'
            '    ctx.logger(f"Resolving DNS for {{target}}...")\n'
            "    try:\n"
            "        result = socket.getaddrinfo(target, None)\n"
            "        ips = list(set(addr[4][0] for addr in result))\n"
            '        ctx.logger(f"Resolved to: {ips}")\n'
            '        return {"target": target, "resolved_ips": ips}\n'
            "    except socket.gaierror as e:\n"
            '        ctx.logger(f"DNS resolution failed: {e}")\n'
            '        return {"target": target, "error": str(e)}\n'
        )
        explanation = "Performs DNS resolution for the specified target hostname."
    elif any(w in desc_lower for w in ["traceroute", "trace", "route", "hop"]):
        body = (
            '    import subprocess\n'
            f'    target = ctx.params.get("target", "{target or "8.8.8.8"}")\n'
            '    ctx.logger(f"Running traceroute to {{target}}...")\n'
            '    result = subprocess.run(["traceroute", "-m", "20", target], capture_output=True, text=True, timeout=60)\n'
            '    ctx.logger(result.stdout)\n'
            '    return {"target": target, "output": result.stdout}\n'
        )
        explanation = "Runs a traceroute to the target to map the network path."
    else:
        body = (
            f'    ctx.logger("Running custom task: {title}")\n'
            f'    target = ctx.params.get("target", "{target or ""}")\n'
            '    ctx.logger(f"Target: {target}")\n'
            '    ctx.logger("Task completed successfully")\n'
            '    return {"status": "completed", "description": "' + title.replace('"', '\\"') + '"}\n'
        )
        explanation = "A template script for your custom task. You can edit the code before running it."

    filename = re.sub(r"[^a-z0-9]+", "_", description.lower())[:40].strip("_") + ".py"
    script = SCRIPT_TEMPLATE.format(title=title, description=description, body=body)
    return script, filename, explanation


@router.post(
    "/ai-generate",
    response_model=AIScriptResponse,
    summary="Generate a Python script from a natural language description",
)
async def ai_generate_script(
    payload: AIScriptRequest,
    current_user: User = Depends(get_current_user),
) -> AIScriptResponse:
    from app.api.routes.settings import _ai_settings

    ai_config = _ai_settings.get(current_user.id)

    if ai_config and ai_config.enabled and ai_config.api_key:
        try:
            import httpx

            system_prompt = (
                "You are a Python script generator for NetPulse Enterprise, a network monitoring tool.\n"
                "Generate a complete, working Python script that follows this exact pattern:\n\n"
                "```python\nasync def run(ctx):\n"
                "    # ctx.db - async SQLAlchemy session\n"
                "    # ctx.logger - log function: ctx.logger(\"message\")\n"
                "    # ctx.params - dict of parameters\n"
                "    # ctx.job_id - current job ID\n\n"
                "    # Your code here\n"
                "    return {\"result\": \"value\"}\n```\n\n"
                "Rules:\n"
                "- The script MUST have an `async def run(ctx)` function as the entry point\n"
                "- Use ctx.logger() for all output messages\n"
                "- Use ctx.params.get(\"target\", \"default\") for target parameters\n"
                "- Use ctx.db for database queries (SQLAlchemy async)\n"
                "- For shell commands, use subprocess.run() with timeout\n"
                "- Always return a dict with results\n"
                "- Include proper error handling\n"
                "- Keep scripts focused and practical for network operations\n\n"
                "IMPORTANT: Output ONLY the Python code inside a single ```python code fence, "
                "followed by a brief one-sentence explanation on a new line after the closing fence."
            )

            user_msg = f"Generate a Python script for: {payload.description}"
            if payload.target:
                user_msg += f"\nTarget: {payload.target}"

            response = httpx.post(
                "https://api.openai.com/v1/chat/completions",
                headers={"Authorization": f"Bearer {ai_config.api_key}"},
                json={
                    "model": ai_config.model or "gpt-4o-mini",
                    "messages": [
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_msg},
                    ],
                    "max_tokens": 1500,
                },
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()

            choices = data.get("choices")
            if not choices:
                raise ValueError("No choices in AI response")

            ai_text = choices[0]["message"]["content"]

            code_match = re.search(r"```python\s*\n(.*?)```", ai_text, re.DOTALL)
            if code_match:
                script_code = code_match.group(1).strip()
                after_fence = ai_text[code_match.end():].strip()
                explanation = after_fence[:300] if after_fence else "AI-generated script based on your description."
            else:
                script_code = ai_text.strip()
                explanation = "AI-generated script based on your description."

            filename = re.sub(r"[^a-z0-9]+", "_", payload.description.lower())[:40].strip("_") + ".py"

            full_script = f'"""\nAuto-generated NetPulse script\nDescription: {payload.description}\n"""\n\n{script_code}\n'

            return AIScriptResponse(script=full_script, filename=filename, explanation=explanation)
        except Exception as exc:
            import logging
            logging.getLogger(__name__).warning("AI script generation failed: %s", exc)

    script, filename, explanation = _generate_script_fallback(payload.description, payload.target)
    return AIScriptResponse(script=script, filename=filename, explanation=explanation)


class RunGeneratedScriptRequest(BaseModel):
    script: str
    filename: str = "ai_generated.py"
    target: Optional[str] = None


@router.post(
    "/run-generated",
    status_code=status.HTTP_201_CREATED,
    summary="Save and execute an AI-generated script",
)
async def run_generated_script(
    payload: RunGeneratedScriptRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    script_code = payload.script
    filename = payload.filename
    target = payload.target

    if not script_code.strip():
        raise HTTPException(status_code=400, detail="Script code is empty")

    if not filename.endswith(".py"):
        filename = filename.rsplit(".", 1)[0] + ".py" if "." in filename else filename + ".py"

    scripts_dir = Path(settings.scripts_base_dir) / settings.scripts_uploads_subdir
    scripts_dir.mkdir(parents=True, exist_ok=True)

    sanitized = _sanitize_filename(filename)
    destination = scripts_dir / sanitized
    destination.write_text(script_code)

    params = {}
    if target:
        params["target"] = target

    job = ScriptJob(
        script_name=sanitized,
        script_path=str(destination),
        status=ScriptJobStatus.PENDING,
        params=params,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    background_tasks.add_task(execute_script_job_task.delay, job.id)

    return {"job_id": job.id, "script_name": job.script_name}