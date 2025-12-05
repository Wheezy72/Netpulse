from __future__ import annotations

"""
WebSocket endpoints for live streams.

Currently provides:
- /api/ws/scripts/{job_id}: stream ScriptJob logs to the Brain console.
"""

import asyncio
from typing import Any

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.config import settings
from app.db.session import async_session_factory
from app.models.script_job import ScriptJob, ScriptJobStatus
from app.models.user import User

router = APIRouter()


async def _get_user_from_token(token: str, db: AsyncSession) -> User | None:
    """Decode a JWT and return the associated User, or None if invalid."""
    try:
        payload: dict[str, Any] = jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
        )
    except JWTError:
        return None

    email = payload.get("sub")
    if not email:
        return None

    result = await db.execute(select(User).where(User.email == email))
    return result.scalar_one_or_none()


@router.websocket("/scripts/{job_id}")
async def websocket_script_logs(websocket: WebSocket, job_id: int) -> None:
    """
    Stream ScriptJob logs and status over WebSocket.

    The client must supply a JWT access token as a `token` query parameter:
      ws://host/api/ws/scripts/{job_id}?token=...

    Messages are JSON objects with the shape:
      { "event": "log", "message": "...", "status": "running" }
      { "event": "complete", "status": "success" }
      { "event": "error", "message": "..." }
    """
    await websocket.accept()

    token = websocket.query_params.get("token")
    if not token:
        await websocket.send_json({"event": "error", "message": "Missing token"})
        await websocket.close(code=4401)
        return

    async with async_session_factory() as db:
        user = await _get_user_from_token(token, db)
        if user is None or not user.is_active:
            await websocket.send_json({"event": "error", "message": "Unauthorized"})
            await websocket.close(code=4401)
            return

        try:
            last_len = 0
            while True:
                job = await db.get(ScriptJob, job_id)
                if job is None:
                    await websocket.send_json(
                        {"event": "error", "message": "Script job not found"}
                    )
                    await websocket.close(code=4404)
                    return

                logs = job.logs or ""
                if len(logs) > last_len:
                    new_segment = logs[last_len:]
                    last_len = len(logs)
                    for line in new_segment.splitlines():
                        if line.strip():
                            await websocket.send_json(
                                {
                                    "event": "log",
                                    "message": line,
                                    "status": job.status.value,
                                }
                            )

                if job.status in {ScriptJobStatus.SUCCESS, ScriptJobStatus.FAILED}:
                    await websocket.send_json(
                        {"event": "complete", "status": job.status.value}
                    )
                    await websocket.close(code=1000)
                    return

                await asyncio.sleep(1)
        except WebSocketDisconnect:
            # Client disconnected; nothing else to do
            return
        except Exception as exc:  # noqa: BLE001
            await websocket.send_json(
                {"event": "error", "message": f"Unexpected error: {exc!r}"}
            )
            await websocket.close(code=1011)