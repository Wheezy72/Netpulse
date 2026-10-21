from __future__ import annotations

"""WebSocket endpoints for live streams.

Provides:
- /api/ws/scripts/{job_id}: stream ScriptJob logs as JSON events.
- /api/ws/scans/{scan_id}: stream Nmap scan output as plain text frames (xterm).
- /api/ws/metrics: stream real-time dashboard metrics as JSON.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Set

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from jose import JWTError, jwt
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import resolve_user_from_subject
from app.core.config import settings
from app.db.session import async_session_factory
from app.models.metric import Metric
from app.models.scan_job import ScanJob, ScanJobStatus
from app.models.script_job import ScriptJob, ScriptJobStatus
from app.models.user import User, UserRole

router = APIRouter()

metrics_clients: Set[WebSocket] = set()

# --- SSH console state -------------------------------------------------------
# Host keys pinned on first use, keyed by "ip:port": the key material plus the
# fingerprint shown to the operator when it was trusted. Written to disk so a
# restart does not silently re-trust whatever answers on that address next
# time — an in-memory map would make every reboot a fresh first use.
_pinned_host_keys: dict[str, dict[str, str]] = {}
_pinned_hosts_path = Path(settings.ssh_known_hosts_file)

# Open sessions per user id. Bumped before connect, released in `finally`.
_session_slots: dict[int, int] = {}


def _load_pinned_hosts() -> None:
    """Read previously pinned keys; a missing or corrupt file is not fatal."""
    try:
        data = json.loads(_pinned_hosts_path.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            _pinned_host_keys.update(
                {
                    str(k): {str(kk): str(vv) for kk, vv in v.items()}
                    for k, v in data.items()
                    if isinstance(v, dict)
                }
            )
    except FileNotFoundError:
        pass
    except Exception as exc:  # noqa: BLE001 - bad file must not block logins
        logging.getLogger("app.ws.ssh").warning(
            "Could not read %s: %s", _pinned_hosts_path, exc
        )


def _save_pinned_hosts() -> None:
    """Persist pins atomically so a crash mid-write cannot empty the file."""
    try:
        _pinned_hosts_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = _pinned_hosts_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(_pinned_host_keys, indent=2), encoding="utf-8")
        tmp.replace(_pinned_hosts_path)
    except Exception as exc:  # noqa: BLE001 - never break the session for this
        logging.getLogger("app.ws.ssh").warning(
            "Could not persist SSH host keys: %s", exc
        )


_load_pinned_hosts()


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

    subject = payload.get("sub") or ""
    if not subject:
        return None

    # Same resolution as the REST dependency: id-based subjects first, with
    # the legacy email form as a fallback.
    return await resolve_user_from_subject(db, subject)


@router.websocket("/scripts/{job_id}")
async def websocket_script_logs(websocket: WebSocket, job_id: int) -> None:
    """Stream ScriptJob logs and status over WebSocket (JSON events)."""

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

        if user.role != UserRole.ADMIN:
            await websocket.send_json({"event": "error", "message": "Forbidden"})
            await websocket.close(code=4403)
            return

        try:
            last_len = 0
            while True:
                result = await db.execute(select(ScriptJob).where(ScriptJob.id == job_id))
                job = result.scalar_one_or_none()
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

                # End the read-only transaction so we see updates on the next poll.
                await db.rollback()
                await asyncio.sleep(1)
        except WebSocketDisconnect:
            return
        except Exception as exc:  # noqa: BLE001
            await websocket.send_json(
                {"event": "error", "message": f"Unexpected error: {exc!r}"}
            )
            await websocket.close(code=1011)


@router.websocket("/scans/{scan_id}")
async def websocket_scan_output(websocket: WebSocket, scan_id: str) -> None:
    """Stream scan output as raw text frames suitable for xterm.js."""

    await websocket.accept()

    token = websocket.query_params.get("token")
    if not token:
        await websocket.send_text("[error] Missing token\n")
        await websocket.close(code=4401)
        return

    async with async_session_factory() as db:
        user = await _get_user_from_token(token, db)
        if user is None or not user.is_active:
            await websocket.send_text("[error] Unauthorized\n")
            await websocket.close(code=4401)
            return

        result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
        job = result.scalar_one_or_none()
        if job is None:
            await websocket.send_text("[error] Scan job not found\n")
            await websocket.close(code=4404)
            return

        artifact_path = Path(job.artifact_path or f"data/scans/scan_{scan_id}.txt")
        last_pos = 0

        try:
            while True:
                result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
                job = result.scalar_one_or_none()
                if job is None:
                    await websocket.send_text("[error] Scan job not found\n")
                    await websocket.close(code=4404)
                    return

                if job.artifact_path:
                    artifact_path = Path(job.artifact_path)

                if artifact_path.exists() and artifact_path.is_file():
                    with artifact_path.open("rb") as f:
                        f.seek(last_pos)
                        data = f.read()
                        last_pos = f.tell()
                    if data:
                        await websocket.send_text(data.decode(errors="replace"))

                if job.status in {ScanJobStatus.COMPLETED, ScanJobStatus.FAILED}:
                    # Flush once more and then close.
                    if artifact_path.exists() and artifact_path.is_file():
                        with artifact_path.open("rb") as f:
                            f.seek(last_pos)
                            data = f.read()
                            last_pos = f.tell()
                        if data:
                            await websocket.send_text(data.decode(errors="replace"))

                    await websocket.close(code=1000)
                    return

                # End the read-only transaction so we see updates on the next poll.
                await db.rollback()
                await asyncio.sleep(0.35)
        except WebSocketDisconnect:
            return
        except Exception as exc:  # noqa: BLE001
            try:
                await websocket.send_text(f"\n[ws-error] {exc!r}\n")
            finally:
                await websocket.close(code=1011)


@router.websocket("/metrics")
async def websocket_metrics(websocket: WebSocket) -> None:
    """Stream real-time dashboard metrics over WebSocket."""

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

    metrics_clients.add(websocket)

    def _isoformat_utc_z(ts: datetime) -> str:
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        else:
            ts = ts.astimezone(timezone.utc)
        return ts.isoformat().replace("+00:00", "Z")

    metric_types = {"latency_ms", "jitter_ms", "packet_loss_pct"}
    last_sent_timestamp: datetime | None = None

    def _mean(values: list[float]) -> float | None:
        if not values:
            return None
        return sum(values) / len(values)

    try:
        while True:
            internet_health: float | None = None
            snapshot_ts: datetime | None = None
            rows: list[Metric] = []

            async with async_session_factory() as db:
                health_result = await db.execute(
                    select(Metric)
                    .where(Metric.metric_type == "internet_health")
                    .order_by(Metric.timestamp.desc())
                    .limit(1)
                )
                health_metric = health_result.scalar_one_or_none()

                if health_metric is not None:
                    snapshot_ts = health_metric.timestamp

                    if last_sent_timestamp is None or snapshot_ts > last_sent_timestamp:
                        internet_health = float(health_metric.value)

                        result = await db.execute(
                            select(Metric).where(
                                Metric.metric_type.in_(metric_types),
                                Metric.timestamp == snapshot_ts,
                            )
                        )
                        rows = list(result.scalars().all())

                        if not rows:
                            window_start = snapshot_ts - timedelta(minutes=15)
                            fallback_result = await db.execute(
                                select(Metric)
                                .where(
                                    Metric.metric_type.in_(metric_types),
                                    Metric.timestamp >= window_start,
                                    Metric.timestamp <= snapshot_ts,
                                )
                                .order_by(Metric.timestamp.desc())
                            )
                            rows = list(fallback_result.scalars().all())

            if snapshot_ts is None or internet_health is None:
                await asyncio.sleep(3)
                continue

            latest_by_target_and_type: dict[tuple[str, str], float] = {}

            # Rows are ordered newest-first in the fallback path. Keep the first occurrence
            # to represent "latest" per (target, metric_type).
            for m in rows:
                tags = m.tags or {}
                target = tags.get("target")
                if not target:
                    continue
                key = (target, m.metric_type)
                if key not in latest_by_target_and_type:
                    latest_by_target_and_type[key] = float(m.value)

            latency_values: list[float] = []
            jitter_values: list[float] = []
            loss_values: list[float] = []

            for (_, metric_type), value in latest_by_target_and_type.items():
                if metric_type == "latency_ms":
                    latency_values.append(value)
                elif metric_type == "jitter_ms":
                    jitter_values.append(value)
                elif metric_type == "packet_loss_pct":
                    loss_values.append(value)

            latency = _mean(latency_values)
            jitter = _mean(jitter_values)
            packet_loss = _mean(loss_values)

            metrics = {
                "event": "metrics",
                "data": {
                    "internet_health": round(internet_health, 1),
                    "latency_ms": round(latency, 2) if latency is not None else None,
                    "jitter_ms": round(jitter, 2) if jitter is not None else None,
                    "packet_loss_pct": round(packet_loss, 2)
                    if packet_loss is not None
                    else None,
                    "timestamp": _isoformat_utc_z(snapshot_ts),
                },
            }

            await websocket.send_json(metrics)
            last_sent_timestamp = snapshot_ts
            await asyncio.sleep(3)

    except WebSocketDisconnect:
        metrics_clients.discard(websocket)
    except Exception:
        metrics_clients.discard(websocket)
        await websocket.close(code=1011)


@router.websocket("/ssh")
async def websocket_ssh(websocket: WebSocket) -> None:
    """Interactive SSH terminal over WebSocket.

    The credential never appears in the URL. The client opens
    ``/api/ws/ssh?ip=…`` and immediately sends one JSON frame::

        {"type": "auth", "token": "…", "username": "…",
         "password": "…", "port": 22}

    so neither the password nor the bearer token lands in an access log,
    a proxy log or browser history.
    """
    await websocket.accept()

    ip = websocket.query_params.get("ip")
    if not ip:
        await websocket.send_text("\r\n[error] Missing target IP address.\r\n")
        await websocket.close(code=4400)
        return

    # First frame must be the handshake; anything else is a client that has
    # not been updated, so close rather than guess.
    try:
        handshake = json.loads(await asyncio.wait_for(websocket.receive_text(), timeout=15))
    except Exception as exc:  # noqa: BLE001 - reported to the operator below
        logging.getLogger("app.ws.ssh").warning(
            "SSH handshake failed from %s: %s: %s",
            websocket.client.host if websocket.client else "?",
            type(exc).__name__,
            exc,
        )
        await websocket.send_text(
            "\r\n[error] No credentials received. This console expects an auth "
            "frame as its first message.\r\n"
        )
        await websocket.close(code=4400)
        return

    if not isinstance(handshake, dict) or handshake.get("type") != "auth":
        await websocket.send_text("\r\n[error] First frame must be an auth message.\r\n")
        await websocket.close(code=4400)
        return

    token = handshake.get("token") or ""
    username = str(handshake.get("username") or "")
    password = str(handshake.get("password") or "")

    if not token or not ip or not username:
        await websocket.send_text("\r\n[error] Missing token, username or target IP address.\r\n")
        await websocket.close(code=4400)
        return

    try:
        port = int(handshake.get("port", 22))
    except (TypeError, ValueError):
        await websocket.send_text("\r\n[error] Invalid port number.\r\n")
        await websocket.close(code=4400)
        return

    async with async_session_factory() as db:
        user = await _get_user_from_token(token, db)
        if user is None or not user.is_active:
            await websocket.send_text("\r\n[error] Unauthorized.\r\n")
            await websocket.close(code=4401)
            return

        # An interactive shell on network gear is a write-capable action; a
        # read-only viewer must not get one. Mirrors the scripts socket.
        if user.role != UserRole.ADMIN:
            await websocket.send_text("\r\n[error] Your role cannot open console sessions.\r\n")
            await websocket.close(code=4403)
            return
        user_id = user.id

    # Imported here so the rest of the module does not pay for paramiko.
    # Everything used above (json, logging) is imported at module scope:
    # a function-local `import logging` shadows the module name for the whole
    # function and turns an earlier `logging.getLogger(...)` into an
    # UnboundLocalError, which is exactly what masked the real bug here.
    import paramiko
    import base64
    import hashlib

    logger = logging.getLogger("app.ws.ssh")

    # --- Concurrent session cap ------------------------------------------------
    # Each session holds a worker thread plus a socket; without a ceiling one
    # account can pin every thread the process has.
    _session_slots.setdefault(user_id, 0)
    if _session_slots[user_id] >= settings.max_ssh_sessions_per_user:
        await websocket.send_text(
            f"\r\n[error] Session limit reached "
            f"({settings.max_ssh_sessions_per_user} per account). Close one and retry.\r\n"
        )
        await websocket.close(code=4429)
        return
    _session_slots[user_id] += 1

    # --- Host key pinning -------------------------------------------------------
    cache_key = f"{ip}:{port}"

    class _PinnedKeyPolicy(paramiko.MissingHostKeyPolicy):
        """Trust on first use, then refuse any change.

        paramiko calls this for every key it has not been told about. The first
        one is recorded together with its fingerprint; a later key that differs
        means the box was replaced or someone is between us and it, so the
        connection is refused instead of silently accepted.
        """

        fingerprint: str | None = None

        def missing_host_key(self, client, hostname, key):  # noqa: ANN001
            blob = key.get_base64()
            digest = base64.b64encode(
                hashlib.sha256(key.asbytes()).digest()
            ).decode().rstrip("=")
            fingerprint = f"SHA256:{digest}"

            pinned = _pinned_host_keys.get(cache_key)
            if pinned is not None:
                if pinned.get("key") != blob:
                    raise paramiko.SSHException(
                        f"Host key for {cache_key} does not match the pinned key "
                        f"({pinned.get('fingerprint', 'recorded')}). Refusing to connect."
                    )
                self.fingerprint = pinned.get("fingerprint")
                return

            if not settings.ssh_trust_on_first_use:
                raise paramiko.SSHException(
                    f"Unknown host key for {cache_key} and trust-on-first-use is "
                    "disabled. Pin the key before connecting."
                )

            _pinned_host_keys[cache_key] = {"key": blob, "fingerprint": fingerprint}
            _save_pinned_hosts()
            self.fingerprint = fingerprint
            logger.warning(
                "SSH host key pinned for %s: %s (%s)",
                cache_key,
                fingerprint,
                key.get_name(),
            )

    policy = _PinnedKeyPolicy()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(policy)

    await websocket.send_text(f"\r\nConnecting to {username}@{ip}:{port}...\r\n")

    def _connect():
        client.connect(
            hostname=ip,
            port=port,
            username=username,
            password=password,
            timeout=settings.ssh_connect_timeout,
            banner_timeout=settings.ssh_connect_timeout,
            auth_timeout=settings.ssh_connect_timeout,
            allow_agent=False,
            look_for_keys=False
        )
        return client.invoke_shell(term="xterm", width=80, height=24)

    try:
        chan = await asyncio.to_thread(_connect)
    except Exception as e:
        await websocket.send_text(f"\r\n[error] Connection failed: {e}\r\n")
        await websocket.close(code=1011)
        client.close()
        _session_slots[user_id] = max(_session_slots.get(user_id, 1) - 1, 0)
        return

    # Show the key we pinned (or matched) so it can be compared with what the
    # device itself displays before anything sensitive is typed.
    if policy.fingerprint:
        await websocket.send_text(f"\r\nHost key ({cache_key}): {policy.fingerprint}\r\n")

    await websocket.send_text("Connected!\r\n\r\n")

    async def shell_reader():
        """Push channel output to the socket by blocking, not by polling."""
        try:
            while True:
                # recv() blocks until the remote sends something or the session
                # ends, so an idle console costs no CPU. The previous build
                # woke a worker thread fifty times a second for every open
                # session, which is measurable on a small box.
                data = await asyncio.to_thread(chan.recv, 4096)
                if not data:
                    await websocket.send_text("\r\n[session closed by remote host]\r\n")
                    break
                await websocket.send_text(data.decode("utf-8", errors="replace"))
        except Exception as exc:
            logger.error(f"SSH reader error: {exc}")
        finally:
            try:
                await websocket.close()
            except Exception:
                pass

    async def ws_reader():
        try:
            while True:
                data = await websocket.receive_text()
                if data.startswith("{") and data.endswith("}"):
                    try:
                        msg = json.loads(data)
                        if msg.get("type") == "resize":
                            cols = msg.get("cols", 80)
                            rows = msg.get("rows", 24)
                            chan.resize_pty(width=cols, height=rows)
                            continue
                    except Exception:
                        pass
                # Send to channel
                def _send(d):
                    chan.send(d.encode("utf-8"))
                await asyncio.to_thread(_send, data)
        except Exception:
            pass
        finally:
            try:
                chan.close()
            except Exception:
                pass
            client.close()

    try:
        await asyncio.gather(shell_reader(), ws_reader())
    finally:
        # Always hand the slot back, even when the socket or channel dies.
        _session_slots[user_id] = max(_session_slots.get(user_id, 1) - 1, 0)
