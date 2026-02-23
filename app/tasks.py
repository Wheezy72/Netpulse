from __future__ import annotations

"""
Celery task definitions.

These tasks wrap the core service functions used for:
- Latency monitoring (Pulse).
- Script execution (Brain).
- Passive ARP discovery and packet capture (Eye/Vault).
- Vulnerability alerting (notifications).
- Scheduled reminders (e.g. scan reminders).
"""

import asyncio

from celery.utils.log import get_task_logger
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from app.core.celery_app import celery_app
from app.core.config import settings
from app.services.alerts import process_vulnerability_alerts, send_system_alert
from app.services.latency_monitor import monitor_latency
from app.services.packet_capture import capture_to_pcap
from app.services.recon import passive_arp_discovery
from app.services.script_executor import execute_script

logger = get_task_logger(__name__)


def _create_session_factory():
    """Create a fresh async engine and session factory for a Celery task.

    This avoids reusing an async engine across multiple event loops, which can
    cause 'Future attached to a different loop' errors when tasks are invoked
    repeatedly via asyncio.run().
    """
    engine = create_async_engine(settings.database_url, echo=False, future=True)
    factory = sessionmaker(bind=engine, expire_on_commit=False, class_=AsyncSession)
    return engine, factory


@celery_app.task(name="app.tasks.monitor_latency_task")
def monitor_latency_task() -> None:
    """Celery task wrapper for the Pulse module's latency monitoring."""

    async def _run() -> None:
        engine, factory = _create_session_factory()
        try:
            async with factory() as session:
                await monitor_latency(session)
        finally:
            await engine.dispose()

    asyncio.run(_run())


@celery_app.task(name="app.tasks.uptime_monitor_task")
def uptime_monitor_task() -> None:
    """Celery task that runs due uptime checks and persists results."""

    async def _run() -> None:
        from datetime import datetime

        from sqlalchemy import select

        from app.api.routes.uptime import _perform_check
        from app.models.uptime import UptimeTarget

        engine, factory = _create_session_factory()
        try:
            async with factory() as session:
                result = await session.execute(
                    select(UptimeTarget).where(UptimeTarget.is_active == True)
                )
                targets = list(result.scalars().all())

                now = datetime.utcnow()
                for target in targets:
                    if target.last_checked_at:
                        elapsed = (now - target.last_checked_at).total_seconds()
                        if elapsed < target.interval_seconds:
                            continue

                    check = await _perform_check(target)
                    session.add(check)

                    target.last_status = check.status
                    target.last_checked_at = check.timestamp
                    target.last_latency_ms = check.latency_ms
                    if check.status == "up":
                        target.consecutive_failures = 0
                    else:
                        target.consecutive_failures += 1

                await session.commit()
        finally:
            await engine.dispose()

    asyncio.run(_run())


@celery_app.task(name="app.tasks.execute_script_job_task")
def execute_script_job_task(job_id: int) -> None:
    """Celery task that executes a ScriptJob by ID."""
    async def _run() -> None:
        engine, factory = _create_session_factory()
        try:
            async with factory() as session:
                await execute_script(session, job_id)
        finally:
            await engine.dispose()

    asyncio.run(_run())


@celery_app.task(name="app.tasks.passive_arp_discovery_task")
def passive_arp_discovery_task() -> None:
    """Celery task that performs short passive ARP discovery.

    Uses the OS default interface instead of hard-coding 'eth0' to avoid
    failures on systems where that interface name does not exist.
    """
    async def _run() -> None:
        engine, factory = _create_session_factory()
        try:
            async with factory() as session:
                try:
                    await passive_arp_discovery(session, iface=None, duration=10)
                except ValueError as exc:
                    # Interface not found or not usable; log and skip rather than crashing.
                    logger.warning("Passive ARP discovery skipped: %s", exc)
        finally:
            await engine.dispose()

    asyncio.run(_run())


@celery_app.task(name="app.tasks.packet_capture_recent_task")
def packet_capture_recent_task(
    duration_seconds: int = 300,
    bpf_filter: str | None = None,
) -> int:
    """Celery task that performs a time-bounded packet capture and returns a capture ID."""
    async def _run() -> int:
        engine, factory = _create_session_factory()
        try:
            async with factory() as session:
                capture_id = await capture_to_pcap(
                    session,
                    duration_seconds=duration_seconds,
                    iface=None,
                    bpf_filter=bpf_filter,
                )
                return capture_id
        finally:
            await engine.dispose()

    return asyncio.run(_run())


@celery_app.task(name="app.tasks.index_pcap_file")
def index_pcap_file(pcap_file_id: int, chunk_size: int = 5000) -> int:
    """Parse a raw .pcap on disk and bulk insert packet metadata.

    This is designed for the PacketBrowser: read via PcapReader (streaming) and
    insert PcapPacket rows in chunks to avoid large in-memory lists.
    """

    async def _run() -> int:
        from datetime import datetime
        from pathlib import Path

        from sqlalchemy import delete, insert

        from app.models.packet_capture import PacketCapture
        from app.models.pcap_meta import PcapFile, PcapPacket

        engine, factory = _create_session_factory()
        try:
            async with factory() as session:
                pcap_file = await session.get(PcapFile, pcap_file_id)
                if not pcap_file:
                    return 0

                pcap_path = Path(pcap_file.filepath)
                if not pcap_path.exists():
                    pcap_file.index_error = "PCAP file not found on disk"
                    pcap_file.indexed_at = datetime.utcnow()
                    await session.commit()
                    return 0

                try:
                    # Re-indexing should not duplicate rows.
                    await session.execute(
                        delete(PcapPacket).where(PcapPacket.file_id == pcap_file_id)
                    )
                    await session.commit()

                    from scapy.all import IP, IPv6, PcapReader, TCP, UDP

                    packet_index = 0
                    inserted = 0
                    batch: list[dict] = []

                    reader = PcapReader(str(pcap_path))
                    try:
                        for pkt in reader:
                            packet_index += 1

                            src_ip = None
                            dst_ip = None
                            proto = None
                            if IP in pkt:
                                ip_layer = pkt[IP]
                                src_ip = ip_layer.src
                                dst_ip = ip_layer.dst
                                proto = str(ip_layer.proto)
                            elif IPv6 in pkt:
                                ip_layer = pkt[IPv6]
                                src_ip = ip_layer.src
                                dst_ip = ip_layer.dst
                                proto = str(ip_layer.nh)

                            src_port = None
                            dst_port = None
                            if TCP in pkt:
                                src_port = pkt[TCP].sport
                                dst_port = pkt[TCP].dport
                                proto = "TCP"
                            elif UDP in pkt:
                                src_port = pkt[UDP].sport
                                dst_port = pkt[UDP].dport
                                proto = "UDP"

                            batch.append(
                                {
                                    "file_id": pcap_file_id,
                                    "packet_index": packet_index,
                                    "timestamp": datetime.utcfromtimestamp(float(pkt.time)),
                                    "src_ip": src_ip,
                                    "dst_ip": dst_ip,
                                    "src_port": src_port,
                                    "dst_port": dst_port,
                                    "protocol": proto,
                                    "length": len(pkt),
                                }
                            )

                            if len(batch) >= chunk_size:
                                await session.execute(insert(PcapPacket), batch)
                                await session.commit()
                                inserted += len(batch)
                                batch.clear()

                    finally:
                        reader.close()

                    if batch:
                        await session.execute(insert(PcapPacket), batch)
                        await session.commit()
                        inserted += len(batch)

                    pcap_file.packet_count = packet_index
                    pcap_file.file_size_bytes = pcap_path.stat().st_size
                    pcap_file.indexed_at = datetime.utcnow()
                    pcap_file.index_error = None

                    if pcap_file.capture_id:
                        capture = await session.get(PacketCapture, pcap_file.capture_id)
                        if capture:
                            capture.packet_count = packet_index
                            capture.file_size_bytes = pcap_file.file_size_bytes

                    await session.commit()

                    # Create a synthetic ScanJob summarizing the PCAP index so it can be
                    # automatically analyzed by the Implicit AI Analyst.
                    try:
                        import uuid
                        from pathlib import Path as _Path

                        from sqlalchemy import func, select

                        from app.models.scan_job import ScanJob, ScanJobStatus

                        time_bounds = await session.execute(
                            select(
                                func.min(PcapPacket.timestamp),
                                func.max(PcapPacket.timestamp),
                            ).where(PcapPacket.file_id == pcap_file_id)
                        )
                        first_ts, last_ts = time_bounds.one()

                        proto_counts = await session.execute(
                            select(PcapPacket.protocol, func.count())
                            .where(PcapPacket.file_id == pcap_file_id)
                            .group_by(PcapPacket.protocol)
                            .order_by(func.count().desc())
                            .limit(10)
                        )

                        proto_lines: list[str] = [
                            f"- {proto or 'unknown'}: {cnt}" for proto, cnt in proto_counts.all()
                        ]

                        scan_id = str(uuid.uuid4())
                        scans_dir = _Path("data/scans")
                        scans_dir.mkdir(parents=True, exist_ok=True)
                        artifact_path = scans_dir / f"scan_{scan_id}.txt"

                        now = datetime.utcnow()
                        artifact = "\n".join(
                            [
                                "Profile: PCAP Index Summary",
                                f"PCAP File: {pcap_file.filename}",
                                f"Path: {pcap_file.filepath}",
                                f"Indexed packets: {pcap_file.packet_count}",
                                f"First packet: {first_ts.isoformat() if first_ts else '(unknown)'}",
                                f"Last packet: {last_ts.isoformat() if last_ts else '(unknown)'}",
                                "",
                                "Top protocols:",
                                *(proto_lines or ["- (none)"]),
                                "",
                                "Notes:",
                                "- This is metadata only (no payloads).",
                            ]
                        )

                        await asyncio.to_thread(
                            artifact_path.write_text, artifact, encoding="utf-8"
                        )

                        session.add(
                            ScanJob(
                                id=scan_id,
                                target=pcap_file.filename,
                                profile="PCAP Index Summary",
                                arguments={
                                    "pcap_file_id": pcap_file_id,
                                    "filepath": pcap_file.filepath,
                                },
                                status=ScanJobStatus.COMPLETED,
                                result_summary={
                                    "pcap_file_id": pcap_file_id,
                                    "packet_count": pcap_file.packet_count,
                                    "first_packet_at": first_ts.isoformat() if first_ts else None,
                                    "last_packet_at": last_ts.isoformat() if last_ts else None,
                                },
                                artifact_path=str(artifact_path),
                                requested_by_user_id=None,
                                started_at=now,
                                completed_at=now,
                            )
                        )
                        await session.commit()

                        try:
                            celery_app.send_task("app.tasks.analyze_scan_results", args=[scan_id])
                        except Exception:
                            pass
                    except Exception:
                        # Indexing success should not be impacted by AI analysis failures.
                        pass

                    return inserted

                except Exception as exc:
                    pcap_file.index_error = str(exc)
                    pcap_file.indexed_at = datetime.utcnow()
                    await session.commit()
                    raise
        finally:
            await engine.dispose()

    return asyncio.run(_run())


@celery_app.task(name="app.tasks.vulnerability_alert_task")
def vulnerability_alert_task() -> None:
    """Celery task that scans for new high/critical vulnerabilities and sends alerts."""
    async def _run() -> None:
        engine, factory = _create_session_factory()
        try:
            async with factory() as session:
                await process_vulnerability_alerts(session)
        finally:
            await engine.dispose()

    asyncio.run(_run())


@celery_app.task(name="app.tasks.scheduled_scan_reminder_task")
def scheduled_scan_reminder_task() -> None:
    """
    Celery task that sends a reminder about scheduled scans.

    This does not perform a scan itself; it simply nudges operators that
    it's time to run (or verify) their scheduled scan playbooks.
    """
    async def _run() -> None:
        subject = "[NetPulse] Scheduled scan reminder"
        body = (
            "This is your scheduled reminder to review and run your scan playbooks.\n"
            "Typical actions:\n"
            "  - Verify recon targets are up to date.\n"
            "  - Run Nmap profiles against critical segments.\n"
            "  - Review the dashboard for new vulnerabilities or anomalies."
        )
        await send_system_alert(subject, body, event_type="scan")

    asyncio.run(_run())


@celery_app.task(name="app.tasks.analyze_scan_results")
def analyze_scan_results(scan_id: str) -> None:
    """Analyze a completed ScanJob artifact with the configured LLM.

    The result is stored back into ScanJob.result_summary under the key
    `ai_briefing` so the UI can display an "AI Analyst Briefing".

    Notes:
    - Uses provider/model from the requesting user's stored AI settings.
    - API keys are loaded from environment variables only.
    - Input is truncated to avoid sending huge artifacts.
    """

    async def _run() -> None:
        import os
        from datetime import datetime
        from pathlib import Path

        import httpx

        from app.api.routes.settings import AISettings, get_ai_api_key, load_ai_settings
        from app.models.scan_job import ScanJob, ScanJobStatus

        engine, factory = _create_session_factory()
        try:
            async with factory() as session:
                job = await session.get(ScanJob, scan_id)
                if not job:
                    return

                if job.status != ScanJobStatus.COMPLETED:
                    return

                # Determine which AI config to use.
                config: AISettings | None = None
                if job.requested_by_user_id:
                    config = await load_ai_settings(session, job.requested_by_user_id)

                # If no per-user settings are available, fall back to a sane default
                # if an environment key exists.
                if not config:
                    if os.environ.get("OPENAI_API_KEY"):
                        config = AISettings(provider="openai", model="gpt-4o-mini", enabled=True)
                    elif os.environ.get("ANTHROPIC_API_KEY"):
                        config = AISettings(provider="anthropic", model="claude-3-5-sonnet-latest", enabled=True)

                if not config or not config.enabled:
                    return

                # Do not re-run analysis if we already have one.
                existing = job.result_summary or {}
                if isinstance(existing, dict) and existing.get("ai_briefing"):
                    return

                artifact_text = ""
                if job.artifact_path and Path(job.artifact_path).exists():
                    # Read the tail to cap memory usage.
                    max_bytes = 80_000
                    p = Path(job.artifact_path)
                    size = p.stat().st_size
                    with p.open("rb") as f:
                        if size > max_bytes:
                            f.seek(size - max_bytes)
                        artifact_text = f.read().decode(errors="replace")

                if not artifact_text.strip():
                    existing = job.result_summary or {}
                    if isinstance(existing, dict):
                        existing["ai_error"] = "No artifact output available to analyze"
                        existing["ai_analyzed_at"] = datetime.utcnow().isoformat() + "Z"
                        job.result_summary = existing
                        await session.commit()
                    return

                system_prompt = (
                    "You are a Senior Security Analyst. Summarize the scan results for an operator. "
                    "Return ONE short paragraph (max ~100 words) highlighting ONLY: "
                    "(1) Critical/high CVEs or vulnerabilities, (2) exposed sensitive ports/services, "
                    "(3) unusual anomalies. If nothing critical is found, say so briefly."
                )

                user_prompt = (
                    f"Scan ID: {job.id}\nTarget: {job.target}\nProfile: {job.profile}\n\n"
                    "RAW OUTPUT (may be truncated):\n"
                    f"{artifact_text}\n"
                )

                provider = config.provider
                if provider in {"groq", "together", "google"}:
                    provider = "openai"

                api_key = get_ai_api_key(provider)

                model_name = config.model
                if provider == "custom" and config.custom_model:
                    model_name = config.custom_model

                async def _call_openai(base_url: str) -> str:
                    if not api_key:
                        raise ValueError("Missing OPENAI_API_KEY")
                    payload = {
                        "model": model_name,
                        "messages": [
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": user_prompt},
                        ],
                        "max_tokens": 220,
                        "temperature": 0.2,
                    }
                    async with httpx.AsyncClient(timeout=60) as client:
                        resp = await client.post(
                            base_url,
                            headers={"Authorization": f"Bearer {api_key}"},
                            json=payload,
                        )
                        resp.raise_for_status()
                        data = resp.json()
                        choices = data.get("choices") or []
                        if not choices:
                            raise ValueError("No choices in OpenAI response")
                        return (choices[0].get("message") or {}).get("content") or ""

                async def _call_anthropic() -> str:
                    if not api_key:
                        raise ValueError("Missing ANTHROPIC_API_KEY")
                    async with httpx.AsyncClient(timeout=60) as client:
                        resp = await client.post(
                            "https://api.anthropic.com/v1/messages",
                            headers={
                                "x-api-key": api_key,
                                "anthropic-version": "2023-06-01",
                                "content-type": "application/json",
                            },
                            json={
                                "model": config.model,
                                "max_tokens": 220,
                                "system": system_prompt,
                                "messages": [{"role": "user", "content": user_prompt}],
                            },
                        )
                        resp.raise_for_status()
                        data = resp.json()
                        blocks = data.get("content") or []
                        return " ".join(
                            b.get("text", "") for b in blocks if b.get("type") == "text"
                        )

                async def _call_ollama() -> str:
                    base = (config.custom_base_url or "http://localhost:11434").rstrip("/")
                    async with httpx.AsyncClient(timeout=120) as client:
                        resp = await client.post(
                            f"{base}/api/chat",
                            json={
                                "model": config.model or config.custom_model or "llama3.1",
                                "messages": [
                                    {"role": "system", "content": system_prompt},
                                    {"role": "user", "content": user_prompt},
                                ],
                                "stream": False,
                            },
                        )
                        resp.raise_for_status()
                        data = resp.json()
                        return (data.get("message") or {}).get("content") or ""

                async def _call_custom_openai() -> str:
                    base = (config.custom_base_url or "").rstrip("/")
                    if not base:
                        raise ValueError("Missing custom_base_url")
                    return await _call_openai(f"{base}/chat/completions")

                try:
                    briefing = ""
                    if provider in ("openai",):
                        briefing = await _call_openai("https://api.openai.com/v1/chat/completions")
                    elif provider == "custom":
                        briefing = await _call_custom_openai()
                    elif provider == "anthropic":
                        briefing = await _call_anthropic()
                    elif provider == "ollama":
                        briefing = await _call_ollama()
                    else:
                        raise ValueError(f"Unsupported provider: {provider}")

                    briefing = briefing.strip()
                    if not briefing:
                        raise ValueError("Empty AI response")

                    result = job.result_summary or {}
                    if not isinstance(result, dict):
                        result = {}
                    result.update(
                        {
                            "ai_briefing": briefing,
                            "ai_provider": provider,
                            "ai_model": model_name,
                            "ai_analyzed_at": datetime.utcnow().isoformat() + "Z",
                        }
                    )
                    job.result_summary = result
                    await session.commit()
                except Exception as exc:
                    result = job.result_summary or {}
                    if not isinstance(result, dict):
                        result = {}
                    result.update(
                        {
                            "ai_error": str(exc),
                            "ai_provider": provider,
                            "ai_model": model_name,
                            "ai_analyzed_at": datetime.utcnow().isoformat() + "Z",
                        }
                    )
                    job.result_summary = result
                    await session.commit()
        finally:
            await engine.dispose()

    asyncio.run(_run())