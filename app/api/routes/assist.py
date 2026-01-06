from __future__ import annotations

"""
assist.py

AI Copilot endpoint for NetPulse. Given a target (device, pulse, capture, script job)
and an optional free-text question, gathers context from the database and calls an
external LLM provider (e.g. OpenAI GPT or Google Gemini) to generate an analysis.

Configuration is via environment / settings:

  AI_PROVIDER: "openai" or "gemini"
  AI_API_KEY: API key for the chosen provider
  AI_MODEL_NAME: model identifier (e.g. "gpt-4.1-mini", "gemini-1.5-pro")

If configuration is missing or invalid, the endpoint returns 503 with an error
message explaining what is missing.
"""

from typing import Literal, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, require_role
from app.core.config import settings
from app.models.device import Device
from app.models.metric import Metric
from app.models.script_job import ScriptJob
from app.models.vault import PacketCapture  # type: ignore[import-not-found]


router = APIRouter()


class AssistMode(str):
    DEVICE = "device"
    PULSE = "pulse"
    PCAP = "pcap"
    SCRIPT_JOB = "script_job"


class AssistRequest(BaseModel):
    mode: Literal["device", "pulse", "pcap", "script_job"]
    target_id: Optional[int] = None
    question: Optional[str] = None


class AssistResponse(BaseModel):
    answer: str


async def _load_device_context(db: AsyncSession, device_id: int) -> dict:
    device = await db.get(Device, device_id)
    if device is None:
        raise HTTPException(status_code=404, detail="Device not found")

    ctx: dict = {
        "type": "device",
        "id": device.id,
        "hostname": device.hostname,
        "ip_address": device.ip_address,
        "mac_address": device.mac_address,
        "device_type": device.device_type,
        "zone": device.zone,
        "vendor": device.vendor,
    }
    return ctx


async def _load_pulse_context(db: AsyncSession) -> dict:
    metric_result = await db.execute(
        select(Metric)
        .where(Metric.metric_type == "internet_health")
        .order_by(Metric.timestamp.desc())
        .limit(20)
    )
    points = metric_result.scalars().all()
    ctx_points = [
        {"timestamp": m.timestamp.isoformat(), "value": float(m.value)} for m in points
    ]
    return {"type": "pulse", "points": ctx_points}


async def _load_pcap_context(db: AsyncSession, capture_id: int) -> dict:
    capture = await db.get(PacketCapture, capture_id)
    if capture is None:
        raise HTTPException(status_code=404, detail="Capture not found")
    return {
        "type": "pcap",
        "id": capture.id,
        "iface": getattr(capture, "iface", None),
        "created_at": capture.created_at.isoformat() if capture.created_at else None,
        "packet_count": getattr(capture, "packet_count", None),
        "bpf_filter": getattr(capture, "bpf_filter", None),
    }


async def _load_script_context(db: AsyncSession, job_id: int) -> dict:
    job = await db.get(ScriptJob, job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Script job not found")
    return {
        "type": "script_job",
        "id": job.id,
        "script_name": job.script_name,
        "status": job.status.value,
        "created_at": job.created_at.isoformat() if job.created_at else None,
    }


def _build_prompt(mode: str, context: dict, question: Optional[str]) -> str:
    base = (
        "You are a helpful network operations assistant for NetPulse, a personal "
        "network console. Explain clearly and concisely, using bullet points when helpful. "
        "Assume the user controls this network.\n\n"
    )

    if mode == AssistMode.DEVICE:
        base += "Context: Device details\n"
        base += f"- ID: {context.get('id')}\n"
        base += f"- Hostname: {context.get('hostname')}\n"
        base += f"- IP: {context.get('ip_address')}\n"
        base += f"- MAC: {context.get('mac_address')}\n"
        base += f"- Type: {context.get('device_type')}\n"
        base += f"- Zone: {context.get('zone')}\n"
        base += f"- Vendor: {context.get('vendor')}\n\n"
    elif mode == AssistMode.PULSE:
        base += "Context: Recent Internet Health metrics (0-100)\n"
        for p in context.get("points", []):
            base += f"- {p['timestamp']}: {p['value']}\n"
        base += "\n"
    elif mode == AssistMode.PCAP:
        base += "Context: Packet capture metadata\n"
        base += f"- ID: {context.get('id')}\n"
        base += f"- Interface: {context.get('iface')}\n"
        base += f"- Packets: {context.get('packet_count')}\n"
        base += f"- Filter: {context.get('bpf_filter')}\n\n"
    elif mode == AssistMode.SCRIPT_JOB:
        base += "Context: Script job\n"
        base += f"- ID: {context.get('id')}\n"
        base += f"- Script name: {context.get('script_name')}\n"
        base += f"- Status: {context.get('status')}\n"
        base += f"- Created at: {context.get('created_at')}\n\n"

    if question:
        base += f"User question: {question}\n\n"
    else:
        base += "User question: Summarise what is happening and suggest what to check next.\n\n"

    base += "Answer:"
    return base


async def _call_openai(model: str, api_key: str, prompt: string) -> str:  # type: ignore[name-defined]
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    body = {
        "model": model,
        "messages": [
            {"role": "system", "content": "You are a network operations copilot."},
            {"role": "user", "content": prompt},
        ],
    }
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post("https://api.openai.com/v1/chat/completions", json=body, headers=headers)
    if resp.status_code != 200:
        raise HTTPException(status_code=503, detail=f"OpenAI error: {resp.text}")
    data = resp.json()
    return data["choices"][0]["message"]["content"]  # type: ignore[index]


async def _call_gemini(model: str, api_key: str, prompt: str) -> str:
    url = f"https://generativelanguage.googleapis.com/v1/models/{model}:generateContent?key={api_key}"
    body = {
        "contents": [
            {
                "parts": [{"text": prompt}],
            }
        ]
    }
    async with httpx.AsyncClient(timeout=30) as client:
        resp = await client.post(url, json=body)
    if resp.status_code != 200:
        raise HTTPException(status_code=503, detail=f"Gemini error: {resp.text}")
    data = resp.json()
    try:
        return data["candidates"][0]["content"]["parts"][0]["text"]  # type: ignore[index]
    except Exception:
        raise HTTPException(status_code=503, detail="Gemini response format unexpected")


@router.post(
    "/analyze",
    response_model=AssistResponse,
    summary="Ask the AI copilot to analyse a device, pulse, PCAP or script job",
    dependencies=[Depends(require_role())],
)
async def analyze(
    payload: AssistRequest,
    db: AsyncSession = Depends(db_session),
) -> AssistResponse:
    provider = getattr(settings, "ai_provider", "").lower()
    api_key = getattr(settings, "ai_api_key", "")
    model = getattr(settings, "ai_model_name", "")

    if not provider or not api_key or not model:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="AI provider is not configured. Set AI_PROVIDER, AI_API_KEY and AI_MODEL_NAME.",
        )

    # Gather context
    if payload.mode == AssistMode.DEVICE:
        if not payload.target_id:
            raise HTTPException(status_code=400, detail="target_id is required for device mode")
        ctx = await _load_device_context(db, payload.target_id)
    elif payload.mode == AssistMode.PULSE:
        ctx = await _load_pulse_context(db)
    elif payload.mode == AssistMode.PCAP:
        if not payload.target_id:
            raise HTTPException(status_code=400, detail="target_id is required for pcap mode")
        ctx = await _load_pcap_context(db, payload.target_id)
    elif payload.mode == AssistMode.SCRIPT_JOB:
        if not payload.target_id:
            raise HTTPException(status_code=400, detail="target_id is required for script_job mode")
        ctx = await _load_script_context(db, payload.target_id)
    else:
        raise HTTPException(status_code=400, detail="Unsupported analysis mode")

    prompt = _build_prompt(payload.mode, ctx, payload.question)

    if provider == "openai":
        answer = await _call_openai(model, api_key, prompt)  # type: ignore[arg-type]
    elif provider == "gemini":
        answer = await _call_gemini(model, api_key, prompt)
    else:
        raise HTTPException(status_code=400, detail="Unsupported AI_PROVIDER; use 'openai' or 'gemini'.")

    return AssistResponse(answer=answer)