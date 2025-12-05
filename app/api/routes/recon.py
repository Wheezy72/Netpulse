from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, require_role
from app.models.user import UserRole
from app.services.alerts import send_system_alert
from app.services.recon import DetectedService, run_nmap_scan

# Reconnaissance endpoints. In business networks, these should be limited to
# authenticated operators to avoid unintentional scanning of sensitive ranges.
router = APIRouter()


class ServicePort(BaseModel):
    port: int
    protocol: str
    service: str


class NmapRecommendation(BaseModel):
    reason: str
    scripts: List[str]


class NmapRecommendationResponse(BaseModel):
    recommendations: List[NmapRecommendation]


class NmapScanRequest(BaseModel):
    target: str


class NmapScanResponse(BaseModel):
    services: List[ServicePort]
    recommendations: List[NmapRecommendation]


def build_recommendations(services: List[ServicePort]) -> List[NmapRecommendation]:
    """Heuristic mapping from detected services to Nmap scripts."""
    recommendations: list[NmapRecommendation] = []

    normalized = {s.service.lower() for s in services}

    if "http" in normalized or "https" in normalized:
        recommendations.append(
            NmapRecommendation(
                reason="HTTP/HTTPS service detected",
                scripts=[
                    "http-title",
                    "http-enum",
                    "http-methods",
                    "http-robots.txt",
                    "http-vuln-cve2017-5638",
                    "http-shellshock",
                ],
            )
        )

    if "ssh" in normalized:
        recommendations.append(
            NmapRecommendation(
                reason="SSH service detected",
                scripts=[
                    "ssh2-enum-algos",
                    "ssh-hostkey",
                    "ssh-auth-methods",
                ],
            )
        )

    if "ssl" in normalized or "tls" in normalized:
        recommendations.append(
            NmapRecommendation(
                reason="TLS/SSL detected",
                scripts=[
                    "ssl-cert",
                    "ssl-enum-ciphers",
                    "ssl-heartbleed",
                    "ssl-known-key",
                ],
            )
        )

    if "ftp" in normalized:
        recommendations.append(
            NmapRecommendation(
                reason="FTP service detected",
                scripts=[
                    "ftp-anon",
                    "ftp-bounce",
                ],
            )
        )

    if "smb" in normalized or "microsoft-ds" in normalized:
        recommendations.append(
            NmapRecommendation(
                reason="SMB/Windows file sharing detected",
                scripts=[
                    "smb-enum-shares",
                    "smb-enum-users",
                    "smb-vuln-ms17-010",
                    "smb-vuln-ms08-067",
                ],
            )
        )

    return recommendations


@router.post(
    "/nmap-recommendations",
    response_model=NmapRecommendationResponse,
    summary="Get context-aware Nmap script recommendations for a target",
    dependencies=[Depends(require_role(UserRole.VIEWER, UserRole.OPERATOR, UserRole.ADMIN))],
)
async def nmap_recommendations(services: List[ServicePort]) -> NmapRecommendationResponse:
    """Return suggested Nmap scripts based on detected services/ports."""
    recs = build_recommendations(services)
    return NmapRecommendationResponse(recommendations=recs)


@router.post(
    "/scan",
    response_model=NmapScanResponse,
    status_code=status.HTTP_200_OK,
    summary="Run an on-demand Nmap scan and get script recommendations",
    dependencies=[Depends(require_role(UserRole.OPERATOR, UserRole.ADMIN))],
)
async def nmap_scan(
    payload: NmapScanRequest,
    db: AsyncSession = Depends(db_session),
) -> NmapScanResponse:
    """Run Nmap against a target and return detected services + script advice."""
    target = payload.target.strip()
    if not target:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Target is required",
        )

    detected: List[DetectedService] = await run_nmap_scan(db, target)

    services = [
        ServicePort(port=s.port, protocol=s.protocol, service=s.service)
        for s in detected
    ]
    recs = build_recommendations(services)

    # Best-effort alert that a scan has completed. This can be useful
    # for long-running scans or unattended runs.
    if detected:
        lines = [
            f"Target: {target}",
            f"Services detected: {len(services)}",
        ]
        for svc in services[:5]:
            lines.append(f"- {svc.protocol}/{svc.port}: {svc.service}")
        subject = f"[NetPulse] Nmap scan completed for {target}"
        body = "\n".join(lines)
        await send_system_alert(
            subject,
            body,
            channel=settings.alert_scan_channel,
        )

    return NmapScanResponse(services=services, recommendations=recs)