from __future__ import annotations

from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, require_admin, require_role
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
    """
    Heuristic mapping from detected services to Nmap NSE scripts.

    Rather than dumping a flat list, we group scripts by what you're trying
    to achieve (enumeration, authentication checks, vulnerability probing).
    """
    recommendations: list[NmapRecommendation] = []

    normalized = {s.service.lower() for s in services}

    # Web services (HTTP/HTTPS)
    if "http" in normalized or "https" in normalized:
        # General web enumeration
        recommendations.append(
            NmapRecommendation(
                reason="Web app recon and enumeration",
                scripts=[
                    "http-title",
                    "http-enum",
                    "http-methods",
                    "http-headers",
                    "http-robots.txt",
                ],
            )
        )
        # Common web vulnerabilities / misconfigurations
        recommendations.append(
            NmapRecommendation(
                reason="Check web application for common vulnerabilities",
                scripts=[
                    "http-vuln-cve2017-5638",
                    "http-shellshock",
                    "http-sql-injection",
                    "http-vuln-cve2006-3392",
                ],
            )
        )
        # Auth and brute-force style checks (lab use only)
        recommendations.append(
            NmapRecommendation(
                reason="Web auth and brute-force oriented checks (lab only)",
                scripts=[
                    "http-auth",
                    "http-brute",
                ],
            )
        )

    # SSH
    if "ssh" in normalized:
        recommendations.append(
            NmapRecommendation(
                reason="SSH fingerprinting and crypto hygiene",
                scripts=[
                    "ssh2-enum-algos",
                    "ssh-hostkey",
                    "ssh-auth-methods",
                ],
            )
        )
        recommendations.append(
            NmapRecommendation(
                reason="SSH brute-force/auth stress (lab use only)",
                scripts=[
                    "ssh-brute",
                ],
            )
        )

    # TLS/SSL
    if "ssl" in normalized or "tls" in normalized:
        recommendations.append(
            NmapRecommendation(
                reason="TLS/SSL certificate and cipher review",
                scripts=[
                    "ssl-cert",
                    "ssl-enum-ciphers",
                    "ssl-known-key",
                ],
            )
        )
        recommendations.append(
            NmapRecommendation(
                reason="Check for legacy TLS/SSL vulnerabilities",
                scripts=[
                    "ssl-heartbleed",
                    "ssl-poodle",
                    "sslv2-drown",
                ],
            )
        )

    # FTP
    if "ftp" in normalized:
        recommendations.append(
            NmapRecommendation(
                reason="FTP configuration and anonymous access",
                scripts=[
                    "ftp-anon",
                    "ftp-bounce",
                ],
            )
        )
        recommendations.append(
            NmapRecommendation(
                reason="FTP auth and brute-force (lab use only)",
                scripts=[
                    "ftp-brute",
                ],
            )
        )

    # SMB / Windows file sharing
    if "smb" in normalized or "microsoft-ds" in normalized:
        recommendations.append(
            NmapRecommendation(
                reason="SMB share and user enumeration",
                scripts=[
                    "smb-enum-shares",
                    "smb-enum-users",
                    "smb-os-discovery",
                ],
            )
        )
        recommendations.append(
            NmapRecommendation(
                reason="SMB vulnerability checks (EternalBlue and others)",
                scripts=[
                    "smb-vuln-ms17-010",
                    "smb-vuln-ms08-067",
                    "smb-vuln-ms10-054",
                ],
            )
        )
        recommendations.append(
            NmapRecommendation(
                reason="SMB security posture review",
                scripts=[
                    "smb-security-mode",
                    "smb2-security-mode",
                ],
            )
        )

    return recommendations


@router.post(
    "/nmap-recommendations",
    response_model=NmapRecommendationResponse,
    summary="Get context-aware Nmap script recommendations for a target",
    dependencies=[Depends(require_role())],
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
    dependencies=[Depends(require_admin)],
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
            event_type="scan",
        )

    return NmapScanResponse(services=services, recommendations=recs)