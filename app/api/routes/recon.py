from __future__ import annotations

from typing import List

from fastapi import APIRouter
from pydantic import BaseModel

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


@router.post(
    "/nmap-recommendations",
    response_model=NmapRecommendationResponse,
    summary="Get context-aware Nmap script recommendations for a target",
)
async def nmap_recommendations(services: List[ServicePort]) -> NmapRecommendationResponse:
    """Return suggested Nmap scripts based on detected services/ports.

    This is intentionally heuristic and stateless; you can extend it as needed
    or back it with a rule engine in future iterations.
    """
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

    return NmapRecommendationResponse(recommendations=recommendations)