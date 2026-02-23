"""
Threat Intelligence API Routes

Provides endpoints for IP reputation checking via external APIs like AbuseIPDB.
"""

from __future__ import annotations

from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from app.api.deps import get_current_user
from app.core.config import settings
from app.models.user import User
from app.services.abuseipdb import (
    ABUSEIPDB_CATEGORIES,
    AbuseIPDBError,
    AbuseIPDBRateLimitExceeded,
    AbuseIPDBService,
    InvalidAPIKey,
    abuseipdb_service,
)

router = APIRouter()


class IPCheckRequest(BaseModel):
    ip_address: str = Field(..., description="IP address to check")
    max_age_days: int = Field(default=90, ge=1, le=365, description="Max age of reports in days")


class IPCheckResponse(BaseModel):
    ip_address: str
    is_public: bool
    abuse_confidence_score: int
    country_code: Optional[str]
    isp: Optional[str]
    domain: Optional[str]
    total_reports: int
    last_reported_at: Optional[str]
    is_whitelisted: bool
    is_tor: bool
    usage_type: Optional[str]
    risk_level: str


class BulkIPCheckRequest(BaseModel):
    ip_addresses: list[str] = Field(..., max_length=100, description="List of IPs to check (max 100)")
    max_age_days: int = Field(default=90, ge=1, le=365)


class BulkIPCheckResponse(BaseModel):
    results: list[IPCheckResponse]
    checked_count: int
    high_risk_count: int


class ReportIPRequest(BaseModel):
    ip_address: str = Field(..., description="IP address to report")
    categories: list[int] = Field(..., min_length=1, description="Category IDs for the report")
    comment: Optional[str] = Field(None, max_length=1024, description="Optional comment")


class ThreatIntelStatusResponse(BaseModel):
    abuseipdb_configured: bool
    abuseipdb_categories: dict[int, str]


@router.get(
    "/status",
    summary="Get threat intelligence service status",
    response_model=ThreatIntelStatusResponse,
)
async def get_status(
    current_user: User = Depends(get_current_user),
) -> ThreatIntelStatusResponse:
    return ThreatIntelStatusResponse(
        abuseipdb_configured=abuseipdb_service.is_configured,
        abuseipdb_categories=ABUSEIPDB_CATEGORIES,
    )


@router.post(
    "/check",
    summary="Check IP reputation via AbuseIPDB",
    response_model=IPCheckResponse,
)
async def check_ip(
    request: IPCheckRequest,
    current_user: User = Depends(get_current_user),
) -> IPCheckResponse:
    if not abuseipdb_service.is_configured:
        raise HTTPException(
            status_code=503,
            detail="AbuseIPDB API key not configured. Add it in Settings > Threat Intelligence.",
        )
    
    try:
        result = await abuseipdb_service.check_ip(
            ip_address=request.ip_address,
            max_age_in_days=request.max_age_days,
            raise_on_error=True,
        )
    except AbuseIPDBRateLimitExceeded as e:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {e.retry_after} seconds." if e.retry_after else "Rate limit exceeded. Try again later.",
        )
    except InvalidAPIKey:
        raise HTTPException(
            status_code=401,
            detail="Invalid AbuseIPDB API key. Please check your settings.",
        )
    except AbuseIPDBError as e:
        raise HTTPException(
            status_code=502,
            detail=f"Failed to check IP reputation: {str(e)}",
        )
    
    if result is None:
        raise HTTPException(
            status_code=502,
            detail="Failed to check IP reputation. Please try again.",
        )
    
    return IPCheckResponse(
        ip_address=result.ip_address,
        is_public=result.is_public,
        abuse_confidence_score=result.abuse_confidence_score,
        country_code=result.country_code,
        isp=result.isp,
        domain=result.domain,
        total_reports=result.total_reports,
        last_reported_at=result.last_reported_at.isoformat() if result.last_reported_at else None,
        is_whitelisted=result.is_whitelisted,
        is_tor=result.is_tor,
        usage_type=result.usage_type,
        risk_level=result.risk_level,
    )


@router.post(
    "/check-bulk",
    summary="Check multiple IP addresses",
    response_model=BulkIPCheckResponse,
)
async def check_bulk(
    request: BulkIPCheckRequest,
    current_user: User = Depends(get_current_user),
) -> BulkIPCheckResponse:
    if not abuseipdb_service.is_configured:
        raise HTTPException(
            status_code=503,
            detail="AbuseIPDB API key not configured. Add it in Settings > Threat Intelligence.",
        )
    
    results = await abuseipdb_service.check_bulk(
        ip_addresses=request.ip_addresses,
        max_age_in_days=request.max_age_days,
    )
    
    response_results = [
        IPCheckResponse(
            ip_address=r.ip_address,
            is_public=r.is_public,
            abuse_confidence_score=r.abuse_confidence_score,
            country_code=r.country_code,
            isp=r.isp,
            domain=r.domain,
            total_reports=r.total_reports,
            last_reported_at=r.last_reported_at.isoformat() if r.last_reported_at else None,
            is_whitelisted=r.is_whitelisted,
            is_tor=r.is_tor,
            usage_type=r.usage_type,
            risk_level=r.risk_level,
        )
        for r in results
    ]
    
    high_risk_count = sum(1 for r in results if r.risk_level in ("high", "critical"))
    
    return BulkIPCheckResponse(
        results=response_results,
        checked_count=len(response_results),
        high_risk_count=high_risk_count,
    )


@router.post(
    "/report",
    summary="Report an abusive IP to AbuseIPDB",
)
async def report_ip(
    request: ReportIPRequest,
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    if not abuseipdb_service.is_configured:
        raise HTTPException(
            status_code=503,
            detail="AbuseIPDB API key not configured.",
        )
    
    for cat_id in request.categories:
        if cat_id not in ABUSEIPDB_CATEGORIES:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid category ID: {cat_id}",
            )
    
    success = await abuseipdb_service.report_ip(
        ip_address=request.ip_address,
        categories=request.categories,
        comment=request.comment,
    )
    
    if not success:
        raise HTTPException(
            status_code=502,
            detail="Failed to report IP. Please try again.",
        )
    
    return {"success": True, "message": f"IP {request.ip_address} reported successfully"}


@router.get(
    "/blacklist",
    summary="Get known malicious IPs from AbuseIPDB blacklist",
)
async def get_blacklist(
    confidence_minimum: int = Query(default=90, ge=25, le=100),
    limit: int = Query(default=100, ge=1, le=10000),
    current_user: User = Depends(get_current_user),
) -> dict[str, Any]:
    if not abuseipdb_service.is_configured:
        raise HTTPException(
            status_code=503,
            detail="AbuseIPDB API key not configured.",
        )
    
    ips = await abuseipdb_service.get_blacklist(
        confidence_minimum=confidence_minimum,
        limit=limit,
    )
    
    return {
        "count": len(ips),
        "confidence_minimum": confidence_minimum,
        "ip_addresses": ips,
    }
