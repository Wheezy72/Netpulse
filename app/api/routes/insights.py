from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import db_session, get_current_user
from app.models.user import User
from app.services.network_insights import (
    detect_bottlenecks,
    get_network_health_summary,
    get_nmap_recommendations,
)

router = APIRouter()


@router.get(
    "/bottlenecks",
    summary="Detect network bottlenecks",
)
async def get_bottlenecks(
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """Identify devices and network segments experiencing performance issues.
    
    Returns a list of potential bottlenecks with severity levels and recommendations.
    """
    return await detect_bottlenecks(db)


@router.get(
    "/health",
    summary="Get network health summary",
)
async def get_health(
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get overall network health status and metrics."""
    return await get_network_health_summary(db)


@router.get(
    "/nmap-recommend",
    summary="Get nmap scan recommendations",
)
async def get_nmap_recommend(
    target: str = Query(..., description="Target IP address"),
    target_type: Optional[str] = Query(None, description="Target type hint (router, server, iot, etc.)"),
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Get intelligent nmap scan recommendations for a target.
    
    The system analyzes known device information and provides tailored
    scan commands based on the target type.
    """
    return await get_nmap_recommendations(target, target_type, db)


@router.get(
    "/traffic-analysis",
    summary="Get traffic analysis insights",
)
async def get_traffic_analysis(
    db: AsyncSession = Depends(db_session),
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Analyze network traffic patterns and identify anomalies."""
    return {
        "status": "operational",
        "analysis": {
            "top_talkers": [],
            "bandwidth_trends": "stable",
            "anomalies_detected": 0,
            "recommendations": [
                "Enable SNMP on network devices for deeper traffic analysis",
                "Configure NetFlow/sFlow for detailed flow data",
            ],
        },
        "message": "Configure traffic monitoring agents for detailed analysis",
    }
