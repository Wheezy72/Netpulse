"""
AbuseIPDB Integration Service

Provides IP reputation checking via the AbuseIPDB API.
Free tier: 1,000 checks/day, up to 100 IPs per bulk check.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Optional

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


class AbuseIPDBError(Exception):
    """Base exception for AbuseIPDB errors."""
    pass


class AbuseIPDBRateLimitExceeded(AbuseIPDBError):
    """Raised when API rate limit is exceeded."""
    def __init__(self, retry_after: Optional[int] = None):
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded. Retry after {retry_after}s" if retry_after else "Rate limit exceeded")


class InvalidAPIKey(AbuseIPDBError):
    """Raised when API key is invalid."""
    pass


class APIError(AbuseIPDBError):
    """Raised for general API errors."""
    def __init__(self, status_code: int, message: str):
        self.status_code = status_code
        super().__init__(f"API error {status_code}: {message}")


@dataclass
class IPReputationResult:
    ip_address: str
    is_public: bool
    abuse_confidence_score: int
    country_code: Optional[str]
    isp: Optional[str]
    domain: Optional[str]
    total_reports: int
    last_reported_at: Optional[datetime]
    is_whitelisted: bool
    is_tor: bool
    usage_type: Optional[str]
    risk_level: str
    
    @classmethod
    def from_api_response(cls, data: dict[str, Any]) -> "IPReputationResult":
        last_reported = None
        if data.get("lastReportedAt"):
            try:
                last_reported = datetime.fromisoformat(
                    data["lastReportedAt"].replace("Z", "+00:00")
                )
            except (ValueError, TypeError):
                pass
        
        score = data.get("abuseConfidenceScore", 0)
        if score >= 75:
            risk_level = "critical"
        elif score >= 50:
            risk_level = "high"
        elif score >= 25:
            risk_level = "medium"
        elif score > 0:
            risk_level = "low"
        else:
            risk_level = "clean"
        
        return cls(
            ip_address=data.get("ipAddress", ""),
            is_public=data.get("isPublic", True),
            abuse_confidence_score=score,
            country_code=data.get("countryCode"),
            isp=data.get("isp"),
            domain=data.get("domain"),
            total_reports=data.get("totalReports", 0),
            last_reported_at=last_reported,
            is_whitelisted=data.get("isWhitelisted", False),
            is_tor=data.get("isTor", False),
            usage_type=data.get("usageType"),
            risk_level=risk_level,
        )
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "ip_address": self.ip_address,
            "is_public": self.is_public,
            "abuse_confidence_score": self.abuse_confidence_score,
            "country_code": self.country_code,
            "isp": self.isp,
            "domain": self.domain,
            "total_reports": self.total_reports,
            "last_reported_at": self.last_reported_at.isoformat() if self.last_reported_at else None,
            "is_whitelisted": self.is_whitelisted,
            "is_tor": self.is_tor,
            "usage_type": self.usage_type,
            "risk_level": self.risk_level,
        }


class AbuseIPDBService:
    BASE_URL = "https://api.abuseipdb.com/api/v2"
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key or getattr(settings, "ABUSEIPDB_API_KEY", None)
        self._client: Optional[httpx.AsyncClient] = None
    
    @property
    def is_configured(self) -> bool:
        return bool(self.api_key)
    
    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.BASE_URL,
                headers={
                    "Key": self.api_key or "",
                    "Accept": "application/json",
                },
                timeout=30.0,
            )
        return self._client
    
    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None
    
    async def check_ip(
        self,
        ip_address: str,
        max_age_in_days: int = 90,
        verbose: bool = True,
        raise_on_error: bool = False,
        max_retries: int = 2,
    ) -> Optional[IPReputationResult]:
        if not self.is_configured:
            logger.warning("AbuseIPDB API key not configured")
            if raise_on_error:
                raise AbuseIPDBError("API key not configured")
            return None
        
        last_error: Optional[Exception] = None
        
        for attempt in range(max_retries + 1):
            try:
                client = await self._get_client()
                response = await client.get(
                    "/check",
                    params={
                        "ipAddress": ip_address,
                        "maxAgeInDays": max_age_in_days,
                        "verbose": str(verbose).lower(),
                    },
                )
                
                if response.status_code == 200:
                    data = response.json()
                    if "data" in data:
                        return IPReputationResult.from_api_response(data["data"])
                    return None
                    
                elif response.status_code == 429:
                    retry_after = response.headers.get("Retry-After")
                    retry_seconds = int(retry_after) if retry_after and retry_after.isdigit() else None
                    logger.warning(f"AbuseIPDB rate limit exceeded. Retry after: {retry_seconds}s")
                    if raise_on_error:
                        raise AbuseIPDBRateLimitExceeded(retry_seconds)
                    return None
                    
                elif response.status_code == 401:
                    logger.error("AbuseIPDB API key is invalid")
                    if raise_on_error:
                        raise InvalidAPIKey("Invalid API key")
                    return None
                    
                elif response.status_code >= 500:
                    logger.warning(f"AbuseIPDB server error ({response.status_code}), attempt {attempt + 1}/{max_retries + 1}")
                    last_error = APIError(response.status_code, "Server error")
                    if attempt < max_retries:
                        await asyncio.sleep(2 ** attempt)
                        continue
                    if raise_on_error:
                        raise last_error
                    return None
                    
                else:
                    logger.error(f"AbuseIPDB API error: {response.status_code}")
                    if raise_on_error:
                        raise APIError(response.status_code, f"Unexpected status code")
                    return None
                    
            except httpx.TimeoutException as e:
                logger.warning(f"AbuseIPDB request timeout, attempt {attempt + 1}/{max_retries + 1}")
                last_error = e
                if attempt < max_retries:
                    await asyncio.sleep(2 ** attempt)
                    continue
                if raise_on_error:
                    raise AbuseIPDBError(f"Request timeout after {max_retries + 1} attempts")
                return None
                
            except httpx.HTTPError as e:
                logger.error(f"AbuseIPDB request failed: {e}")
                if raise_on_error:
                    raise AbuseIPDBError(str(e))
                return None
        
        return None
    
    async def check_bulk(
        self,
        ip_addresses: list[str],
        max_age_in_days: int = 90,
    ) -> list[IPReputationResult]:
        if not self.is_configured:
            logger.warning("AbuseIPDB API key not configured")
            return []
        
        if len(ip_addresses) > 100:
            ip_addresses = ip_addresses[:100]
            logger.warning("Truncating bulk check to 100 IPs (API limit)")
        
        results = []
        tasks = [self.check_ip(ip, max_age_in_days, verbose=False) for ip in ip_addresses]
        
        for result in await asyncio.gather(*tasks, return_exceptions=True):
            if isinstance(result, IPReputationResult):
                results.append(result)
        
        return results
    
    async def report_ip(
        self,
        ip_address: str,
        categories: list[int],
        comment: Optional[str] = None,
    ) -> bool:
        if not self.is_configured:
            logger.warning("AbuseIPDB API key not configured")
            return False
        
        try:
            client = await self._get_client()
            data = {
                "ip": ip_address,
                "categories": ",".join(str(c) for c in categories),
            }
            if comment:
                data["comment"] = comment[:1024]
            
            response = await client.post("/report", data=data)
            
            if response.status_code == 200:
                logger.info(f"Successfully reported IP {ip_address} to AbuseIPDB")
                return True
            else:
                logger.error(f"Failed to report IP: {response.status_code}")
                return False
        except httpx.HTTPError as e:
            logger.error(f"AbuseIPDB report failed: {e}")
            return False
    
    async def get_blacklist(
        self,
        confidence_minimum: int = 90,
        limit: int = 1000,
    ) -> list[str]:
        if not self.is_configured:
            logger.warning("AbuseIPDB API key not configured")
            return []
        
        try:
            client = await self._get_client()
            response = await client.get(
                "/blacklist",
                params={
                    "confidenceMinimum": confidence_minimum,
                    "limit": min(limit, 10000),
                },
            )
            
            if response.status_code == 200:
                data = response.json()
                return [item["ipAddress"] for item in data.get("data", [])]
            else:
                logger.error(f"Failed to get blacklist: {response.status_code}")
                return []
        except httpx.HTTPError as e:
            logger.error(f"AbuseIPDB blacklist request failed: {e}")
            return []


abuseipdb_service = AbuseIPDBService()


ABUSEIPDB_CATEGORIES = {
    1: "DNS Compromise",
    2: "DNS Poisoning",
    3: "Fraud Orders",
    4: "DDoS Attack",
    5: "FTP Brute-Force",
    6: "Ping of Death",
    7: "Phishing",
    8: "Fraud VoIP",
    9: "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH",
    23: "IoT Targeted",
}
