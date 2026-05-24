from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

import httpx

from app.core.config import settings

logger = logging.getLogger(__name__)


class SplunkService:
    def __init__(self) -> None:
        self.enabled = settings.enable_splunk_hec
        self.url = settings.splunk_hec_url
        self.token = settings.splunk_hec_token
        self.index = settings.splunk_hec_index
        self.source = settings.splunk_hec_source
        self.sourcetype = settings.splunk_hec_sourcetype
        self.verify_ssl = settings.splunk_hec_verify_ssl

    def _ready(self) -> bool:
        return bool(self.enabled and self.url and self.token)

    async def emit(self, event: dict[str, Any]) -> None:
        if not self._ready():
            return

        payload = {
            "time": datetime.now(timezone.utc).timestamp(),
            "host": settings.app_name,
            "source": self.source,
            "sourcetype": self.sourcetype,
            "index": self.index,
            "event": event,
        }

        headers = {"Authorization": f"Splunk {self.token}"}
        try:
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=5.0) as client:
                response = await client.post(self.url, json=payload, headers=headers)
                response.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            logger.debug("Splunk HEC emit failed: %s", exc)


_SPLUNK_SERVICE = SplunkService()


def get_splunk_service() -> SplunkService:
    return _SPLUNK_SERVICE
