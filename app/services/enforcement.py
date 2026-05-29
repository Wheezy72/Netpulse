from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from typing import Any

from app.core.config import settings
from app.services.splunk_service import get_splunk_service

logger = logging.getLogger(__name__)

_PORT_PATTERN = re.compile(r"^[A-Za-z0-9/_:-]{1,64}$")


def _validate_port_name(port: str) -> bool:
    return bool(port and _PORT_PATTERN.fullmatch(port))


def _validate_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host))


async def isolate_switch_port(
    port: str,
    *,
    reason: str | None = None,
    switch_host: str | None = None,
    username: str | None = None,
    password: str | None = None,
    device_type: str | None = None,
    enable_secret: str | None = None,
    ssh_port: int | None = None,
) -> dict[str, Any]:
    host = switch_host or settings.switch_mgmt_host
    user = username or settings.switch_mgmt_user
    secret = password or settings.switch_mgmt_password
    dev_type = device_type or settings.switch_mgmt_device_type
    enable = enable_secret or settings.switch_mgmt_enable_secret
    port_num = ssh_port or settings.switch_mgmt_port

    if not host or not user or not secret:
        raise RuntimeError("Switch management credentials are not configured")
    if not _validate_host(host):
        raise ValueError("Invalid switch host")
    if not _validate_port_name(port):
        raise ValueError("Invalid switch port name")

    def _shutdown() -> dict[str, Any]:
        from netmiko import ConnectHandler  # type: ignore[import-untyped]

        connection = ConnectHandler(
            device_type=dev_type,
            host=host,
            username=user,
            password=secret,
            secret=enable or secret,
            port=port_num,
            fast_cli=True,
        )
        try:
            if enable:
                connection.enable()
            output = connection.send_config_set([f"interface {port}", "shutdown"])
            return {"host": host, "port": port, "output": output}
        finally:
            connection.disconnect()

    result = await asyncio.to_thread(_shutdown)
    await get_splunk_service().emit(
        {
            "type": "containment.port_isolated",
            "severity": "critical",
            "host": host,
            "port": port,
            "reason": reason,
            "result": result,
        }
    )
    logger.warning("Isolated switch port %s on %s", port, host)
    return result
