from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class RouterDriver(ABC):
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int | None = None,
        **kwargs: Any,
    ) -> None:
        self.host = host
        self.username = username
        self.password = password
        self.port = port
        self.kwargs = kwargs

    @abstractmethod
    async def get_interfaces(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    async def get_arp_table(self) -> list[dict[str, Any]]:
        raise NotImplementedError

    @abstractmethod
    async def get_config(self) -> str:
        raise NotImplementedError


def create_router_driver(
    driver: str,
    *,
    host: str,
    username: str,
    password: str,
    port: int | None = None,
    device_type: str | None = None,
    enable_secret: str | None = None,
) -> RouterDriver:
    driver_key = (driver or "").lower().strip()

    if driver_key == "mikrotik":
        from app.services.routers.mikrotik import MikroTikRouterDriver

        return MikroTikRouterDriver(
            host=host,
            username=username,
            password=password,
            port=port,
        )

    if driver_key == "netmiko":
        from app.services.routers.netmiko_driver import NetmikoRouterDriver

        if not device_type:
            raise ValueError("device_type is required for netmiko driver")

        return NetmikoRouterDriver(
            host=host,
            username=username,
            password=password,
            port=port,
            device_type=device_type,
            enable_secret=enable_secret,
        )

    raise ValueError(f"Unsupported router driver: {driver}")
