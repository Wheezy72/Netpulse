from __future__ import annotations

import asyncio
from typing import Any

from app.services.routers import RouterDriver


class NetmikoRouterDriver(RouterDriver):
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        device_type: str,
        port: int | None = None,
        enable_secret: str | None = None,
    ) -> None:
        super().__init__(
            host=host,
            username=username,
            password=password,
            port=port,
            device_type=device_type,
            enable_secret=enable_secret,
        )
        self.device_type = device_type
        self.enable_secret = enable_secret
        self.port = port or 22

        # Kenya-optimised defaults: higher delay + robust timeouts for higher
        # latency and banner delays.
        self.global_delay_factor = 2
        self.banner_timeout = 45
        self.auth_timeout = 45
        self.conn_timeout = 45
        self.read_timeout = 60

    def _connect(self):
        from netmiko import ConnectHandler

        params: dict[str, Any] = {
            "device_type": self.device_type,
            "host": self.host,
            "username": self.username,
            "password": self.password,
            "port": self.port,
            "global_delay_factor": self.global_delay_factor,
            "banner_timeout": self.banner_timeout,
            "auth_timeout": self.auth_timeout,
            "conn_timeout": self.conn_timeout,
            "read_timeout": self.read_timeout,
        }
        if self.enable_secret:
            params["secret"] = self.enable_secret

        conn = ConnectHandler(**params)

        if self.enable_secret:
            conn.enable()

        for cmd in [
            "terminal length 0",
            "terminal pager 0",
            "screen-length 0 temporary",
            "screen-length disable",
            "set cli screen-length 0",
            "no page",
        ]:
            try:
                conn.send_command(cmd)
                break
            except Exception:
                continue

        return conn

    def _run_command(self, command: str) -> str:
        conn = self._connect()
        try:
            return conn.send_command(command)
        finally:
            conn.disconnect()

    async def get_interfaces(self) -> list[dict[str, Any]]:
        commands = [
            "show ip interface brief",
            "display ip interface brief",
            "show interfaces terse",
            "show interfaces",
        ]

        def _run() -> list[dict[str, Any]]:
            for cmd in commands:
                try:
                    output = self._run_command(cmd)
                    return [{"command": cmd, "output": output}]
                except Exception:
                    continue
            raise RuntimeError("Unable to fetch interfaces using known commands")

        return await asyncio.to_thread(_run)

    async def get_arp_table(self) -> list[dict[str, Any]]:
        commands = [
            "show ip arp",
            "display arp",
            "show arp",
        ]

        def _run() -> list[dict[str, Any]]:
            for cmd in commands:
                try:
                    output = self._run_command(cmd)
                    return [{"command": cmd, "output": output}]
                except Exception:
                    continue
            raise RuntimeError("Unable to fetch ARP table using known commands")

        return await asyncio.to_thread(_run)

    async def get_config(self) -> str:
        commands = []
        device_lower = (self.device_type or "").lower()

        if "mikrotik" in device_lower or "routeros" in device_lower:
            commands = ["/export"]
        elif "juniper" in device_lower or device_lower.startswith("juniper"):
            commands = ["show configuration"]
        elif "huawei" in device_lower or "h3c" in device_lower:
            commands = ["display current-configuration"]
        else:
            commands = ["show running-config", "show config"]

        def _run() -> str:
            last_exc: Exception | None = None
            for cmd in commands:
                try:
                    return self._run_command(cmd)
                except Exception as exc:
                    last_exc = exc
                    continue
            if last_exc:
                raise last_exc
            raise RuntimeError("Unable to fetch config")

        return await asyncio.to_thread(_run)
