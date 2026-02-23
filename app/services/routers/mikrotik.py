from __future__ import annotations

import asyncio
from typing import Any, Callable, TypeVar

from app.services.routers import RouterDriver


T = TypeVar("T")


class MikroTikRouterDriver(RouterDriver):
    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        port: int | None = None,
    ) -> None:
        super().__init__(host=host, username=username, password=password, port=port)
        self.port = port or 8728

    def _with_api(self, fn: Callable[[Any], T]) -> T:
        import routeros_api

        pool = routeros_api.RouterOsApiPool(
            self.host,
            username=self.username,
            password=self.password,
            port=self.port,
            plaintext_login=True,
        )
        api = pool.get_api()
        try:
            return fn(api)
        finally:
            pool.disconnect()

    async def get_interfaces(self) -> list[dict[str, Any]]:
        def _run(api: Any) -> list[dict[str, Any]]:
            return list(api.get_resource("/interface").get())

        return await asyncio.to_thread(lambda: self._with_api(_run))

    async def get_arp_table(self) -> list[dict[str, Any]]:
        def _run(api: Any) -> list[dict[str, Any]]:
            return list(api.get_resource("/ip/arp").get())

        return await asyncio.to_thread(lambda: self._with_api(_run))

    async def get_config(self) -> str:
        def _run(api: Any) -> str:
            response = api.get_resource("/").call("export")

            # routeros_api responses vary depending on the command. For commands
            # that return a single string, it is usually in done_message['ret'].
            done_message = getattr(response, "done_message", None)
            if isinstance(done_message, dict) and "ret" in done_message:
                ret = done_message.get("ret")
                if isinstance(ret, (bytes, bytearray)):
                    return ret.decode(errors="replace")
                return str(ret)

            if isinstance(response, list):
                lines: list[str] = []
                for item in response:
                    if isinstance(item, dict) and "ret" in item:
                        lines.append(str(item.get("ret")))
                    else:
                        lines.append(str(item))
                return "\n".join(lines)

            return str(response)

        return await asyncio.to_thread(lambda: self._with_api(_run))
