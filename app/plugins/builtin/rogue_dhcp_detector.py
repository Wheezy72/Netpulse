from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from datetime import datetime
from typing import Any, Dict, Optional, Set

from scapy.all import BOOTP, DHCP, Ether, IP, UDP, sniff  # type: ignore[import-untyped]

from app.core.config import settings
from app.db.session import async_session_factory
from app.models.syslog_event import SyslogEvent

logger = logging.getLogger(__name__)

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", re.IGNORECASE)
_DHCP_TYPE_MAP = {
    1: "discover",
    2: "offer",
    3: "request",
    4: "decline",
    5: "ack",
    6: "nak",
    7: "release",
    8: "inform",
}


def _normalize_mac(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("MAC address must be a string")
    mac = value.strip().lower()
    if not _MAC_RE.match(mac):
        raise ValueError(f"Invalid MAC address: {value!r}")
    return mac


def _parse_mac_allowlist(value: Any) -> Set[str]:
    if value is None:
        return set()

    items: list[str]
    if isinstance(value, str):
        raw = value.strip()
        if not raw:
            return set()
        items = [p for p in re.split(r"[\s,]+", raw) if p]
    elif isinstance(value, list):
        items = value
    else:
        raise ValueError("allowed_dhcp_server_macs must be a list[str] or a comma-separated string")

    normalized = {_normalize_mac(item) for item in items}
    if len(normalized) > 256:
        raise ValueError("allowed_dhcp_server_macs is unreasonably large")
    return normalized


def _parse_duration_seconds(value: Any, default: int = 10) -> int:
    if value is None:
        return default
    if isinstance(value, bool):
        raise ValueError("duration_seconds must be an integer")
    if isinstance(value, str):
        if not value.strip():
            return default
        value = int(value)
    if not isinstance(value, int):
        raise ValueError("duration_seconds must be an integer")
    if value < 1 or value > 300:
        raise ValueError("duration_seconds must be between 1 and 300")
    return value


def _parse_iface(value: Any) -> Optional[str]:
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError("interface must be a string")
    iface = value.strip()
    if not iface:
        return None
    if len(iface) > 64:
        raise ValueError("interface name is too long")
    return iface


def _coerce_dhcp_message_type(value: Any) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        for k, v in _DHCP_TYPE_MAP.items():
            if v == lowered:
                return k
    return None


def _extract_dhcp_message_type(pkt) -> Optional[int]:
    options = getattr(pkt[DHCP], "options", None)
    if not isinstance(options, list):
        return None

    for opt in options:
        if not isinstance(opt, tuple) or len(opt) < 2:
            continue
        if opt[0] == "message-type":
            return _coerce_dhcp_message_type(opt[1])
    return None


def _extract_server_identifier(pkt) -> Optional[str]:
    options = getattr(pkt[DHCP], "options", None)
    if not isinstance(options, list):
        return None

    for opt in options:
        if not isinstance(opt, tuple) or len(opt) < 2:
            continue
        if opt[0] == "server_id" and isinstance(opt[1], str):
            try:
                return str(ipaddress.ip_address(opt[1]))
            except ValueError:
                return None
    return None


def _format_chaddr(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, bytes) and len(value) >= 6:
        return ":".join(f"{b:02x}" for b in value[:6])
    if isinstance(value, str):
        try:
            return _normalize_mac(value)
        except ValueError:
            return None
    return None


def _persist_alerts_to_db(alerts: list[dict[str, Any]]) -> None:
    """Persist rogue DHCP alerts to the SyslogEvent table (best-effort).

    This plugin runs in-process; we persist using the shared async_session_factory.
    If we're currently on an event loop (common inside FastAPI), we schedule the
    write as a background task.
    """

    if not alerts:
        return

    async def _persist() -> None:
        try:
            async with async_session_factory() as session:
                for alert in alerts:
                    session.add(
                        SyslogEvent(
                            timestamp=alert["timestamp"],
                            source_ip=alert.get("server_ip") or "0.0.0.0",
                            facility="dhcp",
                            severity="High",
                            hostname=alert.get("server_mac"),
                            message=alert.get("message") or "Rogue DHCP server detected",
                        )
                    )
                await session.commit()
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to persist rogue DHCP alerts: %s", exc)

    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        asyncio.run(_persist())
        return

    loop.create_task(_persist())


class RogueDhcpDetector:
    name = "Rogue DHCP Detector"
    description = "Detects unauthorized DHCP servers by passively sniffing DHCP OFFER/ACK packets"
    version = "1.0.0"
    category = "detector"

    def __init__(self):
        self._allowed_server_macs_raw: Any = None
        self._allowed_server_macs: Set[str] = set()

    def initialize(self, config: Dict[str, Any]) -> None:
        self._allowed_server_macs_raw = config.get("allowed_dhcp_server_macs")

    def execute(self, context: Dict[str, Any]) -> Dict[str, Any]:
        try:
            iface = _parse_iface(context.get("interface") or context.get("iface"))
            duration_seconds = _parse_duration_seconds(
                context.get("duration_seconds")
                if "duration_seconds" in context
                else context.get("duration"),
                default=10,
            )

            self._allowed_server_macs = _parse_mac_allowlist(
                self._allowed_server_macs_raw
                if self._allowed_server_macs_raw is not None
                else settings.allowed_dhcp_server_macs
            )

            if not self._allowed_server_macs:
                return {
                    "status": "error",
                    "message": "No allowlisted DHCP server MACs configured. Set ALLOWED_DHCP_SERVER_MACS or pass allowed_dhcp_server_macs.",
                }

            alerts: list[dict[str, Any]] = []
            seen: set[tuple[str, int, str]] = set()
            packets_seen = 0
            offers_seen = 0
            acks_seen = 0

            def _handler(pkt) -> None:
                nonlocal packets_seen, offers_seen, acks_seen

                packets_seen += 1

                if not pkt.haslayer(Ether) or not pkt.haslayer(UDP) or not pkt.haslayer(DHCP) or not pkt.haslayer(BOOTP):
                    return

                udp = pkt[UDP]
                if getattr(udp, "sport", None) != 67:
                    return

                msg_type = _extract_dhcp_message_type(pkt)
                if msg_type not in (2, 5):
                    return

                if msg_type == 2:
                    offers_seen += 1
                else:
                    acks_seen += 1

                server_mac = str(pkt[Ether].src or "").lower()
                if not server_mac:
                    return

                if server_mac in self._allowed_server_macs:
                    return

                server_ip = _extract_server_identifier(pkt)
                if not server_ip and pkt.haslayer(IP):
                    src_ip = getattr(pkt[IP], "src", None)
                    if isinstance(src_ip, str):
                        try:
                            server_ip = str(ipaddress.ip_address(src_ip))
                        except ValueError:
                            server_ip = None
                if not server_ip:
                    siaddr = getattr(pkt[BOOTP], "siaddr", None)
                    if isinstance(siaddr, str):
                        try:
                            server_ip = str(ipaddress.ip_address(siaddr))
                        except ValueError:
                            server_ip = None

                offered_ip = getattr(pkt[BOOTP], "yiaddr", None)
                if isinstance(offered_ip, str):
                    try:
                        offered_ip = str(ipaddress.ip_address(offered_ip))
                    except ValueError:
                        offered_ip = None
                else:
                    offered_ip = None

                client_mac = _format_chaddr(getattr(pkt[BOOTP], "chaddr", None))
                now = datetime.utcnow()

                key = (server_mac, msg_type, offered_ip or "")
                if key in seen:
                    return
                seen.add(key)

                msg_name = _DHCP_TYPE_MAP.get(msg_type, str(msg_type)).upper()
                message = (
                    f"Rogue DHCP server detected: MAC={server_mac} sent DHCP {msg_name}"
                    + (f" server_id={server_ip}" if server_ip else "")
                    + (f" offered_ip={offered_ip}" if offered_ip else "")
                    + (f" client_mac={client_mac}" if client_mac else "")
                )

                alert = {
                    "type": "rogue_dhcp",
                    "severity": "high",
                    "server_mac": server_mac,
                    "server_ip": server_ip or "0.0.0.0",
                    "dhcp_message_type": msg_name,
                    "offered_ip": offered_ip,
                    "client_mac": client_mac,
                    "message": message,
                    "timestamp": now,
                }
                alerts.append(alert)

            sniff(
                iface=iface,
                filter="udp port 67 or 68",
                prn=_handler,
                store=False,
                timeout=duration_seconds,
            )

            _persist_alerts_to_db(alerts)

            return {
                "status": "ok",
                "duration_seconds": duration_seconds,
                "interface": iface,
                "packets_seen": packets_seen,
                "offers_seen": offers_seen,
                "acks_seen": acks_seen,
                "allowed_server_macs": sorted(self._allowed_server_macs),
                "alerts": [
                    {
                        **a,
                        "timestamp": a["timestamp"].isoformat() + "Z",
                    }
                    for a in alerts
                ],
            }
        except Exception as e:
            return {"status": "error", "message": str(e)}

    def cleanup(self) -> None:
        self._allowed_server_macs.clear()
