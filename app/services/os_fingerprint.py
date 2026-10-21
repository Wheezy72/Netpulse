"""Operating-system identification for a discovered host.

There is no single foolproof passive signal for "this phone runs Android".
Everything available to a LAN observer is evidence rather than proof:

* **nmap OS detection** compares TCP/IP stack fingerprints (SYN window sizes,
  options, TTL, ICMP replies) against a shipped database. It is the strongest
  signal available on a LAN and reports an accuracy percentage per match.
  It needs raw sockets, so it needs admin/root (or Npcap on Windows).
* **Hostnames** are self-reported. `DESKTOP-8FJ2` is Windows, `android-abc123`
  is Android, `Bobss-MacBook-Pro` is macOS. Reliable when present.
* **Open ports**. 139/445 only ever come from Windows; 62078 (lockdownd) and
  5555 (adb) are Apple and Android respectively; a host with 22 open and no
  445 is very likely Unix-like.
* **MAC vendor** is a weak hint on its own — and useless when the device
  randomises its MAC, which phones do by default — but it is decisive for
  Apple and Microsoft hardware.

Every answer carries a confidence so callers can show "Android (likely)" as
distinctly from a fingerprint nmap actually matched.
"""
from __future__ import annotations

import logging
import shutil
from typing import Any, Iterable, Optional, Tuple

logger = logging.getLogger("netpulse.os_fingerprint")

# (operating system, confidence) — confidence is "high" | "medium" | "low".
OSGuess = Tuple[Optional[str], Optional[str]]

# Ports that are effectively signatures of one platform.
PORT_WINDOWS = {139, 445}
PORT_APPLE_LOCKDOWN = {62078}
PORT_MDNS = {5353, 5350}
PORT_ADB = {5555}

# Vendor families. Only used when the MAC is not randomly generated.
ANDROID_VENDORS = {
    "samsung",
    "lg electronics",
    "xiaomi",
    "huawei",
    "google",
    "oneplus",
    "oppo",
    "vivo",
    "realme",
    "motorola",
    "honor",
    "tecno",
    "infinix",
}
APPLE_VENDORS = {"apple"}
MICROSOFT_VENDORS = {"microsoft"}
LINUX_VENDORS = {"raspberry pi foundation", "raspberry pi"}


def _clean(value: Optional[str]) -> str:
    return (value or "").strip().lower()


def infer_os_from_host(
    *,
    hostname: Optional[str] = None,
    vendor: Optional[str] = None,
    open_ports: Iterable[int] = (),
    mac_randomised: bool = False,
) -> OSGuess:
    """Infer ``(os, confidence)`` from signals other than nmap's fingerprint.

    Pure and synchronous so it can be unit tested and reused by the discovery
    path, the deep-scan path and any future passive collector.
    """
    host = _clean(hostname)
    vend = _clean(vendor)
    ports = {int(p) for p in open_ports if p}

    # 1. Hostname: self-reported and specific.
    if host:
        if "android" in host or host.startswith(("sm-", "pixel-")):
            return "Android", "high"
        if any(token in host for token in ("iphone", "ipad", "ipod")):
            return "iOS", "high"
        if any(token in host for token in ("macbook", "imac", "mac mini", "macmini", "mac-")):
            return "macOS", "high"
        if host.startswith(("desktop-", "laptop-", "win-", "ms surface")) or "-pc" in host:
            return "Windows", "high"
        if any(token in host for token in ("ubuntu", "debian", "fedora", "arch", "raspberrypi", "kali")):
            return "Linux", "high"

    # 2. Ports: a platform's own services.
    if PORT_WINDOWS & ports:
        return "Windows", "high"
    if PORT_ADB & ports:
        return "Android", "high"
    if PORT_APPLE_LOCKDOWN & ports:
        return "iOS", "high"
    if ports and 22 in ports and not (PORT_WINDOWS & ports):
        # SSH with no Windows file sharing: a Unix-like host. Distinguishing
        # Linux from macOS needs nmap's fingerprint.
        return "Linux", "medium"

    # 3. Vendor — only trustworthy on a real (non-randomised) MAC.
    if mac_randomised:
        return None, None
    if vend in MICROSOFT_VENDORS:
        return "Windows", "medium"
    if vend in APPLE_VENDORS:
        # An Apple OUI covers both desktop and mobile; mDNS tips it either way.
        return ("macOS", "medium") if PORT_MDNS & ports else ("macOS/iOS", "low")
    if vend in ANDROID_VENDORS:
        return "Android", "medium"
    if vend in LINUX_VENDORS:
        return "Linux", "high"

    return None, None


def nmap_os_detect(ip_address: str, *, timeout_seconds: int = 60) -> OSGuess:
    """Ask nmap to fingerprint the host's IP stack.

    Runs blocking nmap (`-O --osscan-guess`); call it from a worker thread.
    Returns ``(None, None)`` when nmap is missing, unprivileged, or unmatched.
    """
    if shutil.which("nmap") is None:
        return None, None

    try:
        import nmap  # python-nmap
    except Exception:  # noqa: BLE001 - optional dependency
        return None, None

    try:
        scanner = nmap.PortScanner()
        # -Pn: assume the host is up, since many firewalls drop ICMP echo.
        scanner.scan(
            hosts=ip_address,
            arguments=f"-O --osscan-guess -Pn --host-timeout {int(timeout_seconds)}s",
        )
    except Exception as exc:  # noqa: BLE001 - fingerprinting is best-effort
        logger.info("nmap OS detection failed for %s: %s", ip_address, exc)
        return None, None

    try:
        entry: Any = scanner[ip_address]
        matches = list(entry.get("osmatch") or [])
    except Exception:  # noqa: BLE001 - host absent from the scan result
        return None, None

    if not matches:
        return None, None

    # nmap sorts by accuracy; take the best and carry its accuracy through as
    # confidence so an 89% match is not shown like a certainty.
    best = max(matches, key=lambda m: int(m.get("accuracy") or 0))
    label = (best.get("name") or "").strip()
    if not label:
        return None, None

    accuracy = int(best.get("accuracy") or 0)
    confidence = "high" if accuracy >= 95 else "medium" if accuracy >= 80 else "low"
    return label, confidence


def resolve_device_os(
    *,
    ip_address: str,
    hostname: Optional[str] = None,
    vendor: Optional[str] = None,
    open_ports: Iterable[int] = (),
    mac_randomised: bool = False,
    prefer_nmap: bool = True,
) -> OSGuess:
    """Best available OS label for one host, nmap first when it is usable."""
    if prefer_nmap:
        label, confidence = nmap_os_detect(ip_address)
        if label:
            return label, confidence
    return infer_os_from_host(
        hostname=hostname,
        vendor=vendor,
        open_ports=open_ports,
        mac_randomised=mac_randomised,
    )
