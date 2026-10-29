"""Identify the NetPulse console machine by its own network interfaces.

A Windows box often holds two addresses on one LAN at once — Wi-Fi plus a USB
adapter such as the Archer T2U — so a sweep legitimately records the same
machine as two rows with two MAC addresses. That looks like a duplicate bug to
the operator. ``console_macs()`` returns the MACs that belong to this very
machine, so the devices API can flag those rows with ``is_self`` and the UI can
label them "This PC" instead.

The list is refreshed on a short TTL: USB adapters are plugged and unplugged
between sweeps, and a swapped Wi-Fi card changes the set too. Every failure
returns an empty set — mislabelling another device as this machine would be
worse than not labelling anything.
"""
from __future__ import annotations

import logging
import subprocess
import sys
import threading
import time

logger = logging.getLogger("netpulse.console_host")

_CACHE_TTL_SECONDS = 60.0
_lock = threading.Lock()
_cached: tuple[float, frozenset[str]] | None = None


def _normalize(raw: str | None) -> str | None:
    """``aa-bb-cc-dd-ee-ff`` / ``aa:bb:cc:dd:ee:ff`` → ``AABBCCDDEEFF``."""
    if not raw:
        return None
    compact = "".join(ch for ch in raw.upper() if ch in "0123456789ABCDEF")
    # All-zeroes and placeholder addresses identify nothing.
    if len(compact) == 12 and compact != "000000000000":
        return compact
    return None


def _macs_from_scapy() -> set[str]:
    """Working interfaces via scapy, which device discovery already uses."""
    from scapy.interfaces import get_working_ifaces  # noqa: SC - lazy import

    macs = set()
    for iface in get_working_ifaces():
        raw = getattr(iface, "mac", None)
        mac = _normalize(raw)
        if mac:
            macs.add(mac)
    return macs


def _macs_from_platform() -> set[str]:
    """Platform commands, for installs where scapy cannot enumerate."""
    macs: set[str] = set()

    if sys.platform.startswith("win"):
        output = subprocess.run(
            ["ipconfig", "/all"], capture_output=True, text=True, timeout=10, check=False
        ).stdout or ""
        for line in output.splitlines():
            if "Physical Address" in line and ":" in line:
                macs.add(_normalize(line.split(":")[-1]) or "")
    elif sys.platform.startswith("linux"):
        import glob

        for path in glob.glob("/sys/class/net/*/address"):
            try:
                with open(path) as handle:
                    macs.add(_normalize(handle.read().strip()) or "")
            except Exception:  # noqa: BLE001 - unreadable nic, keep going
                continue
            macs.discard("")
    macs.discard("")
    return macs


def _collect() -> frozenset[str]:
    try:
        macs = _macs_from_scapy()
    except Exception as exc:  # noqa: BLE001 - enumeration has several fallbacks
        logger.debug("scapy interface enumeration failed: %s", exc)
        macs = set()

    if not macs:
        try:
            macs = _macs_from_platform()
        except Exception as exc:  # noqa: BLE001 - an empty answer is acceptable
            logger.debug("platform MAC enumeration failed: %s", exc)
            macs = set()

    if not macs:
        logger.warning("Could not determine this machine's interface MACs; \"This PC\" labels will be absent.")
    return frozenset(macs)


def console_macs() -> frozenset[str]:
    """MAC addresses owned by the machine running the console (cached 60s)."""
    global _cached
    with _lock:
        if _cached is None or time.monotonic() - _cached[0] > _CACHE_TTL_SECONDS:
            _cached = (time.monotonic(), _collect())
        return _cached[1]
