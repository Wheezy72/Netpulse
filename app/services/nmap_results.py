"""Turn nmap's plain-text output into structured findings.

Scans stream raw text to an artifact file and to the WebSocket console. That is
fine while you are watching, but it is useless the moment the page closes: the
job row only ever carried an exit code, so the Toolbox could show that a scan
finished and nothing about what it found.

``parse_nmap_text`` reads the artifact back into hosts, ports and services so the
result summary can be stored on the job and rendered later from
``GET /nmap/history``.
"""
from __future__ import annotations

import re
from typing import Any

MAX_HOSTS = 512
MAX_PORTS_PER_HOST = 256

_REPORT = re.compile(r"^Nmap scan report for (.+)$")
_UP = re.compile(r"^Host is up(?: \(([0-9.]+)s latency\))?")
_DOWN = re.compile(r"^Host is (?:down|seems down)")
_PORT = re.compile(
    r"^(?P<port>\d{1,5})/(?P<proto>tcp|udp|sctp)\s+"
    r"(?P<state>[a-z|]+)\s+"
    r"(?P<service>\S*)"
    r"(?:\s+(?P<version>.+))?$"
)
_MAC = re.compile(r"^MAC Address: ([0-9A-Fa-f:]{17})(?: \((.+)\))?")
_OS = re.compile(r"^(?:OS details|Running|Aggressive OS guesses): (.+)$")
_DONE = re.compile(
    r"Nmap done.*?(\d+) IP address(?:es)? \((\d+) hosts? up\) scanned in ([\d.]+) seconds"
)

# Service names nmap prints when it recognises the port but not the daemon.
_NO_VERSION = {"unknown", "tcpwrapped", ""}


def _split_report(subject: str) -> tuple[str, str | None]:
    """``"host.example (10.0.0.5)"`` -> ``("10.0.0.5", "host.example")``."""
    subject = subject.strip()
    match = re.match(r"^(?P<name>.+?) \((?P<addr>[^)\s]+)\)$", subject)
    if match:
        return match.group("addr"), match.group("name").strip()
    return subject, None


def parse_nmap_text(text: str) -> dict[str, Any]:
    """Parse nmap's human-readable output.

    Never raises: an unparseable artifact yields zero hosts plus whatever the
    ``Nmap done`` line revealed, which is still more than an exit code.
    """
    hosts: list[dict[str, Any]] = []
    current: dict[str, Any] | None = None
    hosts_total: int | None = None
    hosts_up: int | None = None
    scan_seconds: float | None = None

    def _close() -> None:
        nonlocal current
        if current is not None:
            current["open_ports"] = sum(1 for p in current["ports"] if p["state"] == "open")
            hosts.append(current)
            current = None

    for raw_line in (text or "").splitlines():
        line = raw_line.rstrip()
        if not line:
            continue

        report = _REPORT.match(line)
        if report:
            _close()
            address, hostname = _split_report(report.group(1))
            current = {
                "address": address,
                "hostname": hostname,
                "state": "unknown",
                "latency_ms": None,
                "mac_address": None,
                "vendor": None,
                "os": None,
                "ports": [],
            }
            continue

        if current is None:
            done = _DONE.search(line)
            if done:
                hosts_total = int(done.group(1))
                hosts_up = int(done.group(2))
                scan_seconds = float(done.group(3))
            continue

        up = _UP.match(line)
        if up:
            current["state"] = "up"
            if up.group(1):
                try:
                    current["latency_ms"] = round(float(up.group(1)) * 1000, 2)
                except ValueError:
                    pass
            continue

        if _DOWN.match(line):
            current["state"] = "down"
            continue

        if line.startswith("MAC Address:"):
            mac = _MAC.match(line)
            if mac:
                current["mac_address"] = mac.group(1).upper()
                current["vendor"] = mac.group(2)
            continue

        os_match = _OS.match(line)
        if os_match:
            current["os"] = os_match.group(1).strip()
            continue

        port = _PORT.match(line)
        if port and len(current["ports"]) < MAX_PORTS_PER_HOST:
            service = port.group("service") or ""
            version = (port.group("version") or "").strip()
            # "unknown" carries no information; drop it so the UI shows the
            # port and its state without an empty column.
            if service in _NO_VERSION:
                service = ""
            if version in _NO_VERSION:
                version = ""
            current["ports"].append(
                {
                    "port": int(port.group("port")),
                    "protocol": port.group("proto"),
                    "state": port.group("state"),
                    "service": service,
                    "version": version,
                }
            )
            continue

        done = _DONE.search(line)
        if done:
            hosts_total = int(done.group(1))
            hosts_up = int(done.group(2))
            scan_seconds = float(done.group(3))

    _close()

    if hosts_total is None:
        hosts_total = len(hosts)
    if hosts_up is None:
        hosts_up = sum(1 for h in hosts if h["state"] == "up")

    open_ports = sum(h["open_ports"] for h in hosts)
    # Only hosts that answered are worth keeping: a /24 ping sweep would
    # otherwise store 253 "down" rows nobody wants to read.
    interesting = [h for h in hosts if h["state"] == "up" or h["ports"]]
    interesting.sort(key=lambda h: (-h["open_ports"], h["address"]))

    return {
        "hosts": interesting[:MAX_HOSTS],
        "hosts_up": hosts_up,
        "hosts_total": hosts_total,
        "open_ports": open_ports,
        "scan_seconds": scan_seconds,
    }
