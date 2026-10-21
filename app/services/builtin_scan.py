"""Built-in TCP connect scanner.

Nmap is optional in this deployment. When it is absent, the console should
still be able to answer "what is on this host?" instead of failing with a 503,
so this module provides a small, dependency-free scan built on asyncio TCP
connects.

It deliberately stays conservative:

* Only TCP connect scans — no raw sockets, no SYN, no privilege requirement.
* A bounded number of targets (``MAX_HOSTS``) and ports (``MAX_PORTS``), so a
  mistyped ``/8`` cannot turn into an accidental stress test.
* Output is written in nmap's textual shape, which keeps the console readable
  and leaves room for a real nmap parser later.
"""
from __future__ import annotations

import asyncio
import ipaddress
import os
import shutil
import subprocess
import time
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence

MAX_HOSTS = 256
MAX_PORTS = 1024
CONNECT_TIMEOUT = 0.7
CONCURRENCY = 200

# The nmap "top 100" ports, plus a few common management ports. Good coverage
# for a LAN sweep without the cost of a full 65k-port walk.
TOP_PORTS: List[int] = [
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152,
    49153, 49154, 49155, 49156, 49157,
]

SERVICES = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 179: "bgp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 514: "shell", 515: "printer", 548: "afp", 554: "rtsp",
    587: "submission", 631: "ipp", 993: "imaps", 995: "pop3s", 1194: "openvpn",
    1433: "ms-sql-s", 1723: "pptp", 1883: "mqtt", 1900: "upnp", 2049: "nfs",
    3000: "http", 3306: "mysql", 3389: "ms-wbt-server", 5000: "upnp",
    5060: "sip", 5432: "postgresql", 5357: "wsdapi", 5900: "vnc", 6379: "redis",
    8000: "http", 8080: "http-proxy", 8081: "http", 8443: "https-alt",
    8888: "sun-answerbook", 9100: "jetdirect", 9999: "abyss", 27017: "mongodb",
}


@dataclass
class HostFinding:
    ip: str
    latency_ms: Optional[float] = None
    open_ports: List[int] = field(default_factory=list)


def engine_available() -> bool:
    return shutil.which("nmap") is not None


def parse_ports(command: str) -> tuple[bool, List[int]]:
    """Return ``(host_discovery_only, ports)`` for an nmap-style command.

    ``-sn`` means ping-sweep semantics. ``-p-`` would be a 65k walk, which the
    built-in engine caps at :data:`MAX_PORTS` and says so in the report.
    """
    tokens = command.split()
    if "-sn" in tokens:
        return True, []
    if "-p-" in tokens:
        return False, TOP_PORTS
    ports: List[int] = []
    for index, token in enumerate(tokens):
        value: Optional[str] = None
        if token == "-p" and index + 1 < len(tokens):
            value = tokens[index + 1]
        elif token.startswith("-p") and len(token) > 2:
            value = token[2:]
        if not value:
            continue
        for chunk in value.split(","):
            chunk = chunk.strip()
            if not chunk:
                continue
            if "-" in chunk:
                low, _, high = chunk.partition("-")
                if low.isdigit() and high.isdigit():
                    start, end = int(low), int(high)
                    if 0 < start <= end <= 65535:
                        ports.extend(range(start, min(end, start + MAX_PORTS) + 1))
            elif chunk.isdigit():
                port = int(chunk)
                if 0 < port <= 65535:
                    ports.append(port)
    if ports:
        return False, sorted(set(ports))[:MAX_PORTS]
    # -F (fast) or a bare command: nmap's fast set is the top 100.
    return False, TOP_PORTS


def _expand_targets(target: str) -> List[str]:
    try:
        if "/" in target:
            network = ipaddress.ip_network(target, strict=False)
            hosts = [str(ip) for ip in network.hosts()][:MAX_HOSTS]
            return hosts or [str(network.network_address)]
        return [str(ipaddress.ip_address(target))]
    except ValueError:
        # Hostname: resolve it (never pass it to a shell).
        import socket

        try:
            infos = socket.getaddrinfo(target, None)
        except OSError:
            return []
        addresses = []
        for info in infos:
            address = info[4][0]
            if address not in addresses:
                addresses.append(address)
        return addresses[:1]


async def _probe(ip: str, port: int, semaphore: asyncio.Semaphore) -> Optional[float]:
    async with semaphore:
        started = time.perf_counter()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=CONNECT_TIMEOUT
            )
        except (OSError, asyncio.TimeoutError):
            return None
        elapsed = (time.perf_counter() - started) * 1000
        writer.close()
        try:
            await writer.wait_closed()
        except OSError:
            pass
        return elapsed


def _ping_alive(ip: str) -> bool:
    """Host discovery without raw sockets: the OS ping binary."""
    ping = shutil.which("ping")
    if not ping:
        return False
    if os.name == "nt":
        argv: Sequence[str] = [ping, "-n", "1", "-w", "700", ip]
    else:
        argv = [ping, "-c", "1", "-W", "1", ip]
    try:
        completed = subprocess.run(
            argv,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=2,
            check=False,
        )
        return completed.returncode == 0
    except (OSError, subprocess.TimeoutExpired):
        return False


async def _scan_host(ip: str, ports: Iterable[int], semaphore: asyncio.Semaphore) -> HostFinding:
    port_list = list(ports)
    results = await asyncio.gather(*(_probe(ip, port, semaphore) for port in port_list))
    open_ports = [port for port, latency in zip(port_list, results) if latency is not None]
    latencies = [latency for latency in results if latency is not None]
    return HostFinding(
        ip=ip,
        latency_ms=min(latencies) if latencies else None,
        open_ports=open_ports,
    )


async def builtin_scan(target: str, command: str) -> tuple[str, dict]:
    """Run the fallback scan and return ``(human_output, result_summary)``."""
    host_discovery_only, ports = parse_ports(command)
    targets = _expand_targets(target)
    if not targets:
        return (
            f"Failed to resolve target: {target}\n",
            {"engine": "builtin", "error": "unresolved_target", "target": target},
        )

    semaphore = asyncio.Semaphore(CONCURRENCY)
    lines = [
        "Starting NetPulse scan (built-in engine — nmap is not installed)",
        f"Target: {target}",
        f"Hosts: {len(targets)} · Ports: {'discovery only' if host_discovery_only else len(ports)}",
        "=" * 60,
        "",
    ]

    findings: List[HostFinding] = []
    if host_discovery_only:
        alive_hosts: List[str] = []
        for ip in targets:
            alive = await asyncio.to_thread(_ping_alive, ip)
            if alive:
                alive_hosts.append(ip)
            lines.append(f"Nmap scan report for {ip}")
            lines.append("Host is up." if alive else "Host seems down.")
            lines.append("")
        summary = {
            "engine": "builtin",
            "host_discovery": True,
            "hosts": [{"ip": ip} for ip in alive_hosts],
            "up_count": len(alive_hosts),
        }
        return "\n".join(lines), summary

    for ip in targets:
        finding = await _scan_host(ip, ports, semaphore)
        findings.append(finding)
        lines.append(f"Nmap scan report for {ip}")
        if finding.open_ports:
            latency = f" ({finding.latency_ms:.2f}ms latency)" if finding.latency_ms else ""
            lines.append(f"Host is up{latency}.")
            lines.append("PORT      STATE  SERVICE")
            for port in finding.open_ports:
                service = SERVICES.get(port, "")
                lines.append(f"{port}/tcp  open   {service}")
        else:
            lines.append("Host is up (no open TCP ports found in the scanned set).")
        lines.append("")

    open_count = sum(len(f.open_ports) for f in findings)
    lines.append("=" * 60)
    lines.append(f"Scan complete: {len(findings)} host(s), {open_count} open port(s)")

    summary = {
        "engine": "builtin",
        "hosts": [
            {
                "ip": finding.ip,
                "open_ports": [
                    {"port": port, "service": SERVICES.get(port, "")}
                    for port in finding.open_ports
                ],
                "latency_ms": round(finding.latency_ms, 2) if finding.latency_ms else None,
            }
            for finding in findings
        ],
        "open_port_count": open_count,
    }
    return "\n".join(lines), summary
