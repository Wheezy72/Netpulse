"""Per-device deep scan: what is actually listening on a discovered host.

The discovery sweep (``app/services/device_discovery.py``) is intentionally
shallow — identity only, no ports. This module is the opt-in second step: given
a device the operator already knows about, it runs a targeted nmap
service/version scan against that single IP and records the listening ports.

Scope is deliberately narrow: ``-sV`` service detection and ``-Pn`` (the host
is known to be up, so skip the ping gate). No NSE script sweep, no
``--script=vuln``, nothing that turns a detail lookup into a noisy
vulnerability assessment.

Import discipline matches the discovery service: stdlib at module level, with
``nmap`` and SQLAlchemy imported inside the functions that need them, so the
parsing logic stays testable in the minimal CI environment.
"""
from __future__ import annotations

import asyncio
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

from app.services.scan_policy import is_restricted_target, validate_target

STATE_PORT_PROTOCOLS = ("tcp", "udp")
# Only ports a scan found something listening on are worth storing. nmap also
# reports "closed" and "filtered" for every port it probed, which would bury
# the interesting rows.
REPORTABLE_STATES = ("open", "open|filtered")


@dataclass(slots=True)
class PortObservation:
    """One listening port as reported by a deep scan."""

    port: int
    protocol: str = "tcp"
    state: Optional[str] = None
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None
    extra_info: Optional[str] = None
    banner: Optional[str] = None


# nmap's vuln NSE library prints a state line per host. "NOT VULNERABLE" also
# contains the word, so the positive pattern is anchored to the state form and
# the negative one is checked first.
_POSITIVE_STATE = re.compile(r"(?im)^\s*(?:state:\s*)?(?:likely\s+)?vulnerable\b")
_NEGATIVE_STATE = re.compile(r"(?im)^\s*state:\s*not vulnerable\b")
_CVE_IN_TEXT = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

# Only the stems in our own catalog ever reach argv, but guard anyway: a script
# name is interpolated into a command line.
_SCRIPT_NAME_SAFE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")


@dataclass(slots=True)
class VulnerabilityFinding:
    """One NSE script that reported a host (or port) as vulnerable."""

    script: str
    title: str
    severity: str = "medium"
    cve_id: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    detail: Optional[str] = None


def script_reports_vulnerable(output: str) -> bool:
    """Whether an NSE script's output is a positive verdict.

    Kept separate and pure because attribution matters: mailing "vulnerable"
    for every script that merely ran would be worse than not scanning at all.
    """
    text = output or ""
    if _NEGATIVE_STATE.search(text):
        return False
    return bool(_POSITIVE_STATE.search(text))


def vuln_findings_from_scan_data(scan_data: Dict[str, Any]) -> List[VulnerabilityFinding]:
    """Read NSE verdicts out of python-nmap's per-port script mapping.

    Pure, like :func:`ports_from_scan_data`: it takes the plain dict so the
    attribution rules are testable without scanning anything.
    """
    from app.services.nmap_capabilities import VULN_SCRIPT_CATALOG

    findings: List[VulnerabilityFinding] = []
    seen: set[tuple[str, Optional[int], Optional[str]]] = set()

    for _host, host_entry in (scan_data or {}).items():
        if not isinstance(host_entry, dict):
            continue
        for protocol in STATE_PORT_PROTOCOLS:
            ports = host_entry.get(protocol)
            if not isinstance(ports, dict):
                continue
            for port_key, info in ports.items():
                if not isinstance(info, dict):
                    continue
                scripts = info.get("script")
                if not isinstance(scripts, dict):
                    continue
                try:
                    port: Optional[int] = int(port_key)
                except (TypeError, ValueError):
                    port = None

                for script_name, output in scripts.items():
                    text = str(output or "")
                    if not script_reports_vulnerable(text):
                        continue

                    key = (str(script_name), port, protocol)
                    if key in seen:
                        continue
                    seen.add(key)

                    catalog = VULN_SCRIPT_CATALOG.get(str(script_name)) or {}
                    summary = str(catalog.get("summary") or "").strip()
                    cve = catalog.get("cve")
                    if not cve:
                        match = _CVE_IN_TEXT.search(text)
                        cve = match.group(0).upper() if match else None

                    findings.append(
                        VulnerabilityFinding(
                            script=str(script_name),
                            title=summary or f"{script_name} reported a vulnerability",
                            severity=str(catalog.get("severity") or "medium"),
                            cve_id=str(cve) if cve else None,
                            port=port,
                            protocol=protocol,
                            detail=text.strip()[:4000] or None,
                        )
                    )

    findings.sort(key=lambda item: (item.port or 0, item.script))
    return findings


def _format_script_output(entry: Dict[str, Any]) -> Optional[str]:
    """Flatten an nmap ``script`` mapping into readable banner text."""
    script = entry.get("script")
    if not isinstance(script, dict) or not script:
        return None
    lines = []
    for name, output in script.items():
        text = str(output).strip()
        if text:
            lines.append(f"{name}: {text[:2000]}")
    return "\n".join(lines) or None


def ports_from_scan_data(scan_data: Dict[str, Any]) -> List[PortObservation]:
    """Flatten python-nmap's per-host port mapping into observations.

    Pure and dependency-free on purpose — it takes a plain dict, which is the
    piece worth testing, rather than a live ``PortScanner``.
    """
    observations: List[PortObservation] = []

    for _host, host_entry in (scan_data or {}).items():
        if not isinstance(host_entry, dict):
            continue
        for protocol in STATE_PORT_PROTOCOLS:
            ports = host_entry.get(protocol)
            if not isinstance(ports, dict):
                continue
            for port_key, info in ports.items():
                if not isinstance(info, dict):
                    continue
                try:
                    port = int(port_key)
                except (TypeError, ValueError):
                    continue

                state = info.get("state")
                state = str(state) if state else None
                if state and state not in REPORTABLE_STATES:
                    continue

                observations.append(
                    PortObservation(
                        port=port,
                        protocol=protocol,
                        state=state,
                        service=info.get("name") or None,
                        product=info.get("product") or None,
                        version=info.get("version") or None,
                        extra_info=info.get("extrainfo") or None,
                        banner=_format_script_output(info),
                    )
                )

    observations.sort(key=lambda obs: (obs.protocol, obs.port))
    return observations


def nmap_available() -> bool:
    """True when the nmap binary is on PATH (python-nmap shells out to it)."""
    return shutil.which("nmap") is not None


def _deep_scan_sync(
    ip_address: str,
    host_timeout: int,
    port_spec: str,
    vuln_scripts: Sequence[str] = (),
) -> Dict[str, Any]:
    """Blocking targeted nmap scan, returned in python-nmap's scan shape."""
    import nmap  # python-nmap

    arguments = f"-sV -T4 -Pn --host-timeout {int(host_timeout)}s"
    if port_spec:
        arguments = f"{arguments} -p {port_spec}"
    scripts = [name for name in vuln_scripts if _SCRIPT_NAME_SAFE.match(name)]
    if scripts:
        # One targeted run instead of a second sweep: the service scan already
        # opened the connections, and the script list is the catalog
        # intersected with what this install actually has on disk.
        arguments = f"{arguments} --script {','.join(scripts)}"

    scanner = nmap.PortScanner()
    scanner.scan(hosts=ip_address, arguments=arguments)

    scan_data: Dict[str, Any] = {}
    for host in scanner.all_hosts():
        entry = scanner[host]
        scan_data[host] = {key: value for key, value in entry.items() if key in STATE_PORT_PROTOCOLS}
    return scan_data


@dataclass(slots=True)
class DeviceScanResult:
    """Everything one deep scan of a known host produced."""

    observations: List[PortObservation] = field(default_factory=list)
    findings: List[VulnerabilityFinding] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


async def scan_device(
    ip_address: str,
    *,
    host_timeout: int = 180,
    port_spec: str = "",
    vuln_scripts: Sequence[str] = (),
) -> DeviceScanResult:
    """Scan one device for listening ports and, optionally, known CVEs.

    Missing nmap, a restricted target, or a failed scan are all reported as
    warnings with an empty result rather than raised, because a detail lookup
    should degrade visibly instead of erroring.
    """
    if not validate_target(ip_address):
        return DeviceScanResult(warnings=[f"Refusing to scan invalid target: {ip_address!r}"])
    if is_restricted_target(ip_address):
        return DeviceScanResult(
            warnings=["Active scanning is prohibited on designated fragile or restricted subnets."]
        )
    if not nmap_available():
        # Built-in engine: a TCP connect sweep still answers "what is
        # listening" without nmap. Service/version detection and the NSE
        # vulnerability scripts both need nmap, so the caller is told the
        # result is port-level only.
        from app.services.builtin_scan import builtin_scan

        try:
            _output, summary = await builtin_scan(ip_address, "-sV -F")
        except Exception as exc:  # noqa: BLE001 - surfaced as a warning
            return DeviceScanResult(warnings=[f"Deep scan failed: {exc}"])

        observations: List[PortObservation] = []
        for host in summary.get("hosts", []):
            for entry in host.get("open_ports", []):
                observations.append(
                    PortObservation(
                        port=entry.get("port"),
                        protocol="tcp",
                        state="open",
                        service=entry.get("service") or None,
                    )
                )
        observations.sort(key=lambda obs: obs.port)
        return DeviceScanResult(
            observations=observations,
            warnings=[
                "Scanned with the built-in TCP engine (nmap not installed); "
                "port-level results only, no service versions or vulnerability checks."
            ],
        )

    try:
        scan_data = await asyncio.to_thread(
            _deep_scan_sync, ip_address, host_timeout, port_spec, list(vuln_scripts)
        )
    except Exception as exc:  # noqa: BLE001 - surfaced to the caller as a warning
        return DeviceScanResult(warnings=[f"Deep scan failed: {exc}"])

    return DeviceScanResult(
        observations=ports_from_scan_data(scan_data),
        findings=vuln_findings_from_scan_data(scan_data),
    )


async def scan_device_ports(
    ip_address: str,
    *,
    host_timeout: int = 180,
    port_spec: str = "",
) -> Tuple[List[PortObservation], List[str]]:
    """Port-only view of :func:`scan_device`, kept for existing callers."""
    result = await scan_device(ip_address, host_timeout=host_timeout, port_spec=port_spec)
    return result.observations, result.warnings


async def upsert_device_ports(
    db: Any,
    device_id: int,
    observations: List[PortObservation],
    *,
    now: Optional[datetime] = None,
) -> Tuple[int, int, int]:
    """Replace a device's stored port set with *observations*.

    Returns ``(created, updated, removed)``. The table describes what is
    listening *now*, so ports that disappeared are deleted rather than left
    behind to mislead the detail view.
    """
    # Imported here so the module stays importable without SQLAlchemy.
    from sqlalchemy import select

    from app.models.device_port import DevicePort

    observed_at = now or datetime.now(timezone.utc)
    result = await db.execute(select(DevicePort).where(DevicePort.device_id == device_id))
    existing = {(row.port, row.protocol): row for row in result.scalars().all()}

    created = 0
    updated = 0
    observed_keys: set[tuple[int, str]] = set()

    for observation in observations:
        key = (observation.port, observation.protocol)
        observed_keys.add(key)
        row = existing.get(key)

        if row is None:
            db.add(
                DevicePort(
                    device_id=device_id,
                    port=observation.port,
                    protocol=observation.protocol,
                    state=observation.state,
                    service=observation.service,
                    product=observation.product,
                    version=observation.version,
                    extra_info=observation.extra_info,
                    banner=observation.banner,
                )
            )
            created += 1
            continue

        row.state = observation.state
        row.service = observation.service or row.service
        row.product = observation.product or row.product
        row.version = observation.version or row.version
        row.extra_info = observation.extra_info or row.extra_info
        row.banner = observation.banner or row.banner
        row.last_seen = observed_at
        updated += 1

    removed = 0
    for key, row in existing.items():
        if key not in observed_keys:
            await db.delete(row)
            removed += 1

    await db.commit()
    return created, updated, removed
