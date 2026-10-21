from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
from typing import Any

from app.core.config import settings

logger = logging.getLogger(__name__)

_PORT_PATTERN = re.compile(r"^[A-Za-z0-9/_:-]{1,64}$")


def _validate_port_name(port: str) -> bool:
    return bool(port and _PORT_PATTERN.fullmatch(port))


def _validate_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.fullmatch(r"[A-Za-z0-9.-]{1,253}", host))


async def isolate_switch_port(
    port: str,
    *,
    reason: str | None = None,
    switch_host: str | None = None,
    username: str | None = None,
    password: str | None = None,
    device_type: str | None = None,
    enable_secret: str | None = None,
    ssh_port: int | None = None,
) -> dict[str, Any]:
    host = switch_host or settings.switch_mgmt_host
    user = username or settings.switch_mgmt_user
    secret = password or settings.switch_mgmt_password
    dev_type = device_type or settings.switch_mgmt_device_type
    enable = enable_secret or settings.switch_mgmt_enable_secret
    port_num = ssh_port or settings.switch_mgmt_port

    if not host or not user or not secret:
        raise RuntimeError("Switch management credentials are not configured")
    if not _validate_host(host):
        raise ValueError("Invalid switch host")
    if not _validate_port_name(port):
        raise ValueError("Invalid switch port name")

    def _shutdown() -> dict[str, Any]:
        from netmiko import ConnectHandler  # type: ignore[import-untyped]

        connection = ConnectHandler(
            device_type=dev_type,
            host=host,
            username=user,
            password=secret,
            secret=enable or secret,
            port=port_num,
            fast_cli=True,
        )
        try:
            if enable:
                connection.enable()
            output = connection.send_config_set([f"interface {port}", "shutdown"])
            return {"host": host, "port": port, "output": output}
        finally:
            connection.disconnect()

    result = await asyncio.to_thread(_shutdown)
    logger.warning("Isolated switch port %s on %s", port, host)
    return result


# ---------------------------------------------------------------------------
# Host isolation via the local OS firewall
#
# This is the *real* isolation path that works without a managed switch: the
# backend installs drop rules for the target address in the host firewall.
# Traffic to/from the node is discarded at the machine running NetPulse.
#
# Injection safety: the IP is parsed with the ipaddress module (no strings
# reach a shell), every subprocess uses an argv list with shell=False, and the
# rule name embeds only the validated address.
# ---------------------------------------------------------------------------

_FIREWALL_RULE_PREFIX = "NetPulse-Isolate-"


def _validated_ip(ip: str) -> str:
    """Return the canonical form of *ip* or raise ValueError.

    Only a literal address is accepted — hostnames are refused so nothing can
    be smuggled into the firewall tooling.
    """
    import ipaddress

    try:
        return str(ipaddress.ip_address(ip.strip()))
    except ValueError as exc:
        raise ValueError("A literal IPv4/IPv6 address is required") from exc


def _run(cmd: list[str]) -> str:
    """Run a fixed-argv command, raising RuntimeError on failure."""
    import subprocess

    proc = subprocess.run(cmd, capture_output=True, text=True, shell=False, timeout=30)
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip() or f"exit code {proc.returncode}"
        raise RuntimeError(detail)
    return (proc.stdout or "").strip()


def _isolate_windows(ip: str) -> dict[str, Any]:
    rule_in = f"{_FIREWALL_RULE_PREFIX}in-{ip}"
    rule_out = f"{_FIREWALL_RULE_PREFIX}out-{ip}"
    added: list[str] = []
    try:
        _run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_in}", "dir=in", "action=block",
            f"remoteip={ip}", "enable=yes",
        ])
        added.append(rule_in)
        _run([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_out}", "dir=out", "action=block",
            f"remoteip={ip}", "enable=yes",
        ])
        added.append(rule_out)
    except RuntimeError as exc:
        if "requested operation requires elevation" in str(exc).lower() or "access is denied" in str(exc).lower():
            raise RuntimeError(
                "Windows firewall rules need an elevated (administrator) "
                "backend process — restart NetPulse as administrator."
            ) from exc
        raise
    return {"method": "windows-firewall", "rules": added}


def _release_windows(ip: str) -> dict[str, Any]:
    removed: list[str] = []
    for direction in ("in", "out"):
        rule = f"{_FIREWALL_RULE_PREFIX}{direction}-{ip}"
        try:
            _run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"])
            removed.append(rule)
        except RuntimeError:
            # A missing rule is not an error during release.
            pass
    return {"method": "windows-firewall", "rules": removed}


def _isolate_posix(ip: str) -> dict[str, Any]:
    import shutil

    iptables = shutil.which("iptables")
    if not iptables:
        nft = shutil.which("nft")
        if not nft:
            raise RuntimeError(
                "Neither iptables nor nft is installed — cannot drop traffic "
                "on this host."
            )
        _run([nft, "add", "table", "inet", "netpulse"])
        _run([nft, "add", "chain", "inet", "netpulse", "isolate", "{", "type", "filter", "hook", "input", "priority", "0", ";", "}"])
        _run([nft, "add", "rule", "inet", "netpulse", "isolate", "ip", "saddr", ip, "drop"])
        return {"method": "nftables", "table": "inet netpulse"}

    _run([iptables, "-I", "INPUT", "-s", ip, "-j", "DROP"])
    _run([iptables, "-I", "OUTPUT", "-d", ip, "-j", "DROP"])
    return {"method": "iptables", "chains": ["INPUT", "OUTPUT"]}


def _release_posix(ip: str) -> dict[str, Any]:
    import shutil

    iptables = shutil.which("iptables")
    if iptables:
        removed: list[str] = []
        for chain, flag in (("INPUT", "-s"), ("OUTPUT", "-d")):
            try:
                _run([iptables, "-D", chain, flag, ip, "-j", "DROP"])
                removed.append(chain)
            except RuntimeError:
                pass
        return {"method": "iptables", "chains": removed}

    nft = shutil.which("nft")
    if nft:
        try:
            _run([nft, "flush", "chain", "inet", "netpulse", "isolate"])
        except RuntimeError:
            pass
        return {"method": "nftables", "table": "inet netpulse"}

    raise RuntimeError("Neither iptables nor nft is installed.")


async def isolate_host(ip: str, *, reason: str | None = None) -> dict[str, Any]:
    """Drop traffic to/from *ip* at this machine's firewall.

    Raises RuntimeError with a human-readable cause when the OS refuses (most
    commonly: the backend lacks root/administrator rights).
    """
    import sys

    address = _validated_ip(ip)
    result = await asyncio.to_thread(
        _isolate_windows if sys.platform.startswith("win") else _isolate_posix,
        address,
    )
    logger.warning("Isolated host %s via %s (%s)", address, result.get("method"), reason)
    return {"ip": address, **result}


async def release_host(ip: str) -> dict[str, Any]:
    """Remove the isolation rules installed by :func:`isolate_host`."""
    import sys

    address = _validated_ip(ip)
    result = await asyncio.to_thread(
        _release_windows if sys.platform.startswith("win") else _release_posix,
        address,
    )
    logger.warning("Released host %s via %s", address, result.get("method"))
    return {"ip": address, **result}
