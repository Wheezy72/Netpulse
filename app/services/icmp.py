from __future__ import annotations

"""Platform-correct ICMP ping helper.

The uptime and device ping-status endpoints both need "is this host answering,
and how fast". The system ``ping`` binary differs enough between Windows and
everything else (``-n`` vs ``-c``, milliseconds vs seconds for the timeout, and
Windows output never says ``packets transmitted``) that the parsing belongs in
one place instead of being re-derived per endpoint.
"""

import asyncio
import os
import re
from dataclasses import dataclass

# Matches "time=1.24 ms" (Linux/macOS) and "time=1ms" / "time<1ms" (Windows).
_TIME_PATTERN = re.compile(r"[Tt]ime[=<]\s*(\d+(?:\.\d+)?)\s*ms")
# "TTL=64" (Windows) and "ttl=64" (Linux/macOS) both appear in the reply line.
# The value is a coarse but real OS-family signal: 64 = Unix-like, 128 = Windows.
_TTL_PATTERN = re.compile(r"[Tt][Tt][Ll][=:]\s*(\d{1,3})")
# Linux summary: "3 packets transmitted, 3 received, 0% packet loss"
# Windows summary: "Packets: Sent = 3, Received = 3, Lost = 0 (0% loss)"
_LINUX_LOSS_PATTERN = re.compile(r"(\d+(?:\.\d+)?)%")
_WINDOWS_LOSS_PATTERN = re.compile(r"Lost\s*=\s*\d+\s*\((\d+(?:\.\d+)?)%")


@dataclass(frozen=True)
class PingOutcome:
    """Result of one ping invocation against a single host."""

    host: str
    reachable: bool
    latency_ms: float | None
    packet_loss_pct: float | None
    error: str | None = None
    ttl: int | None = None


def build_ping_argv(host: str, *, count: int = 1, timeout_s: float = 1.0) -> list[str]:
    """Platform-correct argv for one ping run. Never a shell string."""
    if os.name == "nt":
        # Windows: -n count, -w timeout in milliseconds.
        return ["ping", "-n", str(max(1, count)), "-w", str(int(max(0.1, timeout_s) * 1000)), host]
    # POSIX: -c count, -W timeout in seconds (iputils; macOS ignores -W harmlessly).
    return ["ping", "-c", str(max(1, count)), "-W", str(max(1, round(timeout_s))), host]


def parse_ping_ttl(text: str) -> int | None:
    """The reply's TTL, or None when the platform's ping output omits it."""
    matches = _TTL_PATTERN.findall(text or "")
    if not matches:
        return None
    try:
        value = int(matches[0])
    except ValueError:
        return None
    return value if 0 < value <= 255 else None


def parse_ping_output(text: str) -> tuple[float | None, float | None]:
    """Extract (average latency in ms, packet loss percentage) from ping output.

    Either value may be None when the platform's output does not carry it.
    """
    latencies = [float(m) for m in _TIME_PATTERN.findall(text)]
    avg_ms = (sum(latencies) / len(latencies)) if latencies else None

    loss_match = _WINDOWS_LOSS_PATTERN.search(text)
    if loss_match is None:
        loss_match = _LINUX_LOSS_PATTERN.search(text)
    loss_pct = float(loss_match.group(1)) if loss_match else None

    return avg_ms, loss_pct


async def ping(
    host: str,
    *,
    count: int = 1,
    timeout_s: float = 1.0,
) -> PingOutcome:
    """Ping *host* once (or *count* times) and classify the answer.

    Never raises: every failure mode becomes ``reachable=False`` with an error
    string, so callers can gather over a whole subnet without try/except soup.
    """
    host = (host or "").strip()
    if not host:
        return PingOutcome(host=host, reachable=False, latency_ms=None, packet_loss_pct=None, error="Empty host")

    argv = build_ping_argv(host, count=count, timeout_s=timeout_s)
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except OSError as exc:
        return PingOutcome(host=host, reachable=False, latency_ms=None, packet_loss_pct=None, error=str(exc))

    try:
        stdout, _stderr = await asyncio.wait_for(process.communicate(), timeout=max(timeout_s * count + 2.0, 5.0))
    except asyncio.TimeoutError:
        process.kill()
        await process.wait()
        return PingOutcome(host=host, reachable=False, latency_ms=None, packet_loss_pct=None, error="Ping timed out")
    except Exception as exc:  # Defensive: gather() over many hosts must survive.
        return PingOutcome(host=host, reachable=False, latency_ms=None, packet_loss_pct=None, error=str(exc))

    text = stdout.decode(errors="replace")
    avg_ms, loss_pct = parse_ping_output(text)
    ttl = parse_ping_ttl(text)

    if process.returncode == 0:
        return PingOutcome(
            host=host,
            reachable=True,
            latency_ms=avg_ms,
            packet_loss_pct=loss_pct,
            ttl=ttl,
        )
    return PingOutcome(
        host=host,
        reachable=False,
        latency_ms=None,
        packet_loss_pct=loss_pct,
        error="No response",
    )
