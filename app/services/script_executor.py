from __future__ import annotations

import asyncio
import importlib.util
import inspect
import ipaddress
import re
import textwrap
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.models.script_job import ScriptJob, ScriptJobStatus


_HOSTNAME_PATTERN = re.compile(
    r"^(?=.{1,255}$)[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$"
)


def _validate_ping_target(target: str) -> bool:
    if not target or len(target) > 255:
        return False
    if target.startswith("-"):
        return False
    if any(ch.isspace() for ch in target):
        return False

    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return bool(_HOSTNAME_PATTERN.match(target))


@dataclass
class NetworkTools:
    """Network helper methods exposed to user scripts.

    Provides network utility functions using scapy for packet manipulation.
    """

    async def tcp_rst(
        self,
        src_ip: str,
        src_port: int,
        dst_ip: str,
        dst_port: int,
        count: int = 3,
    ) -> None:
        """Send TCP RST packets to tear down a connection.

        Uses scapy to craft and send TCP RST packets. Requires root privileges.
        
        Args:
            src_ip: Source IP address
            src_port: Source port
            dst_ip: Destination IP address
            dst_port: Destination port
            count: Number of RST packets to send
        """
        def _send_rst() -> None:
            try:
                from scapy.all import IP, TCP, send
                
                for _ in range(count):
                    pkt = IP(src=src_ip, dst=dst_ip) / TCP(
                        sport=src_port,
                        dport=dst_port,
                        flags="R",
                        seq=0,
                    )
                    send(pkt, verbose=False)
            except PermissionError:
                pass
            except Exception:
                pass
        
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, _send_rst)

    async def ping(self, target: str, count: int = 4, timeout: int = 2) -> dict:
        """Ping a target host and return statistics.
        
        Args:
            target: IP address or hostname to ping
            count: Number of ping packets
            timeout: Timeout per packet in seconds
            
        Returns:
            Dictionary with ping statistics
        """
        def _ping_sync() -> dict:
            import subprocess

            if not _validate_ping_target(target):
                return {"target": target, "success": False, "error": "Invalid target"}

            if count < 1 or count > 10:
                return {"target": target, "success": False, "error": "Invalid count"}

            if timeout < 1 or timeout > 10:
                return {"target": target, "success": False, "error": "Invalid timeout"}

            try:
                result = subprocess.run(
                    ["ping", "-c", str(count), "-W", str(timeout), target],
                    capture_output=True,
                    text=True,
                    timeout=count * timeout + 5
                )
                
                lines = result.stdout.split("\n")
                stats = {"target": target, "success": result.returncode == 0}
                
                for line in lines:
                    if "packets transmitted" in line:
                        parts = line.split(",")
                        for part in parts:
                            if "transmitted" in part:
                                stats["transmitted"] = int(part.strip().split()[0])
                            elif "received" in part:
                                stats["received"] = int(part.strip().split()[0])
                            elif "loss" in part:
                                stats["loss_percent"] = float(part.strip().split("%")[0].split()[-1])
                    elif "rtt" in line or "round-trip" in line:
                        if "=" in line:
                            rtt_part = line.split("=")[-1].strip()
                            rtt_values = rtt_part.split("/")
                            if len(rtt_values) >= 3:
                                stats["rtt_min"] = float(rtt_values[0])
                                stats["rtt_avg"] = float(rtt_values[1])
                                stats["rtt_max"] = float(rtt_values[2])
                
                return stats
            except Exception as e:
                return {"target": target, "success": False, "error": str(e)}
        
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, _ping_sync)

    async def port_scan(
        self, target: str, ports: list[int], timeout: float = 1.0
    ) -> dict:
        """Scan specific ports on a target host.
        
        Args:
            target: IP address or hostname
            ports: List of ports to scan
            timeout: Connection timeout per port
            
        Returns:
            Dictionary with port scan results
        """
        import socket
        
        async def check_port(port: int) -> tuple[int, bool]:
            def _check() -> bool:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(timeout)
                    result = sock.connect_ex((target, port))
                    sock.close()
                    return result == 0
                except Exception:
                    return False
            
            loop = asyncio.get_event_loop()
            is_open = await loop.run_in_executor(None, _check)
            return (port, is_open)
        
        tasks = [check_port(port) for port in ports[:100]]
        results = await asyncio.gather(*tasks)
        
        return {
            "target": target,
            "open_ports": [port for port, is_open in results if is_open],
            "closed_ports": [port for port, is_open in results if not is_open],
            "scanned": len(results),
        }


@dataclass
class ScriptContext:
    db: AsyncSession
    logger: Callable[[str], None]
    network: NetworkTools
    job_id: int
    params: Dict[str, Any]


async def _load_script_callable(script_path: Path) -> Callable[[ScriptContext], Any]:
    """Load the `run` callable from a Python module located at script_path."""
    if not script_path.exists():
        raise FileNotFoundError(f"Script not found at {script_path}")

    module_name = f"netpulse_script_{script_path.stem}"
    spec = importlib.util.spec_from_file_location(module_name, str(script_path))
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load spec for script {script_path}")

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)  # type: ignore[call-arg]

    if not hasattr(module, "run"):
        raise AttributeError("Script must define a top-level 'run(ctx)' function")

    run_callable = getattr(module, "run")
    if not callable(run_callable):
        raise TypeError("'run' attribute in script is not callable")

    return run_callable


async def execute_script(
    db: AsyncSession,
    job_id: int,
) -> None:
    """Core logic for executing a ScriptJob.

    The lifecycle:

    - Load ScriptJob from DB.
    - Transition to RUNNING.
    - Build ScriptContext.
    - Invoke script's `run(ctx)` (async or sync).
    - Capture result and logs.
    - Update ScriptJob status and timestamps.
    """
    job = await db.get(ScriptJob, job_id)
    if job is None:
        return

    logs: list[str] = []

    def log(message: str) -> None:
        message = textwrap.shorten(message, width=2000, placeholder="...")
        logs.append(message)

    job.status = ScriptJobStatus.RUNNING
    job.started_at = datetime.utcnow()
    await db.commit()
    await db.refresh(job)

    context = ScriptContext(
        db=db,
        logger=log,
        network=NetworkTools(),
        job_id=job.id,
        params=job.params or {},
    )

    try:
        script_path = Path(job.script_path)
        run_callable = await _load_script_callable(script_path)

        if inspect.iscoroutinefunction(run_callable):
            result = await run_callable(context)  # type: ignore[arg-type]
        else:
            # Run sync functions in a thread to avoid blocking the event loop.
            result = await asyncio.to_thread(run_callable, context)  # type: ignore[arg-type]

        job.result = result if isinstance(result, dict) else {"result": str(result)}
        job.status = ScriptJobStatus.SUCCESS
    except Exception as exc:  # noqa: BLE001
        log(f"Script execution failed: {exc!r}")
        job.status = ScriptJobStatus.FAILED
    finally:
        # Persist logs and final status
        existing_logs = (job.logs or "").strip()
        combined = "\n".join(logs)
        job.logs = f"{existing_logs}\n{combined}".strip() if existing_logs else combined
        job.finished_at = datetime.utcnow()

        await db.commit()
        await db.refresh(job)