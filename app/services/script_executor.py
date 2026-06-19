from __future__ import annotations

import asyncio
import importlib.util
import inspect
import ipaddress
import json
import re
import sys
import textwrap
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Callable, Dict, Optional

from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
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


def _is_allowed_script_path(script_path: Path) -> bool:
    allowed_roots = [
        (Path(settings.scripts_base_dir) / settings.scripts_uploads_subdir).resolve(),
        (Path(settings.scripts_base_dir) / settings.scripts_prebuilt_subdir).resolve(),
    ]
    try:
        resolved = script_path.resolve(strict=True)
    except Exception:
        return False
    return any(resolved == root or root in resolved.parents for root in allowed_roots)


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

        loop = asyncio.get_running_loop()
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

        loop = asyncio.get_running_loop()
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

            loop = asyncio.get_running_loop()
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
    if not _is_allowed_script_path(script_path):
        raise PermissionError("Script path is outside of the allowed directories")

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

    script_path = Path(job.script_path)
    temp_file_path = None
    try:
        # Validate that the script exists and is allowed early
        await _load_script_callable(script_path)

        # Build wrapper code string
        wrapper_code = f"""import asyncio
import sys
import json
import importlib.util
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, {repr(str(Path(__file__).parent.parent.parent.resolve().as_posix()))})

from app.services.script_executor import NetworkTools

class SubprocessContext:
    def __init__(self, job_id, params):
        self.job_id = job_id
        self.params = params
        self.network = NetworkTools()
        self.db = None
    
    def logger(self, message):
        print(f"[LOG] {{message}}", flush=True)

async def main():
    script_path = Path({repr(str(script_path.resolve().as_posix()))})
    params = json.loads({repr(json.dumps(job.params or {}))})
    
    spec = importlib.util.spec_from_file_location("run_module", str(script_path))
    if spec is None or spec.loader is None:
        print("[ERROR] Could not load script spec", file=sys.stderr, flush=True)
        sys.exit(1)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    
    ctx = SubprocessContext({job.id}, params)
    
    try:
        import inspect
        if inspect.iscoroutinefunction(module.run):
            res = await module.run(ctx)
        else:
            res = module.run(ctx)
        print(f"[RESULT] {{json.dumps(res)}}", flush=True)
    except Exception as e:
        print(f"[ERROR] {{e}}", file=sys.stderr, flush=True)
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
"""
        temp_dir = Path(settings.scripts_base_dir) / "temp"
        temp_dir.mkdir(parents=True, exist_ok=True)
        temp_file_path = temp_dir / f"temp_job_{job.id}.py"
        temp_file_path.write_text(wrapper_code, encoding="utf-8")

        if settings.environment.lower() == "development":
            # Bypass sandbox: execute Python code natively using asyncio subprocess
            proc = await asyncio.create_subprocess_exec(
                sys.executable,
                str(temp_file_path.resolve()),
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
        else:
            # Production: execute using secure gVisor sandbox containment scripts
            proc = await asyncio.create_subprocess_exec(
                "docker",
                "run",
                "--runtime=runsc",
                "-i",
                "--rm",
                "-v",
                f"{temp_dir.resolve().as_posix()}:/workspace/temp",
                "-v",
                f"{Path(settings.scripts_base_dir).resolve().as_posix()}:/workspace/scripts",
                "python:3.11-slim",
                "python",
                f"/workspace/temp/{temp_file_path.name}",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

        stdout_bytes, stderr_bytes = await proc.communicate()
        stdout_str = stdout_bytes.decode(errors="replace")
        stderr_str = stderr_bytes.decode(errors="replace")

        result_dict = None
        for line in stdout_str.splitlines():
            if line.startswith("[LOG] "):
                log(line[6:])
            elif line.startswith("[RESULT] "):
                try:
                    result_dict = json.loads(line[9:])
                except Exception:
                    log(f"Failed to parse result: {line}")
            else:
                if line.strip():
                    log(f"stdout: {line}")

        for line in stderr_str.splitlines():
            if line.strip():
                log(f"stderr: {line}")

        if proc.returncode == 0:
            job.result = result_dict if isinstance(result_dict, dict) else {"result": str(result_dict)}
            job.status = ScriptJobStatus.SUCCESS
        else:
            log(f"Script process exited with non-zero code: {proc.returncode}")
            job.status = ScriptJobStatus.FAILED

    except Exception as exc:  # noqa: BLE001
        log(f"Script execution failed: {exc!r}")
        job.status = ScriptJobStatus.FAILED
    finally:
        # Cleanup temp file
        if temp_file_path and temp_file_path.exists():
            try:
                temp_file_path.unlink()
            except Exception:
                pass

        # Persist logs and final status
        existing_logs = (job.logs or "").strip()
        combined = "\n".join(logs)
        job.logs = f"{existing_logs}\n{combined}".strip() if existing_logs else combined
        job.finished_at = datetime.utcnow()

        await db.commit()
        await db.refresh(job)
