#!/usr/bin/env python3
"""Launch the NetPulse stack with one readable console and per-service logs.

The Windows launcher used to open four cmd windows, and the Linux one let three
services interleave unfiltered output, so it was hard to see what was running
and harder to see what had broken. This starts the API, the Celery worker and
the Vite dev server as children of a single process:

  * every line is prefixed with the service that produced it,
  * each service's full output goes to logs/<service>.log,
  * a service that dies is reported with the tail of its own log,
  * Ctrl+C stops all of them, including uvicorn's reload children.

Preflight (PostgreSQL, the database, Redis) still belongs to run_stack.sh and
windows_run_stack.bat; this script only launches processes.

Usage: python scripts/stack.py [--no-frontend] [--no-worker] [--verbose]
"""

from __future__ import annotations

import argparse
import os
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LOG_DIR = ROOT / "logs"
API_PORT = 8000

COLOR = {
    "api": "\033[36m",
    "worker": "\033[35m",
    "ui": "\033[33m",
    "stack": "\033[32m",
}
RESET = "\033[0m"

# Scapy writes its "capture driver is missing" warning straight to stderr as
# several lines with blank ones in between, before any logging exists. It is
# real information, but it is not what the operator needs on every launch, so
# those lines and empty ones are kept out of the console only -- logs/api.log
# keeps every byte.
_NOISE = (
    "WARNING: Scapy has detected that your pcap service is not running",
    "WARNING: [SC] StartService FAILED",
    "The service cannot be started, either because it is disabled",
    "WARNING: Could not start the pcap service!",
)

_print_lock = threading.Lock()
_use_color = False
_stopping = threading.Event()
_exit_code = 0


@dataclass(frozen=True)
class Service:
    name: str
    command: list[str]
    cwd: Path
    # A dead API means nothing works, so the whole stack goes down with it.
    # The worker and the dev server are useful to lose on their own.
    fatal: bool = False

    @property
    def log_path(self) -> Path:
        return LOG_DIR / f"{self.name}.log"


def emit(source: str, message: str) -> None:
    """Write one whole line, so threads cannot interleave mid-line."""
    prefix = f"{COLOR.get(source, '')}[{source:6}]{RESET}" if _use_color else f"[{source:6}]"
    with _print_lock:
        sys.stdout.write(f"{prefix} {message}\n")
        sys.stdout.flush()


def _enable_ansi() -> bool:
    if not sys.stdout.isatty():
        return False
    if os.name == "nt":
        # Turns on VT escape handling in the Windows console (cmd/PowerShell).
        os.system("")
    return True


def _port_in_use(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.3)
        return sock.connect_ex(("127.0.0.1", port)) == 0


def _tail(path: Path, lines: int = 15) -> list[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            # Strip the newline: the caller adds its own, otherwise every
            # reported line prints with a blank line after it.
            return [line.rstrip("\r\n") for line in deque(handle, maxlen=lines)]
    except Exception:
        return []


def _shutdown(code: int = 0) -> None:
    global _exit_code
    if not _stopping.is_set():
        _exit_code = code
    _stopping.set()


def _read_output(service: Service, process: subprocess.Popen[str]) -> None:
    """Copy one service's output to the console and its log file, then report."""
    assert process.stdout is not None
    with open(service.log_path, "w", encoding="utf-8", errors="replace") as log:
        for raw in process.stdout:
            line = raw.rstrip("\n")
            log.write(line + "\n")
            log.flush()
            if not line.strip():
                continue
            if any(marker in line for marker in _NOISE):
                continue
            emit(service.name, line)

    code = process.wait()
    if _stopping.is_set():
        return

    emit("stack", f"{service.name} stopped on its own (exit code {code}).")
    tail = _tail(service.log_path)
    if tail:
        emit("stack", f"last lines of logs/{service.name}.log:")
        for line in tail:
            emit("stack", f"  {line}")

    if service.fatal:
        # Whatever the exit code: without the API nothing else is useful, so do
        # not sit here pretending the stack is up.
        emit("stack", "The API is required, so the rest of the stack is stopping.")
        _shutdown(code)
    elif code != 0:
        emit("stack", f"{service.name} is not running; the rest of the stack continues.")


def _start(service: Service) -> subprocess.Popen[str]:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    # A test can pre-create the log so an early crash still has something to
    # show; opening with "w" in the reader keeps that behaviour simple.
    service.log_path.touch(exist_ok=True)

    env = dict(os.environ)
    env.setdefault("PYTHONUNBUFFERED", "1")
    env.setdefault("FORCE_COLOR", "1")

    kwargs: dict[str, object] = {
        "cwd": str(service.cwd),
        "stdout": subprocess.PIPE,
        "stderr": subprocess.STDOUT,
        "text": True,
        "bufsize": 1,
        "env": env,
    }
    if os.name == "nt":
        # CREATE_NO_WINDOW is what stops a second console popping up;
        # CREATE_NEW_PROCESS_GROUP lets taskkill /T reach the reload child.
        kwargs["creationflags"] = (
            subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
        )
    else:
        # Own session: killing the group takes uvicorn's reloader with it.
        kwargs["start_new_session"] = True

    process = subprocess.Popen(service.command, **kwargs)  # type: ignore[call-overload]
    threading.Thread(
        target=_read_output,
        args=(service, process),
        name=f"reader-{service.name}",
        daemon=True,
    ).start()
    return process


def _wait_for_api(timeout: float = 60.0) -> None:
    """Print the URLs once the API actually answers, not when its process starts."""
    url = f"http://127.0.0.1:{API_PORT}/api/health/live"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not _stopping.is_set():
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    _print_summary()
                    return
        except (urllib.error.URLError, OSError, ValueError):
            pass
        time.sleep(0.5)

    if not _stopping.is_set():
        emit("stack", f"The API has not answered for {int(timeout)}s - check logs/api.log.")


def _print_summary() -> None:
    frontend = "  http://localhost:6969   (Vite prints another port if 6969 is busy)"
    lines = [
        "",
        "  NetPulse is running",
        f"    App        http://localhost:{API_PORT}",
        f"    Dev UI     {frontend.strip()}",
        f"    API docs   http://localhost:{API_PORT}/docs",
        "    Logs       logs/api.log  logs/worker.log  logs/ui.log",
        "  Ctrl+C stops every service.",
        "",
    ]
    with _print_lock:
        sys.stdout.write("\n".join(lines) + "\n")
        sys.stdout.flush()


def _stop(processes: list[tuple[Service, subprocess.Popen[str]]]) -> None:
    for _service, process in processes:
        if process.poll() is not None:
            continue
        try:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/F", "/T", "/PID", str(process.pid)],
                    capture_output=True,
                    check=False,
                )
            else:
                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
        except Exception:
            continue

    deadline = time.monotonic() + 10
    for _service, process in processes:
        try:
            process.wait(timeout=max(0.5, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            if os.name != "nt":
                try:
                    os.killpg(os.getpgid(process.pid), signal.SIGKILL)
                except Exception:
                    pass


def build_services(verbose: bool, with_worker: bool, with_frontend: bool) -> list[Service]:
    api_command = [
        sys.executable, "-m", "uvicorn", "app.main:app",
        "--reload", "--host", "0.0.0.0", "--port", str(API_PORT),
    ]
    if not verbose:
        # One line per HTTP request buried every real message.
        api_command.append("--no-access-log")

    worker_command = [
        sys.executable, "-m", "celery",
        "-A", "app.core.celery_app.celery_app", "worker",
        f"--loglevel={'INFO' if verbose else 'WARNING'}",
    ]
    if os.name == "nt":
        # Celery's prefork pool is unreliable on Windows; solo is the supported one.
        worker_command.append("--pool=solo")

    services = [Service("api", api_command, ROOT, fatal=True)]
    if with_worker:
        services.append(Service("worker", worker_command, ROOT))

    if with_frontend:
        npm = shutil.which("npm") or shutil.which("npm.cmd")
        if npm is None:
            emit("stack", "npm is not on PATH; starting without the dev server.")
        else:
            services.append(Service("ui", [npm, "run", "dev"], ROOT / "frontend"))

    return services


def main() -> int:
    global _use_color

    parser = argparse.ArgumentParser(description="Run the NetPulse stack in one console.")
    parser.add_argument("--no-frontend", action="store_true", help="skip the Vite dev server")
    parser.add_argument("--no-worker", action="store_true", help="skip the Celery worker")
    parser.add_argument("--verbose", action="store_true", help="keep HTTP access logs and info-level worker logs")
    args = parser.parse_args()

    _use_color = _enable_ansi()

    if _port_in_use(API_PORT):
        emit("stack", f"Port {API_PORT} is already in use - another NetPulse instance is running?")
        emit("stack", "Stop it (or the process holding the port) and try again.")
        return 1

    services = build_services(args.verbose, not args.no_worker, not args.no_frontend)

    emit("stack", "Starting NetPulse")
    for service in services:
        emit("stack", f"  {service.name}: {' '.join(service.command)}")

    processes: list[tuple[Service, subprocess.Popen[str]]] = []
    try:
        for service in services:
            processes.append((service, _start(service)))
    except Exception as exc:
        emit("stack", f"Could not start {services[len(processes)].name}: {exc}")
        _stop(processes)
        return 1

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda *_: _shutdown(0))

    threading.Thread(target=_wait_for_api, name="api-readiness", daemon=True).start()

    try:
        while not _stopping.wait(0.5):
            pass
    except KeyboardInterrupt:
        _shutdown(0)
    finally:
        emit("stack", "Stopping services...")
        _stop(processes)
        emit("stack", "All services stopped.")

    return _exit_code


if __name__ == "__main__":
    raise SystemExit(main())
