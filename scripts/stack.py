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

One stack per machine. A second launch used to start a second set of services
against the same Redis and database, which double-sweeps the network and
inflates every counter. A pidfile makes the launcher single-instance even when
the two launches race the API's port binding:

  * a live pidfile refuses the launch and names the running stack,
  * a pidfile whose process is gone is cleaned up silently,
  * ``--replace`` stops the previous stack and takes over,
  * ``--stop`` stops the running stack and exits.

Usage: python scripts/stack.py [--no-frontend] [--no-worker] [--verbose]
                              [--replace | --stop]
"""

from __future__ import annotations

import argparse
import os
import re
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
RUN_DIR = ROOT / "data" / "run"
LOCK_PATH = RUN_DIR / "stack.pid"
API_PORT = 8000
UI_PORT = 6969


def _ui_url() -> str:
    """The port Vite actually bound: it moves on when 6969 is taken."""
    for line in _tail(LOG_DIR / "ui.log", 80):
        match = re.search(r"http://localhost:(\d+)", line)
        if match:
            return f"http://localhost:{match.group(1)}"
    return f"http://localhost:{UI_PORT}"

COLOR = {
    "api": "\033[36m",
    "worker": "\033[35m",
    "ui": "\033[33m",
    "stack": "\033[32m",
}
RESET = "\033[0m"

# Lines that repeat on every launch and say nothing the operator can act on.
# They stay in logs/<service>.log, which keeps every byte; only the console
# skips them. A route warning used to print twice a minute on a LAN without a
# default route and drowned the warnings that did matter.
_NOISE = (
    "WARNING: Scapy has detected that your pcap service is not running",
    "WARNING: [SC] StartService FAILED",
    "The service cannot be started, either because it is disabled",
    "WARNING: Could not start the pcap service!",
    "No route found for IPv4 destination",
    "A new release of pip is available",
    "To update, run: python.exe -m pip install",
)

# Celery draws an ASCII banner on every start: twelve lines that name the host,
# the transport and the pool, all of which this launcher already printed two
# lines above. The shapes are unusual enough to match safely; a real warning
# from the worker never contains this punctuation.
_CELERY_BANNER_PREFIXES = (
    "-------------- celery@",
    "--- *****",
    "-- *******",
    "- *** ---",
    "- ** ----------",
    "-------------- [queues]",
    "-------------- .>",
    ".> ",
)


def _is_noise(line: str) -> bool:
    if any(marker in line for marker in _NOISE):
        return True
    text = line.strip()
    return any(text.startswith(prefix) for prefix in _CELERY_BANNER_PREFIXES)

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


# ---------------------------------------------------------------------------
# Single instance
# ---------------------------------------------------------------------------


def _pid_alive(pid: int) -> bool:
    """True when a process with this id exists. Never raises."""
    if pid <= 0:
        return False
    if os.name == "nt":
        completed = subprocess.run(
            ["tasklist", "/FI", f"PID eq {pid}", "/NH"],
            capture_output=True,
            text=True,
            check=False,
        )
        return str(pid) in (completed.stdout or "")
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        # Exists, owned by someone else.
        return True
    return True


def _running_stack_pid() -> int | None:
    """The pid recorded by a previous launch, if that process still exists."""
    try:
        raw = LOCK_PATH.read_text(encoding="utf-8").strip().splitlines()[0]
        pid = int(raw)
    except (FileNotFoundError, IndexError, ValueError, OSError):
        return None

    if pid == os.getpid():
        return None
    return pid if _pid_alive(pid) else None


def _write_lock() -> None:
    RUN_DIR.mkdir(parents=True, exist_ok=True)
    LOCK_PATH.write_text(f"{os.getpid()}\n", encoding="utf-8")


def _clear_lock() -> None:
    try:
        LOCK_PATH.unlink()
    except OSError:
        pass


def _stop_pid_tree(pid: int) -> None:
    """Stop a stack and every child it owns (uvicorn's reloader, Celery, Vite)."""
    if os.name == "nt":
        subprocess.run(
            ["taskkill", "/F", "/T", "/PID", str(pid)],
            capture_output=True,
            check=False,
        )
        return
    for sig in (signal.SIGTERM, signal.SIGKILL):
        try:
            os.killpg(os.getpgid(pid), sig)
        except ProcessLookupError:
            return
        except OSError:
            try:
                os.kill(pid, sig)
            except OSError:
                return
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if not _pid_alive(pid):
                return
            time.sleep(0.2)


def _pid_command_line(pid: int) -> str:
    """The command line of *pid*, or an empty string when it cannot be read."""
    if pid <= 0:
        return ""
    if os.name == "nt":
        try:
            completed = subprocess.run(
                [
                    "powershell", "-NoProfile", "-Command",
                    f"(Get-CimInstance Win32_Process -Filter 'ProcessId={pid}').CommandLine",
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            return (completed.stdout or "").strip()
        except Exception:
            return ""
    try:
        return Path(f"/proc/{pid}/cmdline").read_bytes().replace(b"\x00", b" ").decode(
            errors="replace"
        )
    except OSError:
        return ""


def _looks_like_netpulse(pid: int) -> bool:
    """True when the pid is one of *our* services, not an unrelated program."""
    command = _pid_command_line(pid).lower()
    if not command:
        return False
    markers = ("app.main:app", "netpulse", "celery", "vite", "stack.py")
    return any(marker in command for marker in markers)


def _port_owner(port: int) -> int | None:
    """Best-effort: which pid is listening on *port*, so the message can name it."""
    if os.name != "nt":
        return None
    completed = subprocess.run(
        ["netstat", "-ano", "-p", "TCP"], capture_output=True, text=True, check=False
    )
    for line in (completed.stdout or "").splitlines():
        parts = line.split()
        if len(parts) >= 5 and parts[0].upper() == "TCP" and parts[1].endswith(f":{port}"):
            if parts[3].upper() == "LISTENING" and parts[4].isdigit():
                return int(parts[4])
    return None


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
        # A service is allowed to repeat itself -- uvicorn does it on every
        # reload, the scheduler on every tick. Printing each copy is what made
        # the console unreadable, so identical consecutive lines are counted and
        # reported once, after the burst has finished.
        last_line = ""
        repeats = 0

        def flush_repeats() -> None:
            nonlocal repeats
            if repeats:
                emit(service.name, f"  ... previous line repeated {repeats}x")
                repeats = 0

        for raw in process.stdout:
            line = raw.rstrip("\n")
            log.write(line + "\n")
            log.flush()
            if not line.strip():
                continue
            if _is_noise(line):
                continue
            if line == last_line:
                repeats += 1
                continue
            flush_repeats()
            last_line = line
            emit(service.name, line)

        flush_repeats()

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


def _wait_for_api(timeout: float = 60.0) -> bool:
    """Block until the API answers its liveness probe (or the timeout).

    The dev server is started after this returns. Vite proxies /api from the
    first request it serves, so starting it before the API was listening printed
    a burst of ECONNREFUSED proxy errors on every single launch.
    """
    url = f"http://127.0.0.1:{API_PORT}/api/health/live"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not _stopping.is_set():
        try:
            with urllib.request.urlopen(url, timeout=2) as response:
                if response.status == 200:
                    return True
        except (urllib.error.URLError, OSError, ValueError):
            pass
        time.sleep(0.4)
    return False


def _print_summary(elapsed: float | None = None, *, ready: bool = True) -> None:
    """One compact block instead of a banner plus a line per service."""
    took = f" in {elapsed:.1f}s" if elapsed else ""
    headline = f"ready{took}" if ready else "still starting - the API has not answered yet"
    rows = [
        ("console", _ui_url()),
        ("api", f"http://localhost:{API_PORT}"),
        ("docs", f"http://localhost:{API_PORT}/docs"),
        ("logs", "logs/api.log | logs/worker.log | logs/ui.log"),
    ]
    width = max(len(label) for label, _ in rows)
    lines = ["", f"[stack ] {headline}"]
    lines += [f"[stack ]   {label:<{width}}  {value}" for label, value in rows]
    lines.append("[stack ]   Ctrl+C stops every service.")
    lines.append("")
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
        "--reload",
        # Watch the source only. Watching the project root made WatchFiles walk
        # node_modules, logs/ and data/ too, and on Windows the reloader can
        # wedge on that — after which edits silently stop restarting the API.
        "--reload-dir", "app",
        "--host", "0.0.0.0", "--port", str(API_PORT),
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


def describe(services: list[Service]) -> list[str]:
    """One readable line per service.

    The full argv was printed at launch, which meant three wrapped lines of
    paths before the first useful message. The command is still recoverable
    from the process table and from each log's header; what an operator wants
    here is what is running and where.
    """
    described: list[str] = []
    for service in services:
        if service.name == "api":
            described.append(f"api      uvicorn app.main on :{API_PORT} (reloads on save)")
        elif service.name == "worker":
            described.append("worker   celery, solo pool")
        elif service.name == "ui":
            described.append(f"ui       vite dev server on :{UI_PORT}")
        else:
            described.append(f"{service.name:<8} {' '.join(service.command)}")
    return described


def main() -> int:
    global _use_color

    parser = argparse.ArgumentParser(description="Run the NetPulse stack in one console.")
    parser.add_argument("--no-frontend", action="store_true", help="skip the Vite dev server")
    parser.add_argument("--no-worker", action="store_true", help="skip the Celery worker")
    parser.add_argument("--verbose", action="store_true", help="keep HTTP access logs and info-level worker logs")
    parser.add_argument("--replace", action="store_true", help="stop a stack that is already running, then start")
    parser.add_argument("--stop", action="store_true", help="stop the running stack and exit")
    args = parser.parse_args()

    _use_color = _enable_ansi()

    running = _running_stack_pid()

    if args.stop:
        if running is None:
            _clear_lock()
            emit("stack", "No NetPulse stack is running.")
            return 0
        emit("stack", f"Stopping the stack (pid {running})...")
        _stop_pid_tree(running)
        _clear_lock()
        emit("stack", "Stopped.")
        return 0

    if running is not None:
        if not args.replace:
            emit("stack", f"A NetPulse stack is already running (pid {running}).")
            emit("stack", "Starting a second one would double every sweep and counter.")
            emit("stack", "Stop it first with 'python scripts/stack.py --stop', or re-run with --replace.")
            return 1
        emit("stack", f"Stopping the previous stack (pid {running}) first...")
        _stop_pid_tree(running)
        _clear_lock()

    if _port_in_use(API_PORT):
        owner = _port_owner(API_PORT)
        if owner is not None and args.replace and _looks_like_netpulse(owner):
            # The pidfile was gone but a child survived the kill: exactly the
            # orphan that made a "clean restart" fail.
            emit("stack", f"Replacing a leftover NetPulse service holding port {API_PORT} (pid {owner}).")
            _stop_pid_tree(owner)
            time.sleep(1.0)

        if _port_in_use(API_PORT):
            owner = _port_owner(API_PORT)
            if owner is not None:
                emit("stack", f"Port {API_PORT} is held by pid {owner}, which this launcher does not own.")
                emit("stack", f"Stop it (taskkill /F /T /PID {owner}) and try again.")
            else:
                emit("stack", f"Port {API_PORT} is already in use - another NetPulse instance is running?")
                emit("stack", "Stop it (or the process holding the port) and try again.")
            return 1

    _write_lock()

    services = build_services(args.verbose, not args.no_worker, not args.no_frontend)
    backend = [service for service in services if service.name != "ui"]
    frontend = [service for service in services if service.name == "ui"]

    started = time.monotonic()
    emit("stack", "NetPulse starting")
    for service in describe(services):
        emit("stack", f"  {service}")

    processes: list[tuple[Service, subprocess.Popen[str]]] = []

    def _start_all(group: list[Service]) -> str | None:
        for service in group:
            try:
                processes.append((service, _start(service)))
            except Exception as exc:
                return f"Could not start {service.name}: {exc}"
        return None

    failure = _start_all(backend)
    if failure:
        emit("stack", failure)
        _stop(processes)
        _clear_lock()
        return 1

    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, lambda *_: _shutdown(0))

    ready = _wait_for_api()
    if not ready and not _stopping.is_set():
        emit("stack", "The API is not answering - check logs/api.log")

    failure = _start_all(frontend)
    if failure:
        emit("stack", failure)
    elif frontend:
        # Wait for Vite's own "Local:" line so the summary prints the port it
        # actually bound (6969 is not guaranteed when something else holds it).
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and not _stopping.is_set():
            if "http://localhost:" in "".join(_tail(LOG_DIR / "ui.log", 40)):
                break
            time.sleep(0.3)

    _print_summary((time.monotonic() - started) if ready else None, ready=ready)

    try:
        while not _stopping.wait(0.5):
            pass
    except KeyboardInterrupt:
        _shutdown(0)
    finally:
        emit("stack", "Stopping services...")
        _stop(processes)
        _clear_lock()
        emit("stack", "All services stopped.")

    return _exit_code


if __name__ == "__main__":
    raise SystemExit(main())
