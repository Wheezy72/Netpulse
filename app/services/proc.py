"""Spawn child processes from any event loop, on any platform.

``asyncio.create_subprocess_exec`` only exists where the running loop implements
subprocess transport. On Windows that means the Proactor loop; uvicorn installs
a ``SelectorEventLoop`` whenever it is started with ``--reload`` or more than one
worker (so Ctrl+C keeps working), and on that loop the call raises a bare
``NotImplementedError`` -- no message, no errno. NetPulse runs behind
``uvicorn --reload`` on Windows, so every feature that shells out (nmap scans,
script jobs, tcpdump captures) died there with an unhelpful traceback.

``ChildProcess`` sidesteps the whole question: it always starts the child with
:class:`subprocess.Popen` and pumps its output from daemon threads back onto the
event loop, so streaming behaves the same regardless of which loop is serving.
"""
from __future__ import annotations

import asyncio
import subprocess
import sys
import threading
from typing import Sequence

_IS_WINDOWS = sys.platform == "win32"

# Read from ChildProcess.lines to mean "the child closed this stream", the same
# way a StreamReader signals end of file.
EOF = None


class _NoTimeout:
    async def __aenter__(self) -> None:
        return None

    async def __aexit__(self, *_exc: object) -> bool:
        return False


class ChildProcess:
    """A ``Popen`` child whose output can be consumed from an event loop.

    ``lines`` receives stdout -- and stderr too when *merge_stderr* is set -- one
    line at a time while the child runs, followed by :data:`EOF`. When streaming
    is off, stdout is discarded and only stderr is kept, which is what the
    capture and script paths need to report failures.
    """

    def __init__(
        self,
        argv: Sequence[str],
        *,
        merge_stderr: bool = False,
        capture_stderr: bool = True,
        stream: bool = False,
        loop: asyncio.AbstractEventLoop | None = None,
    ) -> None:
        if not argv:
            raise ValueError("argv must not be empty")

        self.argv = list(argv)
        self._loop = loop or asyncio.get_running_loop()
        self._stream = stream
        self._lock = threading.Lock()
        self._pending = 0
        self._stderr_text = ""
        self.lines: asyncio.Queue[str | None] = asyncio.Queue()

        kwargs: dict[str, object] = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE if capture_stderr else subprocess.DEVNULL,
            "bufsize": 1,
            "text": True,
            "errors": "replace",
        }
        if merge_stderr and capture_stderr:
            kwargs["stderr"] = subprocess.STDOUT
        if _IS_WINDOWS:
            # Keep console flashes out of a desktop install's face.
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)

        self._stderr_sink: list[str] = []
        self._proc = subprocess.Popen(self.argv, **kwargs)  # noqa: S603 - argv list, never a shell

        self._threads: list[threading.Thread] = []
        if self._proc.stdout is not None:
            self._start_reader(self._proc.stdout, to_queue=stream)
        if self._proc.stderr is not None and not merge_stderr:
            self._start_reader(self._proc.stderr, to_queue=False)

        if not self._threads:
            self.lines.put_nowait(EOF)

    # -- output pumping ----------------------------------------------------
    def _start_reader(self, stream, *, to_queue: bool) -> None:
        self._pending += 1
        thread = threading.Thread(
            target=self._pump,
            args=(stream, to_queue),
            name=f"netpulse-child-{'out' if to_queue else 'err'}",
            daemon=True,
        )
        self._threads.append(thread)
        thread.start()

    def _pump(self, stream, to_queue: bool) -> None:
        buffer: list[str] = []
        try:
            for line in stream:
                if to_queue:
                    self._post(line)
                else:
                    buffer.append(line)
        except Exception:  # pragma: no cover - closed pipe during teardown
            pass
        finally:
            try:
                stream.close()
            except Exception:
                pass
            if not to_queue:
                with self._lock:
                    self._stderr_sink.extend(buffer)
            with self._lock:
                self._pending -= 1
                finished = self._pending == 0
            if finished:
                with self._lock:
                    self._stderr_text = "".join(self._stderr_sink)
                # Whichever reader finishes last announces the end, including
                # the stderr-only one, or a streamed consumer waits forever.
                self._post(EOF)

    def _post(self, item: str | None) -> None:
        try:
            self._loop.call_soon_threadsafe(self.lines.put_nowait, item)
        except RuntimeError:
            # The loop closed while the child was still talking; nobody is left
            # to read the line, so dropping it is correct.
            pass

    # -- Process-alike API -------------------------------------------------
    @property
    def pid(self) -> int:
        return self._proc.pid

    @property
    def returncode(self) -> int | None:
        return self._proc.returncode

    def poll(self) -> int | None:
        return self._proc.poll()

    def terminate(self) -> None:
        if self._proc.poll() is None:
            try:
                self._proc.terminate()
            except OSError:
                pass

    def kill(self) -> None:
        if self._proc.poll() is None:
            try:
                self._proc.kill()
            except OSError:
                pass

    async def wait(self) -> int:
        return await asyncio.to_thread(self._proc.wait)

    def stderr_text(self) -> str:
        """Everything the child has written to stderr so far."""
        with self._lock:
            if self._pending:
                return "".join(self._stderr_sink)
            return self._stderr_text

    async def drain(self) -> None:
        """Wait for the reader threads, then reap the child."""
        await asyncio.to_thread(self._join_readers)
        if self._proc.returncode is None:
            await self.wait()

    def _join_readers(self) -> None:
        current = threading.current_thread()
        for thread in self._threads:
            if thread is not current:
                thread.join(timeout=5)


async def run_captured(
    argv: Sequence[str],
    *,
    timeout: float | None = None,
) -> tuple[int | None, str, str]:
    """Run *argv* to completion and return ``(returncode, stdout, stderr)``.

    Raises :class:`TimeoutError` if *timeout* elapses first; the child is killed
    before the exception propagates.
    """
    child = ChildProcess(argv, stream=True, merge_stderr=False)
    output: list[str] = []
    try:
        async with (asyncio.timeout(timeout) if timeout else _NoTimeout()):
            while True:
                line = await child.lines.get()
                if line is EOF:
                    break
                output.append(line)
            returncode = await child.wait()
    except BaseException:
        child.kill()
        await child.drain()
        raise
    await child.drain()
    return returncode, "".join(output), child.stderr_text()
