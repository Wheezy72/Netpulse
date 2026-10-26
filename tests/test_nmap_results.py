"""Parsing of nmap's text output, and the child-process helper behind it.

The parser is what makes a finished scan readable after the page is closed; the
process helper is what keeps nmap runnable on Windows, where uvicorn's reload
loop has no subprocess support.
"""
from __future__ import annotations

import asyncio
import os
import sys

import pytest

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://netpulse:netpulse@localhost:5432/netpulse")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("ENVIRONMENT", "development")

from app.services.nmap_results import parse_nmap_text  # noqa: E402

SAMPLE = """\
Starting Nmap 7.94 ( https://nmap.org ) at 2026-10-26 05:21 UTC
Nmap scan report for 192.168.1.1
Host is up (0.0021s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE VERSION
22/tcp  open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0)
80/tcp  open  http    lighttpd 1.4.59
MAC Address: 8C:44:BB:07:6C:10 (Unknown)

Nmap scan report for 192.168.1.55
Host is up (0.011s latency).
All 1000 scanned ports on 192.168.1.55 are in ignored states.
MAC Address: 0A:58:A9:FE:AC:02 (Unknown)

Nmap scan report for 192.168.1.99
Host is down.

Nmap done: 256 IP addresses (2 hosts up) scanned in 12.34 seconds
"""


class TestParseNmapText:
    def test_reads_hosts_ports_and_services(self) -> None:
        findings = parse_nmap_text(SAMPLE)

        assert findings["hosts_up"] == 2
        assert findings["hosts_total"] == 256
        assert findings["open_ports"] == 2
        assert findings["scan_seconds"] == pytest.approx(12.34)

        hosts = {host["address"]: host for host in findings["hosts"]}
        assert set(hosts) == {"192.168.1.1", "192.168.1.55"}  # the down host is dropped

        gateway = hosts["192.168.1.1"]
        assert gateway["state"] == "up"
        assert gateway["latency_ms"] == pytest.approx(2.1)
        assert gateway["mac_address"] == "8C:44:BB:07:6C:10"
        assert gateway["open_ports"] == 2
        assert [port["port"] for port in gateway["ports"]] == [22, 80]
        assert gateway["ports"][0]["service"] == "ssh"
        assert "8.9p1" in gateway["ports"][0]["version"]

    def test_sorts_hosts_by_open_ports(self) -> None:
        findings = parse_nmap_text(SAMPLE)
        assert findings["hosts"][0]["address"] == "192.168.1.1"

    def test_named_host_keeps_both_address_and_name(self) -> None:
        findings = parse_nmap_text(
            "Nmap scan report for router.lan (192.168.1.1)\n"
            "Host is up.\n"
            "PORT   STATE SERVICE\n"
            "53/udp open  domain\n"
        )
        host = findings["hosts"][0]
        assert host["address"] == "192.168.1.1"
        assert host["hostname"] == "router.lan"
        assert host["ports"][0]["protocol"] == "udp"

    def test_unparseable_output_is_not_an_exception(self) -> None:
        findings = parse_nmap_text("Scan aborted: nmap is not installed on this host.")
        assert findings["hosts"] == []
        assert findings["hosts_up"] == 0

    def test_empty_output(self) -> None:
        assert parse_nmap_text("")["hosts"] == []


class TestChildProcess:
    async def test_streams_output_then_signals_eof(self) -> None:
        from app.services.proc import EOF, ChildProcess

        child = ChildProcess(
            [sys.executable, "-c", "print('first'); print('second')"],
            stream=True,
            merge_stderr=True,
        )
        seen: list[str] = []
        while True:
            line = await child.lines.get()
            if line is EOF:
                break
            seen.append(line.strip())
        assert await child.wait() == 0
        await child.drain()
        assert seen == ["first", "second"]

    async def test_captures_stdout_and_stderr_separately(self) -> None:
        from app.services.proc import run_captured

        code, out, err = await run_captured(
            [sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr)"],
            timeout=30,
        )
        assert code == 0
        assert out.strip() == "out"
        assert err.strip() == "err"

    async def test_timeout_kills_the_child(self) -> None:
        from app.services.proc import run_captured

        with pytest.raises(TimeoutError):
            await run_captured(
                [sys.executable, "-c", "import time; time.sleep(30)"], timeout=0.5
            )

    async def test_missing_binary_raises_oserror(self) -> None:
        from app.services.proc import ChildProcess

        with pytest.raises(OSError):
            ChildProcess(["definitely-not-a-real-binary-netpulse"])

    def test_works_on_a_loop_without_subprocess_support(self) -> None:
        """The whole point: the helper works where asyncio's API does not.

        uvicorn --reload installs a SelectorEventLoop on Windows, where
        asyncio.create_subprocess_exec raises NotImplementedError. Running the
        helper on that loop is the regression test for the original crash.
        """
        if sys.platform != "win32":
            pytest.skip("SelectorEventLoop can spawn subprocesses off Windows")

        from app.services.proc import run_captured

        loop = asyncio.SelectorEventLoop()
        try:
            with pytest.raises(NotImplementedError):
                loop.run_until_complete(
                    asyncio.wait_for(
                        loop.subprocess_exec(asyncio.SubprocessProtocol, "cmd", "/c", "echo"),
                        timeout=5,
                    )
                )
            code, out, _ = loop.run_until_complete(
                run_captured([sys.executable, "-c", "print('alive')"], timeout=30)
            )
        finally:
            loop.close()
        assert (code, out.strip()) == (0, "alive")
