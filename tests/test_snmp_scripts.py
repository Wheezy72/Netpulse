"""The SNMP prebuilt scripts read through the in-repo client, not pysnmp.

Both scripts used to import pysnmp, which this project does not depend on, so
they raised ImportError the first time anyone ran them from the UI. They now
walk through app.services.snmp_client. These tests pin the parsing that
replaced the old pysnmp calls: the ARP table join (which must pair a MAC with
the address that shares its table index), the refusal to invent a MAC for an
all-zeroes entry, and the different error handling each script promises.

Because a router is not available in CI, the walk itself is faked — the same
approach test_snmp_client.py takes for the wire encoding.
"""
from __future__ import annotations

import importlib.util
import os
from pathlib import Path
from typing import Any, List, Tuple

import pytest

# app.core.config reads these at import time; conftest runs too late for that.
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://netpulse:netpulse@localhost:5432/netpulse")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("ENVIRONMENT", "development")

from app.services import snmp_client  # noqa: E402

SCRIPTS = Path(__file__).resolve().parent.parent / "scripts" / "prebuilt"

PHYS_ROOT = "1.3.6.1.2.1.4.22.1.2"
NET_ROOT = "1.3.6.1.2.1.4.22.1.3"
CDP_ROOT = "1.3.6.1.4.1.9.9.23.1.2.1.1.4"


def load_script(name: str):
    """Import a prebuilt script by path; scripts/ is not a package."""
    spec = importlib.util.spec_from_file_location(f"prebuilt_{name}", SCRIPTS / f"{name}.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def arp_script():
    return load_script("snmp_arp_discovery")


@pytest.fixture(scope="module")
def topology_script():
    return load_script("snmp_topology_discovery")


def fake_walk(
    phys: List[Tuple[str, Any]],
    net: List[Tuple[str, Any]],
    calls: List[dict],
):
    """Serve the ARP columns (and nothing else) from canned varbinds."""

    def walk(host: str, oid: str, **kwargs: Any) -> List[Tuple[str, Any]]:
        calls.append({"host": host, "oid": oid, **kwargs})
        if oid == PHYS_ROOT:
            return phys
        if oid == NET_ROOT:
            return net
        return []

    return walk


class TestArpDiscovery:
    def _walk(self, arp_script, monkeypatch, phys, net):
        calls: List[dict] = []
        monkeypatch.setattr(snmp_client, "walk", fake_walk(phys, net, calls))
        return arp_script._walk_arp_table("192.168.1.1", "s3cret"), calls

    def test_pairs_each_mac_with_its_own_address(self, arp_script, monkeypatch) -> None:
        phys = [
            (f"{PHYS_ROOT}.1.192.168.1.50", bytes.fromhex("aabbccddeeff")),
            (f"{PHYS_ROOT}.1.192.168.1.51", bytes.fromhex("112233445566")),
        ]
        net = [
            (f"{NET_ROOT}.1.192.168.1.50", bytes([192, 168, 1, 50])),
            (f"{NET_ROOT}.1.192.168.1.51", bytes([192, 168, 1, 51])),
        ]

        entries, _ = self._walk(arp_script, monkeypatch, phys, net)

        assert entries == [
            ("192.168.1.50", "AABBCCDDEEFF"),
            ("192.168.1.51", "112233445566"),
        ]

    def test_address_containing_the_oid_fragment_still_pairs(self, arp_script, monkeypatch) -> None:
        # The old code split each OID on ".1.2." / ".1.3." and kept the tail,
        # so an address like 10.0.2.15 produced keys that no longer matched and
        # the entry silently vanished from the inventory.
        phys = [(f"{PHYS_ROOT}.1.10.0.2.15", bytes.fromhex("deadbeef0001"))]
        net = [(f"{NET_ROOT}.1.10.0.2.15", bytes([10, 0, 2, 15]))]

        entries, _ = self._walk(arp_script, monkeypatch, phys, net)

        assert entries == [("10.0.2.15", "DEADBEEF0001")]

    def test_all_zeroes_mac_is_not_invented(self, arp_script, monkeypatch) -> None:
        phys = [
            (f"{PHYS_ROOT}.1.192.168.1.50", bytes.fromhex("aabbccddeeff")),
            (f"{PHYS_ROOT}.1.192.168.1.77", bytes(6)),  # empty table slot
        ]
        net = [
            (f"{NET_ROOT}.1.192.168.1.50", bytes([192, 168, 1, 50])),
            (f"{NET_ROOT}.1.192.168.1.77", bytes([192, 168, 1, 77])),
        ]

        entries, _ = self._walk(arp_script, monkeypatch, phys, net)

        assert entries == [("192.168.1.50", "AABBCCDDEEFF")]

    def test_address_without_a_mac_is_dropped(self, arp_script, monkeypatch) -> None:
        phys = [(f"{PHYS_ROOT}.1.192.168.1.51", bytes.fromhex("112233445566"))]
        net = [
            (f"{NET_ROOT}.1.192.168.1.50", bytes([192, 168, 1, 50])),
            (f"{NET_ROOT}.1.192.168.1.51", bytes([192, 168, 1, 51])),
        ]

        entries, _ = self._walk(arp_script, monkeypatch, phys, net)

        assert entries == [("192.168.1.51", "112233445566")]

    def test_community_and_timeout_reach_the_client(self, arp_script, monkeypatch) -> None:
        _, calls = self._walk(arp_script, monkeypatch, [], [])

        assert [call["oid"] for call in calls] == [PHYS_ROOT, NET_ROOT]
        assert all(call["host"] == "192.168.1.1" for call in calls)
        assert all(call["community"] == "s3cret" for call in calls)
        assert all(call["timeout"] == 2 for call in calls)

    def test_unreachable_agent_raises_rather_than_reporting_an_empty_table(
        self, arp_script, monkeypatch
    ) -> None:
        def walk(host: str, oid: str, **kwargs: Any):
            raise snmp_client.SnmpError(f"SNMP {host}:161 did not answer within the timeout.")

        monkeypatch.setattr(snmp_client, "walk", walk)

        with pytest.raises(snmp_client.SnmpError):
            arp_script._walk_arp_table("192.168.1.9", "public")


class TestTopologyDiscovery:
    def test_walk_returns_what_the_client_returned(self, topology_script, monkeypatch) -> None:
        varbinds = [(f"{CDP_ROOT}.1", bytes([10, 0, 0, 5]))]
        seen: List[str] = []

        def walk(host: str, oid: str, **kwargs: Any):
            seen.append(oid)
            return varbinds

        monkeypatch.setattr(snmp_client, "walk", walk)

        assert topology_script._snmp_walk("192.168.1.1", "public", CDP_ROOT) == varbinds
        assert seen == [CDP_ROOT]

    def test_unreachable_agent_yields_no_links(self, topology_script, monkeypatch) -> None:
        # A switch with SNMP off must not abort the sweep of the others.
        def walk(host: str, oid: str, **kwargs: Any):
            raise snmp_client.SnmpError("no reply")

        monkeypatch.setattr(snmp_client, "walk", walk)

        assert topology_script._snmp_walk("192.168.1.9", "public", CDP_ROOT) == []

    def test_neighbour_address_is_decoded(self, topology_script) -> None:
        assert topology_script._ip_bytes_to_str(bytes([10, 0, 0, 5])) == "10.0.0.5"
        assert topology_script._ip_bytes_to_str("192.168.1.20") == "192.168.1.20"

    def test_junk_neighbour_value_is_rejected(self, topology_script) -> None:
        assert topology_script._ip_bytes_to_str(b"\x01\x02") is None
        assert topology_script._ip_bytes_to_str(object()) is None


@pytest.mark.parametrize("name", ["snmp_arp_discovery", "snmp_topology_discovery"])
def test_scripts_do_not_depend_on_pysnmp(name: str) -> None:
    """pysnmp is not a dependency: its 4.x API needs a module Python 3.13 dropped."""
    source = (SCRIPTS / f"{name}.py").read_text(encoding="utf-8")

    assert "import pysnmp" not in source
    assert "from pysnmp" not in source
