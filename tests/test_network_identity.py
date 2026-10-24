"""Unit tests for network identity.

Home networks reuse the same addresses, so the fingerprint that separates two
of them is the subnet plus the gateway's MAC. These tests pin that rule and the
parsing of the OS neighbour tables — none of it needs a real network or a
database.
"""
from __future__ import annotations

import os
import sys

import pytest

# app.core.config reads these at import time; conftest runs too late for that.
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://netpulse:netpulse@localhost:5432/netpulse")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("ENVIRONMENT", "development")

import app.services.device_discovery as _discovery  # noqa: E402
import app.services.network_identity as identity  # noqa: E402


def profile(**overrides) -> identity.NetworkProfile:
    values = {
        "cidr": "192.168.1.0/24",
        "gateway_ip": "192.168.1.1",
        "gateway_mac": None,
        "interface": None,
    }
    values.update(overrides)
    return identity.NetworkProfile(**values)


class TestFingerprint:
    def test_same_router_is_the_same_network(self) -> None:
        first = profile(gateway_mac="aabbccddeeff", interface="wlan0")
        second = profile(gateway_mac="AABBCCDDEEFF", interface="eth0")
        assert first.key == second.key

    def test_different_router_mac_is_a_different_network(self) -> None:
        # Same subnet and same gateway IP: only the hardware address separates
        # five homes that all run 192.168.1.0/24.
        first = profile(gateway_mac="AABBCCDDEEFF")
        second = profile(gateway_mac="112233445566")
        assert first.key != second.key

    def test_different_subnet_is_a_different_network(self) -> None:
        assert profile(gateway_mac="AABBCCDDEEFF").key != profile(
            cidr="10.0.0.0/24", gateway_mac="AABBCCDDEEFF"
        ).key

    def test_unknown_mac_still_identifies_by_subnet(self) -> None:
        assert profile().key == "192.168.1.0/24|-"


class TestDefaultName:
    def test_known_vendor_names_the_router(self) -> None:
        assert "Raspberry Pi" in profile(gateway_mac="B827EB112233").default_name

    def test_unknown_vendor_falls_back_to_the_subnet(self) -> None:
        # Locally administered MACs have no vendor; the subnet is the label.
        assert profile(gateway_mac="020000000001").default_name == "192.168.1.0/24"

    def test_missing_subnet_falls_back_to_the_gateway(self) -> None:
        assert profile(cidr="", gateway_ip="10.1.2.1").default_name == "10.1.2.1"


class TestMacFormatting:
    def test_compact_mac_is_rendered_for_the_ui(self) -> None:
        assert identity.format_mac("AABBCCDDEEFF") == "aa:bb:cc:dd:ee:ff"

    def test_empty_stays_empty(self) -> None:
        assert identity.format_mac(None) is None
        assert identity.format_mac("") is None


class TestNeighbourTable:
    def test_linux_ip_neigh_output(self, monkeypatch) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(
            identity,
            "_run",
            lambda command: "192.168.1.1 dev wlan0 lladdr 8C:44:BB:07:6C:10 REACHABLE",
        )
        assert identity._neighbour_mac("192.168.1.1") == "8C44BB076C10"

    def test_windows_arp_output(self, monkeypatch) -> None:
        monkeypatch.setattr(sys, "platform", "win32")
        monkeypatch.setattr(
            identity,
            "_run",
            lambda command: "  192.168.1.1           8c-44-bb-07-6c-10     dynamic",
        )
        assert identity._neighbour_mac("192.168.1.1") == "8C44BB076C10"

    def test_unresolved_neighbour_has_no_mac(self, monkeypatch) -> None:
        monkeypatch.setattr(sys, "platform", "linux")
        monkeypatch.setattr(
            identity,
            "_run",
            lambda command: "192.168.1.1 dev wlan0 FAILED",
        )
        assert identity._neighbour_mac("192.168.1.1") is None


class TestProfileDetection:
    def test_uses_the_subnet_that_contains_the_gateway(self, monkeypatch) -> None:
        # A container bridge and the LAN are both attached; the gateway says
        # which one is the network in use.
        monkeypatch.setattr(
            identity,
            "_attached_subnets",
            lambda: (["172.17.0.0/16", "10.0.0.0/24"], "eth0"),
        )
        monkeypatch.setattr(identity, "detect_gateway_ip", lambda: "10.0.0.1")
        monkeypatch.setattr(identity, "_neighbour_mac", lambda ip: "AABBCCDDEEFF")

        detected = identity.detect_profile()

        assert detected is not None
        assert detected.cidr == "10.0.0.0/24"
        assert detected.interface == "eth0"
        assert detected.key == "10.0.0.0/24|AABBCCDDEEFF"

    def test_nothing_attached_means_no_network(self, monkeypatch) -> None:
        monkeypatch.setattr(identity, "_attached_subnets", lambda: ([], None))
        monkeypatch.setattr(identity, "detect_gateway_ip", lambda: None)
        assert identity.detect_profile() is None

    def test_profile_is_cached_between_calls(self, monkeypatch) -> None:
        calls: list[int] = []

        def fake_detect():
            calls.append(1)
            return profile()

        monkeypatch.setattr(identity, "detect_profile", fake_detect)
        identity.invalidate_cache()
        try:
            identity.current_profile()
            identity.current_profile()
            assert len(calls) == 1
            identity.current_profile(refresh=True)
            assert len(calls) == 2
        finally:
            identity.invalidate_cache()


class TestDiscoverySignature:
    def test_upsert_accepts_a_network_scope(self) -> None:
        """The inventory merge is per network; the keyword must stay accepted."""
        import inspect

        parameters = inspect.signature(_discovery.upsert_discovered_hosts).parameters
        assert "network_id" in parameters
        assert parameters["network_id"].default is None
