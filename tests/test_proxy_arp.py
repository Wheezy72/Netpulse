"""Proxy-ARP collapsing in discovery.

A router that answers ARP on behalf of addresses it cannot reach (proxy ARP, or
a paid Wi-Fi network with a captive portal) makes a whole /24 look populated,
every address carrying the same MAC. Recorded naively that is 255 devices in
the inventory, all of them the same box.
"""
from __future__ import annotations

import os

os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://netpulse:netpulse@localhost:5432/netpulse")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("ENVIRONMENT", "development")

from app.services.device_discovery import collapse_proxy_arp  # noqa: E402

GATEWAY_MAC = "8C:44:BB:07:6C:10"


class TestCollapseProxyArp:
    def test_one_mac_answering_for_a_subnet_becomes_one_host(self) -> None:
        pairs = [(f"192.168.1.{n}", GATEWAY_MAC) for n in range(1, 255)]

        assert collapse_proxy_arp(pairs) == [("192.168.1.1", GATEWAY_MAC)]

    def test_keeps_the_lowest_address_of_the_shared_mac(self) -> None:
        pairs = [
            ("192.168.1.40", GATEWAY_MAC),
            ("192.168.1.1", GATEWAY_MAC),
            ("192.168.1.9", GATEWAY_MAC),
        ]

        assert len([p for p in pairs]) == 3
        assert collapse_proxy_arp(pairs, limit=1) == [("192.168.1.1", GATEWAY_MAC)]

    def test_a_real_network_passes_through_untouched(self) -> None:
        pairs = [
            ("192.168.1.1", "8C:44:BB:07:6C:10"),
            ("192.168.1.20", "D8:3A:DD:11:22:33"),
            ("192.168.1.21", "00:1A:79:AA:BB:CC"),
        ]

        assert collapse_proxy_arp(pairs) == pairs

    def test_a_host_with_a_few_addresses_survives(self) -> None:
        # NAT hosts and VMs legitimately hold several addresses below the limit.
        pairs = [(f"10.0.0.{n}", "AA:BB:CC:DD:EE:FF") for n in range(1, 9)]

        assert collapse_proxy_arp(pairs) == pairs

    def test_unrelated_hosts_keep_their_order(self) -> None:
        pairs = [
            ("192.168.1.5", "D8:3A:DD:11:22:33"),
            ("192.168.1.6", GATEWAY_MAC),
            ("192.168.1.7", "00:1A:79:AA:BB:CC"),
            ("192.168.1.8", GATEWAY_MAC),
            ("192.168.1.9", GATEWAY_MAC),
        ]

        assert collapse_proxy_arp(pairs, limit=1) == [
            ("192.168.1.5", "D8:3A:DD:11:22:33"),
            ("192.168.1.6", GATEWAY_MAC),
            ("192.168.1.7", "00:1A:79:AA:BB:CC"),
        ]

    def test_empty_input(self) -> None:
        assert collapse_proxy_arp([]) == []
