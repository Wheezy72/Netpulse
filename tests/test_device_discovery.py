"""Unit tests for the discovery-only scan path.

Covers the pieces that decide *what* gets reported — MAC/OUI resolution, the
type/OS heuristics, the python-nmap parsing, and the policy guards — none of
which need scapy, nmap, or a database.
"""
from __future__ import annotations

import os

import pytest

# app.core.config reads these at import time. conftest sets the same values, but
# that fixture runs after module import, so set them here too.
os.environ.setdefault("SECRET_KEY", "test-secret-key-for-ci")
os.environ.setdefault("DATABASE_URL", "postgresql+asyncpg://netpulse:netpulse@localhost:5432/netpulse")
os.environ.setdefault("REDIS_URL", "redis://localhost:6379/0")
os.environ.setdefault("ENVIRONMENT", "development")

import app.services.device_discovery as discovery  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.services.device_discovery import (  # noqa: E402
    classify_host,
    hosts_from_arp_pairs,
    hosts_from_scan_data,
    run_device_discovery,
)
from app.services.oui import (  # noqa: E402
    is_locally_administered,
    lookup_vendor,
    normalize_mac,
    oui_prefix,
)
from app.services.scan_policy import (  # noqa: E402
    is_restricted_target,
    subnets_to_sweep,
    validate_target,
)


class TestMacNormalisation:
    def test_accepts_common_separators(self) -> None:
        assert normalize_mac("00:1A:2B:3C:4D:5E") == "001A2B3C4D5E"
        assert normalize_mac("00-1a-2b-3c-4d-5e") == "001A2B3C4D5E"
        assert normalize_mac("001a.2b3c.4d5e") == "001A2B3C4D5E"
        assert normalize_mac("001a2b3c4d5e") == "001A2B3C4D5E"

    def test_rejects_unusable_input(self) -> None:
        assert normalize_mac(None) is None
        assert normalize_mac("") is None
        assert normalize_mac("00:1A:2B") is None  # too short
        assert normalize_mac("ZZ:1A:2B:3C:4D:5E") is None  # not hex

    def test_oui_prefix(self) -> None:
        assert oui_prefix("00:1A:2B:3C:4D:5E") == "001A2B"
        assert oui_prefix("nonsense") is None


class TestVendorLookup:
    def test_known_prefixes(self) -> None:
        assert lookup_vendor("B8:27:EB:11:22:33") == "Raspberry Pi"
        assert lookup_vendor("00:0C:29:AA:BB:CC") == "VMware"

    def test_unknown_and_invalid(self) -> None:
        assert lookup_vendor("02:00:00:00:00:01") is None
        assert lookup_vendor(None) is None

    def test_locally_administered_mac_has_no_vendor(self) -> None:
        # Bit 1 of the first octet set → randomised MAC. "02", "3A", "DA", "EA"
        # all carry it, and their OUI is not a real vendor prefix.
        assert lookup_vendor("02:00:00:00:00:01") is None
        assert lookup_vendor("3A:11:22:33:44:55") is None
        assert lookup_vendor("EA:11:22:33:44:55") is None


class TestClassifyHost:
    def test_gateway_always_wins(self) -> None:
        assert classify_host(None, None, is_gateway=True) == ("Router", "Linux/Embedded")

    def test_hostname_and_vendor_signals(self) -> None:
        assert classify_host("core-switch-1", None)[0] == "Switch (Cisco)"
        assert classify_host("printer-2f", None)[0] == "Printer"
        # Model names, not just the literal word "printer".
        assert classify_host("HP-LaserJet-4", None)[0] == "Printer"
        assert classify_host("nas-01", None)[0] == "NAS"
        assert classify_host("living-room-tv", None)[0] == "Smart TV"
        assert classify_host("Janes-iPhone", None)[0] == "Phone/Tablet (Apple)"

    def test_unknown_host_is_not_guessed(self) -> None:
        # The old heuristic labelled every unrecognised host "Linux Workstation",
        # which is a confident claim with nothing behind it.
        assert classify_host(None, None) == (None, None)
        assert classify_host("somehost", "SomeVendor") == (None, None)

    def test_vendor_only_does_not_claim_an_os(self) -> None:
        device_type, os_label = classify_host(None, "Intel")
        assert device_type == "Windows Workstation"
        assert os_label is None

    def test_randomised_mac_vendor_is_distrusted(self) -> None:
        # A randomised MAC whose vendor collided with "HP" must not be called a
        # Windows workstation — the vendor string is not trustworthy here.
        assert classify_host(None, "HP", mac_address="3A:00:00:00:00:01") == (None, None)

    def test_randomised_mac_still_honours_hostname(self) -> None:
        # Explicit hostname evidence is still trusted on a randomised MAC.
        assert classify_host("Janes-iPhone", "HP", mac_address="3A:00:00:00:00:01")[0] == (
            "Phone/Tablet (Apple)"
        )


class TestHostsFromScanData:
    def test_parses_addresses_hostnames_and_vendor(self) -> None:
        scan_data = {
            "192.168.1.1": {
                "status": {"state": "up"},
                "addresses": {"ipv4": "192.168.1.1", "mac": "B8:27:EB:11:22:33"},
                "hostnames": [{"name": "pi.hole", "type": "PTR"}],
                "vendor": {},
            }
        }
        hosts = hosts_from_scan_data(scan_data)
        assert len(hosts) == 1
        host = hosts[0]
        assert host.ip_address == "192.168.1.1"
        assert host.mac_address == "B827EB112233"
        assert host.hostname == "pi.hole"
        assert host.vendor == "Raspberry Pi"  # filled from the OUI table
        assert host.source == "nmap"

    def test_skips_down_hosts_and_junk_entries(self) -> None:
        scan_data = {
            "10.0.0.9": {"status": {"state": "down"}, "addresses": {"ipv4": "10.0.0.9"}},
            "10.0.0.10": "not-a-dict",
        }
        assert hosts_from_scan_data(scan_data) == []

    def test_prefers_reported_vendor_over_oui_table(self) -> None:
        scan_data = {
            "10.0.0.5": {
                "status": {"state": "up"},
                "addresses": {"ipv4": "10.0.0.5", "mac": "00:11:22:33:44:55"},
                "hostnames": [],
                "vendor": {"00:11:22:33:44:55": "Cisco Systems"},
            }
        }
        assert hosts_from_scan_data(scan_data)[0].vendor == "Cisco Systems"

    def test_empty_input(self) -> None:
        assert hosts_from_scan_data({}) == []


class TestHostsFromArpPairs:
    def test_deduplicates_by_address(self) -> None:
        hosts = hosts_from_arp_pairs(
            [("10.0.0.1", "00:11:22:33:44:55"), ("10.0.0.1", "00:11:22:33:44:55")]
        )
        assert len(hosts) == 1
        assert hosts[0].source == "arp"

    def test_ignores_missing_address(self) -> None:
        assert hosts_from_arp_pairs([("", "00:11:22:33:44:55")]) == []


class TestTargetPolicy:
    def test_validate_target(self) -> None:
        assert validate_target("192.168.1.0/24") is True
        assert validate_target("example.com") is True
        assert validate_target("") is False
        assert validate_target("-sS") is False
        assert validate_target("10.0.0.1; rm -rf /") is False

    def test_restricted_cidrs_block_targets(self, monkeypatch) -> None:
        monkeypatch.setattr(settings, "restricted_vlan_cidrs", ["10.20.0.0/16"])
        monkeypatch.setattr(settings, "medical_iot_vlan_cidrs", [])

        assert is_restricted_target("10.20.5.5") is True
        assert is_restricted_target("10.20.0.0/24") is True
        assert is_restricted_target("10.21.0.1") is False
        # Hostnames cannot be classified statically.
        assert is_restricted_target("printer.local") is False

    def test_legacy_setting_still_honoured(self, monkeypatch) -> None:
        monkeypatch.setattr(settings, "restricted_vlan_cidrs", [])
        monkeypatch.setattr(settings, "medical_iot_vlan_cidrs", ["192.168.50.0/24"])
        assert is_restricted_target("192.168.50.10") is True

    def test_subnets_to_sweep_filters_and_skips_restricted(self, monkeypatch) -> None:
        monkeypatch.setattr(settings, "restricted_vlan_cidrs", ["10.20.0.0/16"])
        monkeypatch.setattr(settings, "medical_iot_vlan_cidrs", [])

        result = subnets_to_sweep(["192.168.1.0/24", "10.0.0.0/8", "10.20.1.0/24", "garbage"])
        assert result == ["192.168.1.0/24"]


class TestRunDeviceDiscoveryGuards:
    async def test_rejects_invalid_target(self) -> None:
        with pytest.raises(ValueError):
            await run_device_discovery(None, target="10.0.0.1; ls", persist=False)

    async def test_restricted_target_is_refused_without_probing(self, monkeypatch) -> None:
        monkeypatch.setattr(settings, "restricted_vlan_cidrs", ["10.20.0.0/16"])
        monkeypatch.setattr(settings, "medical_iot_vlan_cidrs", [])

        def _must_not_run(*_args, **_kwargs):
            raise AssertionError("restricted target must never be probed")

        monkeypatch.setattr(discovery, "arp_sweep", _must_not_run)

        outcome = await run_device_discovery(None, target="10.20.7.7", persist=False)
        assert outcome.hosts == []
        assert outcome.skipped_restricted == ["10.20.7.7"]
        assert outcome.created == 0

    async def test_missing_tooling_is_reported_not_raised(self, monkeypatch) -> None:
        def _no_raw_sockets(*_args, **_kwargs):
            raise OSError("raw sockets unavailable")

        monkeypatch.setattr(discovery, "arp_sweep", _no_raw_sockets)
        monkeypatch.setattr(discovery, "nmap_available", lambda: False)

        outcome = await run_device_discovery(None, target="192.0.2.10", persist=False)
        assert outcome.hosts == []
        assert outcome.warnings, "an empty sweep must explain why it was empty"
        assert "nmap" in outcome.warnings[0]

    async def test_concurrent_run_is_refused(self) -> None:
        async with discovery._discovery_lock:
            outcome = await run_device_discovery(None, target="192.0.2.10", persist=False)
        assert outcome.hosts == []
        assert "already in progress" in outcome.warnings[0]
