"""Unit tests for nmap capability detection and scan planning.

No nmap binary or NSE scripts are required: each planner test builds an
NmapCapabilities value by hand, and the detector test stubs shutil.which.
"""
from __future__ import annotations

import re
from datetime import datetime

import pytest

from app.services import nmap_capabilities
from app.services.nmap_capabilities import (
    CATALOG_VERSION,
    VULN_SCRIPT_CATALOG,
    NmapCapabilities,
    NmapUnavailableError,
    available_profiles,
    detect_capabilities,
    plan_command,
)

TARGET = "192.0.2.10"
ALL_PROFILES = ["sweep", "quick", "services", "full", "vuln"]
SCAN_PROFILES = ["quick", "services", "full", "vuln"]


def _caps(
    *,
    available: bool = True,
    privileged: bool = True,
    vuln_scripts: tuple[str, ...] = (),
    script_categories: tuple[str, ...] = (),
) -> NmapCapabilities:
    return NmapCapabilities(
        available=available,
        version="7.95" if available else None,
        privileged=privileged,
        script_categories=frozenset(script_categories),
        vuln_scripts=vuln_scripts,
        scripts_dir="/usr/share/nmap/scripts",
        detected_at=datetime(2026, 10, 19, 12, 0, 0),
    )


# ── Scan type selection ──────────────────────────────────────────────────────


@pytest.mark.parametrize("profile", SCAN_PROFILES)
def test_privileged_uses_syn_scan(profile: str) -> None:
    plan = plan_command(profile, TARGET, _caps(privileged=True))
    assert "-sS" in plan.argv
    assert "-sT" not in plan.argv


@pytest.mark.parametrize("profile", SCAN_PROFILES)
def test_unprivileged_uses_connect_scan_and_notes_it(profile: str) -> None:
    plan = plan_command(profile, TARGET, _caps(privileged=False))
    assert "-sT" in plan.argv
    assert "-sS" not in plan.argv
    assert "--unprivileged" in plan.argv
    assert "-Pn" in plan.argv
    assert "No raw-socket privileges, using TCP connect scan" in plan.notes


def test_unprivileged_sweep_skips_raw_ping_flags() -> None:
    """A sweep without raw sockets must not ask nmap for raw ARP/ICMP."""
    plan = plan_command("sweep", TARGET, _caps(privileged=False))
    assert "-PE" not in plan.argv
    assert "-Pn" not in plan.argv  # -Pn would report every address as up
    assert "--unprivileged" in plan.argv
    assert plan.argv[-1] == TARGET


# ── Per-profile argv ─────────────────────────────────────────────────────────


def test_sweep_plan_is_discovery_only() -> None:
    plan = plan_command("sweep", TARGET, _caps())
    assert plan.argv == ["nmap", "-sn", "-PE", "-PS22,80,443", "-T4", TARGET]
    assert plan.notes == ["host discovery only"]


def test_quick_plan_uses_top_ports() -> None:
    plan = plan_command("quick", TARGET, _caps())
    assert plan.argv == ["nmap", "-sS", "-F", "--max-retries", "2", "-T4", TARGET]


def test_quick_plan_honours_explicit_ports() -> None:
    plan = plan_command("quick", TARGET, _caps(), ports="22,443")
    assert "-F" not in plan.argv
    assert plan.argv[plan.argv.index("-p") + 1] == "22,443"
    assert plan.argv[-1] == TARGET


def test_services_plan_uses_version_detection() -> None:
    plan = plan_command("services", TARGET, _caps())
    assert "-sV" in plan.argv
    assert "--version-light" in plan.argv
    assert "-F" in plan.argv
    assert "-T4" in plan.argv
    assert plan.argv[-1] == TARGET


def test_full_plan_scans_all_ports() -> None:
    plan = plan_command("full", TARGET, _caps())
    assert "-p-" in plan.argv
    assert plan.argv[plan.argv.index("--min-rate") + 1] == "1000"
    assert plan.argv[plan.argv.index("--max-retries") + 1] == "2"
    assert plan.argv[-1] == TARGET


def test_profile_is_case_insensitive() -> None:
    plan = plan_command("  QUICK ", TARGET, _caps())
    assert plan.profile == "quick"


# ── Vulnerability profile ────────────────────────────────────────────────────


def test_vuln_plan_uses_only_installed_catalog_scripts() -> None:
    plan = plan_command(
        "vuln",
        TARGET,
        _caps(
            vuln_scripts=("ssl-heartbleed", "smb-vuln-ms17-010", "not-a-catalog-script"),
            script_categories=("vuln",),
        ),
    )

    assert "--script" in plan.argv
    script_value = plan.argv[plan.argv.index("--script") + 1]
    assert script_value == "smb-vuln-ms17-010,ssl-heartbleed"
    assert plan.vuln_scripts == ["smb-vuln-ms17-010", "ssl-heartbleed"]
    assert all(name in VULN_SCRIPT_CATALOG for name in plan.vuln_scripts)
    assert plan.argv[-1] == TARGET


def test_vuln_plan_notes_catalog_version() -> None:
    plan = plan_command("vuln", TARGET, _caps(vuln_scripts=("ssl-heartbleed",)))
    assert any(CATALOG_VERSION in note for note in plan.notes)


def test_vuln_plan_falls_back_to_vuln_category() -> None:
    plan = plan_command("vuln", TARGET, _caps(script_categories=("safe", "vuln")))
    assert plan.argv[plan.argv.index("--script") + 1] == "vuln"
    assert plan.vuln_scripts == []


def test_vuln_plan_without_scripts_or_category_notes_unavailable() -> None:
    plan = plan_command("vuln", TARGET, _caps())
    assert "--script" not in plan.argv
    assert plan.vuln_scripts == []
    assert any("vuln" in note and "unavailable" in note for note in plan.notes)
    assert plan.argv[-1] == TARGET


# ── Contract and errors ─────────────────────────────────────────────────────


@pytest.mark.parametrize("profile", ALL_PROFILES)
def test_display_is_an_nmap_command_line_ending_in_target(profile: str) -> None:
    plan = plan_command(profile, TARGET, _caps())
    assert plan.argv[0] == "nmap"
    assert plan.display == " ".join(plan.argv)
    assert plan.display.startswith("nmap ")
    assert plan.argv[-1] == TARGET


def test_unknown_profile_raises_value_error() -> None:
    with pytest.raises(ValueError):
        plan_command("aggressive-ish", TARGET, _caps())


def test_unavailable_nmap_raises_nmap_unavailable_error() -> None:
    with pytest.raises(NmapUnavailableError):
        plan_command("quick", TARGET, _caps(available=False))


def test_available_profiles_lists_every_planner_profile() -> None:
    profiles = available_profiles()
    assert [profile["id"] for profile in profiles] == ALL_PROFILES
    for profile in profiles:
        assert profile["label"]
        assert profile["description"]


def test_catalog_is_versioned_and_well_formed() -> None:
    assert re.fullmatch(r"\d{4}\.\d{2}", CATALOG_VERSION)
    assert len(VULN_SCRIPT_CATALOG) >= 18
    for name, entry in VULN_SCRIPT_CATALOG.items():
        assert name
        assert set(entry) == {"cve", "summary"}
        assert entry["cve"] is None or entry["cve"].startswith("CVE-")


# ── Detection ───────────────────────────────────────────────────────────────


def test_detect_capabilities_without_nmap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(nmap_capabilities.shutil, "which", lambda _name: None)
    monkeypatch.setattr(nmap_capabilities, "_SCRIPTS_DIR_CANDIDATES", ())
    monkeypatch.setattr(nmap_capabilities, "_capabilities_cache", None)
    monkeypatch.setattr(nmap_capabilities, "_capabilities_cache_at", 0.0)

    caps = detect_capabilities(force=True)

    assert caps.available is False
    assert caps.version is None
    assert caps.vuln_scripts == ()
    assert caps.scripts_dir is None
    assert isinstance(caps.detected_at, datetime)


# ── Linux raw-socket privileges ─────────────────────────────────────────────


class TestLinuxRawSocketPrivileges:
    """Linux grants raw sockets by capability, not only by UID."""

    def test_process_cap_eff_net_raw_bit(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import io

        monkeypatch.setattr(
            nmap_capabilities,
            "open",
            lambda *_args, **_kwargs: io.StringIO("Name:\tpython3\nCapEff:\t0000000000002000\n"),
            raising=False,
        )
        assert nmap_capabilities._linux_process_has_cap_net_raw() is True

    def test_process_without_net_raw(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import io

        monkeypatch.setattr(
            nmap_capabilities,
            "open",
            lambda *_args, **_kwargs: io.StringIO("Name:\tpython3\nCapEff:\t0000000000000000\n"),
            raising=False,
        )
        assert nmap_capabilities._linux_process_has_cap_net_raw() is False

    @staticmethod
    def _file_caps(*, effective: bool = True, net_raw: bool = True) -> bytes:
        import struct

        magic = 0x02000000 | (0x1 if effective else 0x0)
        permitted_low = (1 << 13) if net_raw else 0
        return struct.pack("<IIII", magic, permitted_low, 0, 0)

    def test_setcap_binary_is_recognised(self, monkeypatch: pytest.MonkeyPatch) -> None:
        # setcap on nmap gives the child the capability even when we have none.
        monkeypatch.setattr(
            nmap_capabilities.os, "getxattr", lambda *_: self._file_caps(), raising=False
        )
        assert nmap_capabilities._linux_binary_has_cap_net_raw("/usr/bin/nmap") is True

    def test_binary_without_the_effective_flag_is_not_trusted(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(
            nmap_capabilities.os,
            "getxattr",
            lambda *_: self._file_caps(effective=False),
            raising=False,
        )
        assert nmap_capabilities._linux_binary_has_cap_net_raw("/usr/bin/nmap") is False

    def test_binary_without_net_raw(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            nmap_capabilities.os,
            "getxattr",
            lambda *_: self._file_caps(net_raw=False),
            raising=False,
        )
        assert nmap_capabilities._linux_binary_has_cap_net_raw("/usr/bin/nmap") is False

    def test_missing_binary(self, monkeypatch: pytest.MonkeyPatch) -> None:
        assert nmap_capabilities._linux_binary_has_cap_net_raw(None) is False

    def test_non_root_linux_falls_back_to_binary_capabilities(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(nmap_capabilities.os, "name", "posix")
        monkeypatch.setattr(nmap_capabilities.sys, "platform", "linux")
        monkeypatch.setattr(
            nmap_capabilities.os, "geteuid", lambda: 1000, raising=False
        )
        monkeypatch.setattr(
            nmap_capabilities, "_linux_process_has_cap_net_raw", lambda: False
        )
        monkeypatch.setattr(
            nmap_capabilities, "_linux_binary_has_cap_net_raw", lambda _path: True
        )
        assert nmap_capabilities._has_raw_socket_privileges() is True

    def test_root_is_privileged(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(nmap_capabilities.os, "name", "posix")
        monkeypatch.setattr(nmap_capabilities.sys, "platform", "linux")
        monkeypatch.setattr(
            nmap_capabilities.os, "geteuid", lambda: 0, raising=False
        )
        assert nmap_capabilities._has_raw_socket_privileges() is True


# ── Windows: the driver is only half the answer ─────────────────────────────


def _completed(returncode: int, stdout: str = "", stderr: str = ""):
    from types import SimpleNamespace

    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


class TestWindowsRawSocketPrivileges:
    """A running Npcap service does not prove raw scans can open a device."""

    def test_driver_running_and_devices_listed_is_privileged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(nmap_capabilities.os, "name", "nt")
        monkeypatch.setattr(nmap_capabilities, "_npcap_driver_running", lambda: True)
        monkeypatch.setattr(
            nmap_capabilities, "_npcap_can_enumerate_devices", lambda: True
        )
        assert nmap_capabilities._has_raw_socket_privileges() is True

    def test_driver_running_but_pcap_devices_unusable_is_not_privileged(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # The reported bug: the service says RUNNING, nmap cannot open a device,
        # and every SYN scan died with "dnet: Failed to open device ethN".
        monkeypatch.setattr(nmap_capabilities.os, "name", "nt")
        monkeypatch.setattr(nmap_capabilities, "_npcap_driver_running", lambda: True)
        monkeypatch.setattr(
            nmap_capabilities, "_npcap_can_enumerate_devices", lambda: False
        )
        assert nmap_capabilities._has_raw_socket_privileges() is False

    def test_driver_stopped_never_probes_nmap(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr(nmap_capabilities.os, "name", "nt")
        monkeypatch.setattr(nmap_capabilities, "_npcap_driver_running", lambda: False)

        def _boom() -> bool:
            raise AssertionError("nmap must not be probed when the driver is stopped")

        monkeypatch.setattr(nmap_capabilities, "_npcap_can_enumerate_devices", _boom)
        assert nmap_capabilities._has_raw_socket_privileges() is False


class TestNpcapDeviceProbe:
    """`nmap --iflist` is the signal; the service state is not."""

    def test_successful_listing_is_usable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            nmap_capabilities.subprocess,
            "run",
            lambda *a, **k: _completed(0, "DEV (SHORT) IP/MASK TYPE UP\neth0 (eth0) 192.0.2.5/24 ethernet up\n"),
        )
        assert nmap_capabilities._npcap_can_enumerate_devices() is True

    def test_nmap_quitting_is_not_usable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(
            nmap_capabilities.subprocess,
            "run",
            lambda *a, **k: _completed(1, "pcap_findalldevs(): Cannot retrieve pcap interfaces\nQUITTING!\n"),
        )
        assert nmap_capabilities._npcap_can_enumerate_devices() is False

    def test_adapter_names_error_is_not_usable(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Exit 0 would be wrong to trust here: the error can arrive on stderr.
        monkeypatch.setattr(
            nmap_capabilities.subprocess,
            "run",
            lambda *a, **k: _completed(
                0, "", "pcap_findalldevs(): PacketGetAdapterNames: No more data (259)\n"
            ),
        )
        assert nmap_capabilities._npcap_can_enumerate_devices() is False

    def test_missing_binary_is_not_usable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def _raise(*_a, **_k):
            raise FileNotFoundError("nmap")

        monkeypatch.setattr(nmap_capabilities.subprocess, "run", _raise)
        assert nmap_capabilities._npcap_can_enumerate_devices() is False
