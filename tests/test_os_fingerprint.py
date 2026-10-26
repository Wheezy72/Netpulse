"""Operating-system fingerprinting: the pure heuristic, without nmap."""
from __future__ import annotations

from app.services.os_fingerprint import (
    infer_os_from_host,
    os_family_from_ttl,
    os_label_from_banner,
    resolve_device_os,
)


def test_windows_hostname_is_high_confidence() -> None:
    assert infer_os_from_host(hostname="DESKTOP-8FJ2K9L") == ("Windows", "high")


def test_android_hostname_is_high_confidence() -> None:
    assert infer_os_from_host(hostname="android-9f3c1a2b") == ("Android", "high")


def test_mac_hostname_is_high_confidence() -> None:
    assert infer_os_from_host(hostname="Bobs-MacBook-Pro.local") == ("macOS", "high")


def test_ubuntu_hostname_is_high_confidence() -> None:
    assert infer_os_from_host(hostname="ubuntuserver") == ("Linux", "high")


def test_windows_file_sharing_ports_win_over_hostname_absence() -> None:
    assert infer_os_from_host(open_ports=[135, 139, 445]) == ("Windows", "high")


def test_adb_port_means_android() -> None:
    assert infer_os_from_host(open_ports=[5555]) == ("Android", "high")


def test_apple_lockdown_port_means_ios() -> None:
    assert infer_os_from_host(open_ports=[62078]) == ("iOS", "high")


def test_ssh_without_windows_sharing_means_unix_like() -> None:
    assert infer_os_from_host(open_ports=[22, 80]) == ("Linux", "medium")


def test_no_signals_returns_none_not_a_guess() -> None:
    """An unrecognised host stays unknown rather than being called Linux."""
    assert infer_os_from_host() == (None, None)


def test_randomised_mac_never_uses_vendor() -> None:
    """A locally administered MAC carries no real vendor prefix."""
    assert infer_os_from_host(vendor="HP", mac_randomised=True) == (None, None)


def test_vendor_is_only_a_medium_hint() -> None:
    assert infer_os_from_host(vendor="Samsung") == ("Android", "medium")
    assert infer_os_from_host(vendor="Microsoft") == ("Windows", "medium")


def test_hostname_outranks_vendor() -> None:
    """A Galaxy branded "desktop-" is still read from what it calls itself."""
    assert infer_os_from_host(hostname="desktop-office", vendor="Samsung") == (
        "Windows",
        "high",
    )


def test_resolve_falls_back_when_nmap_is_absent(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.services.os_fingerprint.shutil.which", lambda _name: None
    )
    assert resolve_device_os(ip_address="192.168.1.5", open_ports=[445]) == (
        "Windows",
        "high",
    )


# ── Distribution detection ────────────────────────────────────────────────
# A Kali box and a Debian box run the same TCP/IP stack, so only a self-
# reported string can tell them apart. These tests pin down that rule.


def test_kali_banner_is_named_not_folded_into_linux() -> None:
    assert infer_os_from_host(
        service_banners=["ssh OpenSSH 9.6p1 Kali-1 (protocol 2.0)"]
    ) == ("Kali Linux", "high")


def test_debian_banner_stays_debian() -> None:
    assert infer_os_from_host(
        service_banners=["ssh OpenSSH 9.2p1 Debian-2+deb12u2"]
    ) == ("Debian", "high")


def test_ubuntu_banner_beats_a_samba_port() -> None:
    """Samba opens 445 on Linux; a banner that says Ubuntu is the better fact."""
    assert infer_os_from_host(
        open_ports=[22, 445], service_banners=["Ubuntu 22.04 smbd"]
    ) == ("Ubuntu", "high")


def test_banner_without_a_distribution_is_ignored() -> None:
    assert os_label_from_banner("OpenSSH 8.9 (protocol 2.0)") is None


def test_kali_hostname_is_named() -> None:
    assert infer_os_from_host(hostname="kali") == ("Kali Linux", "high")


def test_virtual_machine_annotation_needs_a_hypervisor_vendor() -> None:
    assert infer_os_from_host(
        hostname="kali", vendor="VMware, Inc."
    ) == ("Kali Linux (virtual machine)", "high")


# ── TTL ───────────────────────────────────────────────────────────────────


def test_ttl_families() -> None:
    assert os_family_from_ttl(64) == ("Linux/Unix", "low")
    assert os_family_from_ttl(128) == ("Windows", "low")
    assert os_family_from_ttl(255) == ("Network device", "low")
    assert os_family_from_ttl(None) == (None, None)


def test_ttl_is_only_used_when_nothing_better_answers() -> None:
    assert infer_os_from_host(ttl=64) == ("Linux/Unix", "low")
    # A hostname outranks the hint.
    assert infer_os_from_host(hostname="DESKTOP-AB12", ttl=64) == ("Windows", "high")


def test_ttl_from_a_virtual_machine_says_linux_not_a_distro() -> None:
    assert infer_os_from_host(ttl=64, vendor="VirtualBox") == (
        "Linux (virtual machine)",
        "medium",
    )
