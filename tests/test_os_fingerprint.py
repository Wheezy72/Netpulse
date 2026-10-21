"""Operating-system fingerprinting: the pure heuristic, without nmap."""
from __future__ import annotations

from app.services.os_fingerprint import infer_os_from_host, resolve_device_os


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
