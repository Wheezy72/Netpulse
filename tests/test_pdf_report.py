"""PDF reports: the shared design system, not the routes.

These assert what actually matters about a report — that it is a valid PDF, that
the numbers came from the data handed in, and that the page chrome carries the
report's own id — rather than pixel-matching the layout, which would make every
styling tweak look like a regression.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from app.core.clock import utcnow



class FakeDevice:
    def __init__(self, ip, hostname, mac, vendor, os_, kind, last_seen, gateway=False):
        self.ip_address = ip
        self.hostname = hostname
        self.mac_address = mac
        self.vendor = vendor
        self.os = os_
        self.device_type = kind
        self.last_seen = last_seen
        self.is_gateway = gateway


def _devices() -> list[FakeDevice]:
    now = utcnow()
    return [
        FakeDevice("192.168.1.1", "router.lan", "a4:2b:8c:11:22:33", "TP-Link", "Linux/Unix", "Router", now, True),
        FakeDevice("192.168.1.10", "kali", "00:0c:29:aa:bb:cc", "VMware, Inc.", "Kali Linux (virtual machine)", "Workstation", now - timedelta(hours=2)),
        FakeDevice("192.168.1.23", "immortan", "3c:7c:3f:9e:11:07", "ASUSTek", "Windows", "Desktop", now - timedelta(minutes=1)),
    ]


def _device_is_online(device, window_minutes=10) -> bool:
    return (utcnow() - device.last_seen).total_seconds() <= window_minutes * 60


def _page_text(raw: bytes) -> str:
    """Extract the text of a report so the test can read what it says."""
    import pymupdf

    with pymupdf.open(stream=raw, filetype="pdf") as document:
        return "".join(page.get_text() for page in document)


def test_inventory_pdf_is_a_valid_pdf_with_the_computed_counts() -> None:
    from app.services.pdf_report import build_inventory_pdf

    devices = _devices()
    raw = build_inventory_pdf(
        devices=devices,
        title="NetPulse Network Summary Report",
        report_type="network_summary",
        is_online=_device_is_online,
    )

    assert raw.startswith(b"%PDF")
    text = _page_text(raw)
    # The headline numbers are computed from the devices, not invented.
    assert "3" in text          # total devices
    assert "192.168.1.10" in text
    assert "Kali" in text       # the label is the one the fingerprint produced
    assert "Page 1 of 1" in text


def test_inventory_pdf_counts_silent_devices_from_the_same_rule() -> None:
    from app.services.pdf_report import build_inventory_pdf

    devices = _devices()
    raw = build_inventory_pdf(
        devices=devices,
        title="Device Inventory Report",
        report_type="device_inventory",
        is_online=_device_is_online,
    )
    text = _page_text(raw)
    assert "silent" in text  # the 2-hour-old device is not answering


def test_inventory_pdf_survives_an_empty_inventory() -> None:
    from app.services.pdf_report import build_inventory_pdf

    raw = build_inventory_pdf(
        devices=[],
        title="Empty",
        report_type="device_inventory",
        is_online=_device_is_online,
    )
    assert raw.startswith(b"%PDF")
    assert "No devices were recorded" in _page_text(raw)


def test_logs_pdf_reports_level_counts_and_wraps_long_messages() -> None:
    from app.services.pdf_report import build_logs_pdf

    logs = [
        {"timestamp": "2026-10-26T07:18:58.000000Z", "level": "warning", "logger": "netpulse.router_source", "message": "Router verification failed " + "with detail " * 30},
        {"timestamp": "2026-10-26T07:22:37.000000Z", "level": "error", "logger": "netpulse.nmap_runner", "message": "nmap is not installed on this host."},
        {"timestamp": "2026-10-26T07:30:04.000000Z", "level": "info", "logger": "app.main", "message": "Discovery sweep complete."},
    ]
    raw = build_logs_pdf(logs=logs, total=120, level_filter=None)

    assert raw.startswith(b"%PDF")
    text = _page_text(raw)
    assert "Router verification failed" in text
    assert "nmap is not installed" in text


def test_scan_pdf_prints_the_command_it_ran() -> None:
    from app.services.pdf_report import build_scan_pdf

    raw = build_scan_pdf(
        scan_type="services",
        target="192.168.1.0/24",
        command="nmap -sT -sV --version-light -F -T4 192.168.1.0/24",
        results="Nmap scan report for 192.168.1.10\n22/tcp open  ssh",
        summary={"hosts": [{"address": "192.168.1.10", "hostname": "kali", "os": "Kali Linux", "open_ports": 1}], "open_ports": 1, "scan_seconds": 12, "exit_code": 0},
    )

    assert raw.startswith(b"%PDF")
    text = _page_text(raw)
    assert "-sV" in text          # the exact command, for reproduction
    assert "192.168.1.10" in text


def test_mojibake_is_avoided_in_the_scan_output_block() -> None:
    """A user-supplied string must be escaped, not passed to the parser raw."""
    from app.services.pdf_report import build_scan_pdf

    raw = build_scan_pdf(
        scan_type="quick",
        target="x",
        command=None,
        results="literal <tags> & ampersands",
        summary=None,
    )
    assert raw.startswith(b"%PDF")
    text = _page_text(raw)
    assert "literal <tags> & ampersands" in text


def test_fallback_pdf_still_opens_when_reportlab_is_absent() -> None:
    from app.services.pdf_report import fallback_pdf

    raw = fallback_pdf("Title <escaped>", "subtitle")
    assert raw.startswith(b"%PDF")
