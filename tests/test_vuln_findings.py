"""Attribution rules for NSE vulnerability output.

The scan used to be fluent in ports and silent about CVEs. These tests pin the
two things that can go wrong when that changes: calling a clean host vulnerable,
and filing a finding under the wrong CVE.
"""
from app.services.device_enrichment import (
    script_reports_vulnerable,
    vuln_findings_from_scan_data,
)
from app.services.nmap_capabilities import VULN_SCRIPT_CATALOG


def test_not_vulnerable_is_not_a_finding() -> None:
    assert script_reports_vulnerable("State: NOT VULNERABLE") is False
    assert script_reports_vulnerable("smb-vuln-ms17-010:\n  State: NOT VULNERABLE") is False


def test_vulnerable_state_is_positive() -> None:
    assert script_reports_vulnerable(
        "VULNERABLE:\n  State: VULNERABLE\n  IDs: CVE:CVE-2017-0143"
    )


def test_clean_output_is_not_a_finding() -> None:
    assert script_reports_vulnerable("") is False
    assert script_reports_vulnerable("Service detected, nothing to report.") is False


def test_catalog_attribution_carries_cve_severity_and_port() -> None:
    scan_data = {
        "10.0.0.5": {
            "tcp": {
                445: {
                    "state": "open",
                    "script": {
                        "smb-vuln-ms17-010": (
                            "VULNERABLE:\n"
                            "  Remote Code Execution vulnerability in Microsoft SMBv1\n"
                            "  State: VULNERABLE\n"
                            "  IDs: CVE:CVE-2017-0143"
                        )
                    },
                }
            }
        }
    }

    findings = vuln_findings_from_scan_data(scan_data)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.cve_id == "CVE-2017-0143"
    assert finding.severity == "critical"
    assert finding.port == 445
    assert finding.protocol == "tcp"
    assert finding.script == "smb-vuln-ms17-010"


def test_unknown_script_uses_the_cve_in_its_output() -> None:
    scan_data = {
        "10.0.0.9": {
            "tcp": {
                8080: {
                    "state": "open",
                    "script": {
                        "some-custom-vuln": (
                            "VULNERABLE:\n  State: VULNERABLE\n  IDs: CVE:CVE-2021-44228"
                        )
                    },
                }
            }
        }
    }

    findings = vuln_findings_from_scan_data(scan_data)

    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2021-44228"
    # Unknown scripts get the conservative default rather than a guess.
    assert findings[0].severity == "medium"


def test_ports_without_script_output_produce_no_findings() -> None:
    assert vuln_findings_from_scan_data({"10.0.0.5": {"tcp": {80: {"state": "open"}}}}) == []
    assert vuln_findings_from_scan_data({}) == []


def test_every_catalog_entry_has_a_known_severity() -> None:
    allowed = {"critical", "high", "medium", "low", "info"}
    for script, entry in VULN_SCRIPT_CATALOG.items():
        assert entry.get("severity") in allowed, script
