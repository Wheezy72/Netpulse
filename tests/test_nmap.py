from __future__ import annotations

import pytest
from fastapi import HTTPException

from app.api.routes.nmap import (
    _validate_target,
    _validate_script_list,
    _parse_safe_nmap_args,
    get_scan_type_from_command,
    _is_restricted_segment,
    _contains_active_syn_flags
)


def test_validate_target() -> None:
    assert _validate_target("192.168.1.1") is True
    assert _validate_target("example.com") is True
    assert _validate_target("10.0.0.0/24") is True
    assert _validate_target("") is False
    assert _validate_target(" ") is False
    assert _validate_target("192.168.1.1; ls") is False
    assert _validate_target("-sS") is False


def test_validate_script_list() -> None:
    _validate_script_list("http-enum")  # should not raise
    with pytest.raises(HTTPException):
        _validate_script_list("../traversal")
    with pytest.raises(HTTPException):
        _validate_script_list("http-enum;bad")


def test_parse_safe_nmap_args() -> None:
    args = _parse_safe_nmap_args("nmap -sV -p 80", "192.168.1.1")
    assert args == ["nmap", "-sV", "-p", "80", "192.168.1.1"]

    with pytest.raises(HTTPException):
        # Disallowed flag
        _parse_safe_nmap_args("nmap --bad-flag", "192.168.1.1")


def test_get_scan_type_from_command() -> None:
    assert get_scan_type_from_command("nmap -sn") == "Ping Sweep"
    assert get_scan_type_from_command("nmap -sV") == "Version Detection"
    assert get_scan_type_from_command("nmap -sV -sC") == "Script Scan"
    assert get_scan_type_from_command("nmap -p-") == "Full Port Scan"
    assert get_scan_type_from_command("nmap -A") == "Aggressive Scan"
    assert get_scan_type_from_command("nmap -sS") == "Custom Scan"


def test_contains_active_syn_flags() -> None:
    assert _contains_active_syn_flags("nmap -sS -p 80") is True
    assert _contains_active_syn_flags("nmap -sT -p 80") is False
