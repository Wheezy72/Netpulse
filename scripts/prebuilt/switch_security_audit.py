from __future__ import annotations

"""
switch_security_audit.py

Prebuilt script: analyzes the latest backed-up running configurations of switches
and routers to audit compliance with secure hardening guidelines. Discovered issues
are automatically logged in the Netpulse vulnerabilities database.

It inspects configurations for:
- Insecure management protocols (Telnet / HTTP)
- Default or guessable SNMP community strings (public/private)
- Cleartext administrative passwords
- Legacy SSH protocol versions (SSH v1)
- Disabled password encryption services
"""

import re
from datetime import datetime
from pathlib import Path
from collections import defaultdict
from typing import Any, Dict, List, Tuple

from sqlalchemy import select
from app.db.session import async_session_factory
from app.models.device import Device
from app.models.vulnerability import Vulnerability, VulnerabilitySeverity


def _analyze_config(config_text: str) -> List[Dict[str, Any]]:
    """Scan the configuration text line-by-line for insecure patterns."""
    findings = []
    
    # 1. Telnet detection
    # Common triggers: 'transport input telnet' or 'transport input all'
    if re.search(r"^\s*transport\s+input\s+(?:telnet|all\b)", config_text, re.MULTILINE | re.IGNORECASE):
        findings.append({
            "title": "Cleartext Management Protocol Enabled (Telnet)",
            "severity": VulnerabilitySeverity.HIGH,
            "port": 23,
            "protocol": "tcp",
            "description": (
                "The configuration allows Telnet access. Telnet transmits all data, "
                "including administrator usernames and passwords, in cleartext, "
                "allowing potential network attackers to sniff administrative sessions."
            )
        })

    # 2. Insecure SNMP Community Strings
    if re.search(r"^\s*snmp-server\s+community\s+(?:public|private)\b", config_text, re.MULTILINE | re.IGNORECASE):
        findings.append({
            "title": "Default SNMP Community String Configured",
            "severity": VulnerabilitySeverity.HIGH,
            "port": 161,
            "protocol": "udp",
            "description": (
                "The switch is configured with a default SNMP community string ('public' or 'private'). "
                "Attackers can leverage this to read system metrics or rewrite device configurations."
            )
        })

    # 3. Cleartext Administrative Passwords
    # Matches 'password 0 <pass>' or 'enable password' which uses weak reversible cipher (or none)
    if re.search(r"^\s*(?:username\s+\S+\s+password\s+0\s+|enable\s+password\s+)", config_text, re.MULTILINE | re.IGNORECASE):
        findings.append({
            "title": "Cleartext Administrative Password Storage",
            "severity": VulnerabilitySeverity.CRITICAL,
            "description": (
                "The configuration contains cleartext or weakly obfuscated passwords. "
                "Any hacker gaining access to the config file can read the system password immediately."
            )
        })

    # 4. Legacy SSH Version
    if re.search(r"^\s*ip\s+ssh\s+version\s+1\b", config_text, re.MULTILINE | re.IGNORECASE):
        findings.append({
            "title": "Legacy SSH Version 1 Enforced",
            "severity": VulnerabilitySeverity.HIGH,
            "port": 22,
            "protocol": "tcp",
            "description": (
                "The device is configured to use SSH version 1. SSHv1 contains protocol-level "
                "vulnerabilities susceptible to man-in-the-middle exploits and session hijacking."
            )
        })

    # 5. Disabled Password Encryption Service
    if re.search(r"^\s*no\s+service\s+password-encryption\b", config_text, re.MULTILINE | re.IGNORECASE):
        findings.append({
            "title": "Service Password-Encryption Disabled",
            "severity": VulnerabilitySeverity.MEDIUM,
            "description": (
                "The global 'service password-encryption' command is missing or disabled. "
                "Administrative passwords added to the local database will remain unencrypted in the config output."
            )
        })

    return findings


async def _apply_findings(device_id: int, findings: List[Dict[str, Any]]):
    """Write/sync findings to the vulnerabilities database table for the device."""
    async with async_session_factory() as session:
        # Clear previous config_audit alerts for this device
        try:
            from sqlalchemy import delete
            await session.execute(
                delete(Vulnerability).where(
                    Vulnerability.device_id == device_id,
                    Vulnerability.source == "config_audit"
                )
            )
        except Exception:
            pass

        for f in findings:
            vuln = Vulnerability(
                device_id=device_id,
                source="config_audit",
                title=f["title"],
                severity=f["severity"],
                description=f["description"],
                port=f.get("port"),
                protocol=f.get("protocol"),
                detected_at=datetime.utcnow()
            )
            session.add(vuln)

        await session.commit()


def run(ctx: Any) -> dict:
    ctx.logger("switch_security_audit: scanning backups directory...")

    # Group backups by device name
    search_paths = [Path("/data/backups"), Path("data/backups")]
    backups_dir = None
    for p in search_paths:
        if p.exists() and p.is_dir():
            backups_dir = p
            break

    if not backups_dir:
        ctx.logger("switch_security_audit: backups directory not found.")
        return {"status": "failed", "error": "No backups directory found"}

    files_by_device: Dict[str, List[Path]] = defaultdict(list)
    for path in backups_dir.glob("*.cfg"):
        name = path.name
        if "-" not in name:
            continue
        parts = name.split("-")
        if len(parts) < 3:
            continue
        device_label = "-".join(parts[:-2])
        files_by_device[device_label].append(path)

    total_audited = 0
    total_findings = 0
    results: List[Dict[str, Any]] = []

    for device_label, paths in files_by_device.items():
        # Sort by mtime to get latest backup
        paths_sorted = sorted(paths, key=lambda p: p.stat().st_mtime)
        latest_backup = paths_sorted[-1]
        
        ctx.logger(f"switch_security_audit: auditing latest backup file {latest_backup.name}")
        
        try:
            config_text = latest_backup.read_text(errors="ignore")
            findings = _analyze_config(config_text)
            
            # Match label to a Device record in db
            async def _find_device_id(label: str) -> int | None:
                async with async_session_factory() as session:
                    res = await session.execute(
                        select(Device.id).where(
                            (Device.hostname == label) | (Device.ip_address == label)
                        )
                    )
                    return res.scalar_one_or_none()

            dev_id = ctx.loop.run_until_complete(_find_device_id(device_label))
            if dev_id:
                ctx.loop.run_until_complete(_apply_findings(dev_id, findings))
                total_audited += 1
                total_findings += len(findings)
                results.append({
                    "device": device_label,
                    "backup_file": latest_backup.name,
                    "vulnerabilities_found": len(findings)
                })
            else:
                ctx.logger(f"switch_security_audit: device '{device_label}' not found in inventory, skipping vulnerability logging.")
                results.append({
                    "device": device_label,
                    "backup_file": latest_backup.name,
                    "vulnerabilities_found": len(findings),
                    "warning": "Device not found in database inventory"
                })

        except Exception as e:
            ctx.logger(f"switch_security_audit: error auditing {device_label}: {e}")

    ctx.logger(f"switch_security_audit: completed. Audited {total_audited} devices, logged {total_findings} security vulnerabilities.")
    return {
        "status": "completed",
        "devices_audited": total_audited,
        "vulnerabilities_logged": total_findings,
        "details": results
    }
