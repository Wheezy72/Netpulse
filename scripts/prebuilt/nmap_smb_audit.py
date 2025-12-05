from __future__ import annotations

"""
Prebuilt script: nmap_smb_audit.py

Runs an Nmap SMB audit profile against a target, focusing on share/user
enumeration and common SMB vulnerabilities (e.g. EternalBlue).

Use this only against systems you control or have explicit permission
to test.
"""

from typing import Any, Dict


async def run(ctx: Any) -> Dict[str, Any]:
    """
    Execute an SMB-focused Nmap profile against ctx.params["target"].

    Parameters
    ----------
    ctx.params["target"] : str
        Target hostname or IP.

    Returns
    -------
    dict with Nmap arguments and raw output.
    """
    target = str(ctx.params.get("target", "")).strip()
    if not target:
        ctx.logger("nmap_smb_audit: missing 'target' in ctx.params")
        return {"error": "missing target"}

    ctx.logger(f"nmap_smb_audit: running SMB profile against {target}")

    import asyncio
    import shlex

    args = [
        "nmap",
        "-sV",
        "-Pn",
        "-p", "139,445",
        "--script",
        ",".join(
            [
                "smb-enum-shares",
                "smb-enum-users",
                "smb-os-discovery",
                "smb-security-mode",
                "smb2-security-mode",
                "smb-vuln-ms17-010",
                "smb-vuln-ms08-067",
            ]
        ),
        target,
    ]
    ctx.logger(f"nmap_smb_audit: command = {' '.join(shlex.quote(a) for a in args)}")

    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    code = proc.returncode

    if code != 0:
        ctx.logger(f"nmap_smb_audit: nmap exited with code {code}")
        if stderr:
            ctx.logger(stderr.decode(errors=\"ignore\"))
        return {
            \"status\": \"error\",
            \"return_code\": code,
            \"stderr\": stderr.decode(errors=\"ignore\"),
        }

    output_text = stdout.decode(errors=\"ignore\")
    ctx.logger(\"nmap_smb_audit: scan completed\")

    return {
        \"status\": \"ok\",
        \"target\": target,
        \"return_code\": code,
        \"output\": output_text,
    }