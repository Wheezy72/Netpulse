from __future__ import annotations

"""
Prebuilt script: nmap_web_recon.py

Runs a focused Nmap web reconnaissance profile against a single target,
using HTTP/HTTPS-related NSE scripts.

Intended for lab and internal use on hosts you own or have explicit
permission to test. This wraps common Nmap web flags into a repeatable
Smart Script.
"""

import re
from typing import Any, Dict, List

TARGET_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9.\-:/]+$")


async def run(ctx: Any) -> Dict[str, Any]:
    """
    Execute a web-focused Nmap profile against ctx.params["target"].

    Parameters
    ----------
    ctx.params["target"] : str
        Target hostname or IP address.

    Returns
    -------
    dict with Nmap arguments and raw output.
    """
    target = str(ctx.params.get("target", "")).strip()
    if not target:
        ctx.logger("nmap_web_recon: missing 'target' in ctx.params")
        return {"error": "missing target"}

    if len(target) > 256 or not TARGET_PATTERN.match(target):
        ctx.logger("nmap_web_recon: invalid target")
        return {"error": "invalid target"}

    ctx.logger(f"nmap_web_recon: running web profile against {target}")

    # This script assumes Nmap is available in the worker image.
    import asyncio
    import shlex

    # Profile: version detection + safe/default web scripts on common ports.
    # You can adjust ports or script set in your own copy if desired.
    args = [
        "nmap",
        "-sV",
        "-Pn",
        "-p", "80,443,8080,8443",
        "--script",
        ",".join(
            [
                "http-title",
                "http-enum",
                "http-methods",
                "http-headers",
                "http-robots.txt",
                "http-vuln-cve2017-5638",
                "http-shellshock",
            ]
        ),
        target,
    ]
    ctx.logger(f"nmap_web_recon: command = {' '.join(shlex.quote(a) for a in args)}")

    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    code = proc.returncode

    if code != 0:
        ctx.logger(f"nmap_web_recon: nmap exited with code {code}")
        if stderr:
            ctx.logger(stderr.decode(errors="ignore"))
        return {
            "status": "error",
            "return_code": code,
            "stderr": stderr.decode(errors="ignore"),
        }

    output_text = stdout.decode(errors="ignore")
    ctx.logger("nmap_web_recon: scan completed")

    return {
        "status": "ok",
        "target": target,
        "return_code": code,
        "output": output_text,
    }