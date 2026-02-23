from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from pydantic import BaseModel

from app.api.deps import get_current_user
from app.models.user import User

router = APIRouter()

SCANS_DIR = Path("data/scans")
SCANS_DIR.mkdir(parents=True, exist_ok=True)

scan_results_store: Dict[str, Dict[str, Any]] = {}

ALLOWED_NMAP_FLAGS = {
    '-sS', '-sT', '-sU', '-sV', '-sC', '-sn', '-sP', '-sA', '-sW', '-sM', '-sN', '-sF', '-sX',
    '-O', '-A', '-F', '-T0', '-T1', '-T2', '-T3', '-T4', '-T5',
    '-Pn', '-n', '-R', '-v', '-vv', '-d', '-dd', '-p-',
    '--open', '--reason', '--osscan-guess',
}

TARGET_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9.\-/]+$')
PORT_PATTERN = re.compile(r'^[\d,\-]+$')


def _load_history_from_disk():
    """Load scan history from disk on startup."""
    for file in SCANS_DIR.glob("*.txt"):
        try:
            parts = file.stem.split("_")
            if file.name.startswith("nmap_scan_output_"):
                scan_id = parts[-1] if len(parts) >= 4 else file.stem
            elif file.name.startswith("scan_"):
                scan_id = parts[1] if len(parts) >= 2 else file.stem
            else:
                continue
            
            if scan_id not in scan_results_store:
                with open(file, 'r') as f:
                    lines = f.readlines()
                    command = lines[0].replace("Command: ", "").strip() if len(lines) > 0 else ""
                    target = lines[1].replace("Target: ", "").strip() if len(lines) > 1 else ""
                    scan_type = lines[2].replace("Type: ", "").strip() if len(lines) > 2 else ""
                    output = "".join(lines[5:]) if len(lines) > 5 else ""
                    
                scan_results_store[scan_id] = {
                    "id": scan_id,
                    "command": command,
                    "target": target,
                    "scan_type": scan_type,
                    "started_at": datetime.fromtimestamp(file.stat().st_mtime).isoformat(),
                    "completed_at": datetime.fromtimestamp(file.stat().st_mtime).isoformat(),
                    "status": "completed",
                    "output": output,
                    "file_path": str(file),
                }
        except Exception:
            continue

_load_history_from_disk()


def _validate_target(target: str) -> bool:
    """Validate target is a safe IP/hostname/CIDR."""
    if not target or len(target) > 256:
        return False
    if not TARGET_PATTERN.match(target):
        return False
    return True


def _parse_safe_nmap_args(command: str, target: str) -> List[str]:
    """Parse nmap command and return safe argument list for subprocess_exec."""
    args = ['nmap']
    parts = command.strip().split()
    
    if parts and parts[0] == 'nmap':
        parts = parts[1:]
    
    i = 0
    while i < len(parts):
        part = parts[i]
        
        if part == target or part.startswith(target):
            i += 1
            continue
        
        if part in ALLOWED_NMAP_FLAGS:
            args.append(part)
            i += 1
            continue
        
        if part == '-p' and i + 1 < len(parts):
            port_spec = parts[i + 1]
            if PORT_PATTERN.match(port_spec):
                args.append('-p')
                args.append(port_spec)
                i += 2
                continue
        elif part.startswith('-p') and PORT_PATTERN.match(part[2:]):
            args.append(part)
            i += 1
            continue
        
        if part == '--top-ports' and i + 1 < len(parts):
            try:
                count = int(parts[i + 1])
                if 1 <= count <= 65535:
                    args.append('--top-ports')
                    args.append(str(count))
                    i += 2
                    continue
            except ValueError:
                pass
        
        if part.startswith('--script='):
            script_value = part[9:]
            safe_scripts = {
                'vuln', 'safe', 'default', 'http-headers', 'http-title', 'http-methods',
                'smb-enum-shares', 'smb-vuln-ms17-010', 'smb-os-discovery',
                'ssl-cert', 'ssl-enum-ciphers', 'ssh-hostkey',
                'dns-brute', 'ftp-anon', 'mysql-info', 'banner',
                'snmp-info', 'http-sql-injection', 'ssl-heartbleed',
                'mysql-empty-password', 'ssh-auth-methods',
                'http-brute', 'ssh-brute', 'ftp-brute',
                'tls-ticketbleed', 'traceroute',
            }
            script_parts = script_value.split(',')
            if all(s.strip() in safe_scripts for s in script_parts):
                args.append(part)
                i += 1
                continue
        
        i += 1
    
    args.append(target)
    return args


class NmapCommandRequest(BaseModel):
    command: str
    target: str
    save_results: bool = True


class AICommandRequest(BaseModel):
    description: str
    target: str


class ScanResult(BaseModel):
    id: str
    command: str
    target: str
    scan_type: str
    started_at: str
    completed_at: Optional[str] = None
    status: str
    output: Optional[str] = None
    file_path: Optional[str] = None


def get_scan_type_from_command(command: str) -> str:
    """Determine scan type from nmap command flags."""
    if '-sV' in command:
        return 'Version Detection'
    elif '-sS' in command:
        return 'SYN Stealth Scan'
    elif '-sU' in command:
        return 'UDP Scan'
    elif '-sT' in command:
        return 'TCP Connect Scan'
    elif '-sn' in command:
        return 'Ping Sweep'
    elif '-O' in command:
        return 'OS Detection'
    elif '--script' in command or '-sC' in command:
        return 'Script Scan'
    elif '-A' in command:
        return 'Aggressive Scan'
    elif '-p-' in command:
        return 'Full Port Scan'
    else:
        return 'Basic Scan'


@router.post("/execute", response_model=ScanResult)
async def execute_nmap(
    request: NmapCommandRequest,
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
) -> ScanResult:
    """Execute an nmap command and return results."""
    if not shutil.which('nmap'):
        raise HTTPException(status_code=503, detail="nmap is not installed on this system")
    
    if not _validate_target(request.target):
        raise HTTPException(status_code=400, detail="Invalid target format. Use IP address, hostname, or CIDR notation.")
    
    safe_args = _parse_safe_nmap_args(request.command, request.target)
    command_str = " ".join(safe_args)
    
    scan_id = str(uuid.uuid4())[:8]
    scan_type = get_scan_type_from_command(command_str)
    
    result = ScanResult(
        id=scan_id,
        command=command_str,
        target=request.target,
        scan_type=scan_type,
        started_at=datetime.now().isoformat(),
        status="running",
        output=None,
        file_path=None,
    )
    
    scan_results_store[scan_id] = result.dict()
    
    async def run_scan():
        try:
            proc = await asyncio.create_subprocess_exec(
                *safe_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            output = stdout.decode() + (stderr.decode() if stderr else "")
            
            scan_results_store[scan_id]["output"] = output
            scan_results_store[scan_id]["completed_at"] = datetime.now().isoformat()
            scan_results_store[scan_id]["status"] = "completed"
            
            if request.save_results:
                safe_target = request.target.replace('/', '_').replace('.', '-').replace(':', '-')[:30]
                file_path = SCANS_DIR / f"nmap_scan_output_{safe_target}_{scan_id}.txt"
                with open(file_path, 'w') as f:
                    f.write(f"Command: {command_str}\n")
                    f.write(f"Target: {request.target}\n")
                    f.write(f"Type: {scan_type}\n")
                    f.write(f"Time: {datetime.now().isoformat()}\n")
                    f.write("=" * 60 + "\n\n")
                    f.write(output)
                scan_results_store[scan_id]["file_path"] = str(file_path)
        except asyncio.TimeoutError:
            scan_results_store[scan_id]["status"] = "timeout"
            scan_results_store[scan_id]["output"] = "Scan timed out after 5 minutes"
        except Exception as e:
            scan_results_store[scan_id]["status"] = "error"
            scan_results_store[scan_id]["output"] = str(e)
    
    background_tasks.add_task(run_scan)
    
    return result


@router.get("/result/{scan_id}", response_model=ScanResult)
async def get_scan_result(
    scan_id: str,
    current_user: User = Depends(get_current_user),
) -> ScanResult:
    """Get the result of a scan by ID."""
    if scan_id not in scan_results_store:
        raise HTTPException(status_code=404, detail="Scan not found")
    return ScanResult(**scan_results_store[scan_id])


@router.get("/history", response_model=List[ScanResult])
async def get_scan_history(
    current_user: User = Depends(get_current_user),
) -> List[ScanResult]:
    """Get recent scan history."""
    results = list(scan_results_store.values())
    results.sort(key=lambda x: x.get("started_at", ""), reverse=True)
    return [ScanResult(**r) for r in results[:50]]


@router.post("/ai-command")
async def generate_ai_command(
    request: AICommandRequest,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    """Use AI to generate an nmap command from natural language description."""
    description = request.description.lower()
    target = request.target
    
    flags = ["nmap"]
    explanation_parts = []
    
    if "quiet" in description or "stealth" in description or "no noise" in description or "don't cause noise" in description:
        flags.append("-T2")
        explanation_parts.append("Slower timing to avoid detection")
    elif "fast" in description or "quick" in description:
        flags.append("-T4")
        explanation_parts.append("Faster timing for speed")
    else:
        flags.append("-T3")
        explanation_parts.append("Normal timing")
    
    if "udp" in description:
        flags.append("-sU")
        explanation_parts.append("UDP port scan")
    elif "syn" in description or "stealth" in description:
        flags.append("-sS")
        explanation_parts.append("SYN stealth scan")
    else:
        flags.append("-sT")
        explanation_parts.append("TCP connect scan")
    
    if "version" in description or "service" in description:
        flags.append("-sV")
        explanation_parts.append("Service version detection")
    
    if "os" in description or "operating system" in description:
        flags.append("-O")
        explanation_parts.append("OS detection")
    
    if "vuln" in description or "vulnerab" in description:
        flags.append("--script=vuln")
        explanation_parts.append("Vulnerability scripts")
    
    if "eternalblue" in description or "ms17" in description:
        flags.append("-p 445")
        flags.append("--script=smb-vuln-ms17-010")
        explanation_parts.append("EternalBlue/MS17-010 check on SMB port")
    
    if "heartbleed" in description:
        flags.append("-p 443")
        flags.append("--script=ssl-heartbleed")
        explanation_parts.append("Heartbleed vulnerability check")
    
    if "ssl" in description or "tls" in description or "certificate" in description:
        if "cipher" in description:
            flags.append("--script=ssl-enum-ciphers")
            explanation_parts.append("SSL/TLS cipher enumeration")
        elif "cert" in description or "certificate" in description:
            flags.append("--script=ssl-cert")
            explanation_parts.append("SSL certificate information")
        else:
            flags.append("--script=ssl-cert,ssl-enum-ciphers")
            explanation_parts.append("SSL/TLS certificate and cipher analysis")
    
    if "banner" in description or "grab" in description:
        flags.append("--script=banner")
        explanation_parts.append("Banner grabbing")
    
    if "smb" in description or "windows share" in description:
        flags.append("-p 139,445")
        flags.append("--script=smb-enum-shares,smb-os-discovery")
        explanation_parts.append("SMB share enumeration and OS discovery")
    
    if "dns" in description and "brute" in description:
        flags.append("--script=dns-brute")
        explanation_parts.append("DNS subdomain brute force")
    
    if "ftp" in description and ("anon" in description or "anonymous" in description):
        flags.append("-p 21")
        flags.append("--script=ftp-anon")
        explanation_parts.append("Anonymous FTP access check")
    
    if "snmp" in description:
        flags.append("-sU -p 161")
        flags.append("--script=snmp-info")
        explanation_parts.append("SNMP device information")
    
    if "ssh" in description and "auth" in description:
        flags.append("-p 22")
        flags.append("--script=ssh-auth-methods")
        explanation_parts.append("SSH authentication methods")
    
    if "mysql" in description:
        flags.append("-p 3306")
        flags.append("--script=mysql-info")
        explanation_parts.append("MySQL server information")
    
    if "http" in description and "title" in description:
        flags.append("--script=http-title")
        explanation_parts.append("HTTP page title detection")
    
    if "brute" in description and "force" in description:
        if "ssh" in description:
            flags.append("-p 22 --script=ssh-brute")
            explanation_parts.append("SSH brute force")
        elif "ftp" in description:
            flags.append("-p 21 --script=ftp-brute")
            explanation_parts.append("FTP brute force")
        elif "http" in description:
            flags.append("-p 80,443 --script=http-brute")
            explanation_parts.append("HTTP brute force")
    
    if "all port" in description or "full port" in description:
        flags.append("-p-")
        explanation_parts.append("All 65535 ports")
    elif "top port" in description or "common port" in description:
        flags.append("--top-ports 1000")
        explanation_parts.append("Top 1000 common ports")
    elif "web" in description or "http" in description:
        flags.append("-p 80,443,8080,8443")
        explanation_parts.append("Web ports")
    
    if "no ping" in description or "skip ping" in description:
        flags.append("-Pn")
        explanation_parts.append("Skip host discovery")
    
    if "no dns" in description or "skip dns" in description:
        flags.append("-n")
        explanation_parts.append("No DNS resolution")
    
    if "aggressive" in description:
        flags.append("-A")
        explanation_parts.append("Aggressive scan (OS, version, scripts, traceroute)")
    
    flags.append(target)
    
    command = " ".join(flags)
    explanation = "Command breakdown:\n- " + "\n- ".join(explanation_parts)
    
    return {
        "command": command,
        "explanation": explanation,
        "scan_type": get_scan_type_from_command(command),
        "estimated_time": "2-10 minutes depending on target and options",
    }


@router.get("/presets")
async def get_nmap_presets(
    current_user: User = Depends(get_current_user),
) -> List[Dict[str, str]]:
    """Get common nmap scan presets."""
    return [
        {"id": "quick", "name": "Quick Scan", "command": "nmap -T4 -F", "description": "Fast scan of top 100 ports"},
        {"id": "full", "name": "Full Port Scan", "command": "nmap -p- -T4", "description": "All 65535 TCP ports"},
        {"id": "version", "name": "Version Detection", "command": "nmap -sV -T3", "description": "Detect service versions"},
        {"id": "os", "name": "OS Detection", "command": "nmap -O -T3", "description": "Detect operating system"},
        {"id": "stealth", "name": "Stealth Scan", "command": "nmap -sS -T2 -n", "description": "SYN scan, slower, no DNS"},
        {"id": "udp", "name": "UDP Scan", "command": "nmap -sU --top-ports 100", "description": "Top 100 UDP ports"},
        {"id": "vuln", "name": "Vulnerability Scan", "command": "nmap -sV --script=vuln", "description": "Check for known vulnerabilities"},
        {"id": "aggressive", "name": "Aggressive Scan", "command": "nmap -A -T4", "description": "OS, version, scripts, traceroute"},
        {"id": "web", "name": "Web Server Scan", "command": "nmap -p 80,443,8080,8443 -sV --script=http-headers", "description": "Web server enumeration"},
        {"id": "smb", "name": "SMB Audit", "command": "nmap -p 139,445 --script=smb-enum-shares,smb-vuln*", "description": "Windows share enumeration"},
    ]


@router.delete("/history")
async def clear_scan_history(
    current_user: User = Depends(get_current_user),
) -> Dict[str, str]:
    """Clear scan history from memory."""
    scan_results_store.clear()
    return {"message": "Scan history cleared"}


@router.get("/files")
async def list_stored_scans(
    current_user: User = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """List all stored scan files."""
    files = []
    for file in sorted(SCANS_DIR.glob("scan_*.txt"), key=lambda f: f.stat().st_mtime, reverse=True):
        files.append({
            "filename": file.name,
            "scan_id": file.name.split("_")[1] if "_" in file.name else "",
            "size": file.stat().st_size,
            "modified": datetime.fromtimestamp(file.stat().st_mtime).isoformat(),
        })
    return files[:100]


@router.get("/files/{filename}")
async def download_scan_file(
    filename: str,
    current_user: User = Depends(get_current_user),
):
    """Download a stored scan file."""
    from fastapi.responses import FileResponse
    
    if not filename.startswith("scan_") or not filename.endswith(".txt"):
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    if ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Invalid filename")
    
    file_path = SCANS_DIR / filename
    if not file_path.exists():
        raise HTTPException(status_code=404, detail="File not found")
    
    return FileResponse(
        path=str(file_path),
        filename=filename,
        media_type="text/plain",
    )


class TracerouteRequest(BaseModel):
    target: str


class TracerouteHop(BaseModel):
    hop: int
    ip: Optional[str] = None
    rtt_ms: Optional[List[float]] = None
    is_timeout: bool = False


@router.post("/traceroute")
async def run_traceroute(
    request: TracerouteRequest,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    if not _validate_target(request.target):
        raise HTTPException(status_code=400, detail="Invalid target format. Use IP address or hostname.")

    if not shutil.which('traceroute'):
        raise HTTPException(status_code=503, detail="traceroute is not installed on this system")

    try:
        proc = await asyncio.create_subprocess_exec(
            'traceroute', '-n', '-m', '30', '-w', '2', request.target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=60)
        raw_output = stdout.decode() + (stderr.decode() if stderr else "")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Traceroute timed out after 60 seconds")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Traceroute failed: {str(e)}")

    hops: List[Dict[str, Any]] = []
    for line in raw_output.strip().split('\n'):
        line = line.strip()
        if not line or line.startswith('traceroute'):
            continue
        match = re.match(r'^\s*(\d+)\s+(.+)$', line)
        if not match:
            continue
        hop_num = int(match.group(1))
        rest = match.group(2).strip()

        if rest == '* * *' or all(c in '* ' for c in rest):
            hops.append({"hop": hop_num, "ip": None, "rtt_ms": None, "is_timeout": True})
            continue

        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', rest)
        ip_addr = ip_match.group(1) if ip_match else None

        rtts = [float(v) for v in re.findall(r'([\d.]+)\s*ms', rest)]

        hops.append({
            "hop": hop_num,
            "ip": ip_addr,
            "rtt_ms": rtts if rtts else None,
            "is_timeout": False,
        })

    return {
        "target": request.target,
        "hops": hops,
        "raw_output": raw_output,
    }


class PingSweepRequest(BaseModel):
    target: str


@router.post("/ping-sweep")
async def ping_sweep(
    request: PingSweepRequest,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    if not _validate_target(request.target):
        raise HTTPException(status_code=400, detail="Invalid target format. Use IP address or CIDR notation (e.g. 192.168.1.0/24).")

    if not shutil.which('nmap'):
        raise HTTPException(status_code=503, detail="nmap is not installed on this system")

    try:
        proc = await asyncio.create_subprocess_exec(
            'nmap', '-sn', '-T4', request.target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=120)
        raw_output = stdout.decode() + (stderr.decode() if stderr else "")
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Ping sweep timed out after 120 seconds")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Ping sweep failed: {str(e)}")

    hosts: List[Dict[str, Any]] = []
    lines = raw_output.split('\n')
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        report_match = re.match(r'Nmap scan report for\s+(.+)', line)
        if report_match:
            host_info = report_match.group(1).strip()
            ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', host_info)
            ip = ip_match.group(1) if ip_match else host_info
            hostname = host_info.split('(')[0].strip() if '(' in host_info else None

            status = "unknown"
            latency = None
            if i + 1 < len(lines):
                next_line = lines[i + 1].strip()
                if "Host is up" in next_line:
                    status = "up"
                    lat_match = re.search(r'\(([\d.]+)s?\s*latency\)', next_line)
                    if lat_match:
                        try:
                            latency = f"{float(lat_match.group(1)) * 1000:.1f}ms"
                        except ValueError:
                            pass
                elif "Host seems down" in next_line:
                    status = "down"

            host_entry: Dict[str, Any] = {"ip": ip, "status": status}
            if hostname and hostname != ip:
                host_entry["hostname"] = hostname
            if latency:
                host_entry["latency"] = latency
            hosts.append(host_entry)
        i += 1

    return {
        "target": request.target,
        "hosts": hosts,
        "total_found": len(hosts),
        "raw_output": raw_output,
    }


class DnsLookupRequest(BaseModel):
    target: str


@router.post("/dns-lookup")
async def dns_lookup(
    request: DnsLookupRequest,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    target = request.target.strip()
    if not target or len(target) > 256:
        raise HTTPException(status_code=400, detail="Invalid target")
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.\-]+$', target):
        raise HTTPException(status_code=400, detail="Invalid hostname format")

    records: Dict[str, List[str]] = {}

    for record_type in ['A', 'AAAA', 'MX', 'NS', 'CNAME', 'TXT', 'SOA']:
        try:
            if shutil.which('dig'):
                proc = await asyncio.create_subprocess_exec(
                    'dig', '+short', record_type, target,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            elif shutil.which('nslookup'):
                proc = await asyncio.create_subprocess_exec(
                    'nslookup', f'-type={record_type}', target,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
            else:
                proc = await asyncio.create_subprocess_exec(
                    'host', '-t', record_type, target,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )

            stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=10)
            output = stdout.decode().strip()
            if output:
                entries = [line.strip() for line in output.split('\n') if line.strip() and not line.startswith(';')]
                if entries:
                    records[record_type] = entries
        except (asyncio.TimeoutError, Exception):
            continue

    return {
        "target": target,
        "records": records,
    }


class WhoisRequest(BaseModel):
    target: str


@router.post("/whois")
async def whois_lookup(
    request: WhoisRequest,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    target = request.target.strip()
    if not target or len(target) > 256:
        raise HTTPException(status_code=400, detail="Invalid target")
    if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.\-:]+$', target):
        raise HTTPException(status_code=400, detail="Invalid target format")

    if not shutil.which('whois'):
        raise HTTPException(status_code=503, detail="Whois tool not available. Install with: apt install whois")

    try:
        proc = await asyncio.create_subprocess_exec(
            'whois', target,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=15)
        output = stdout.decode(errors="replace")
        err_output = stderr.decode(errors="replace") if stderr else ""

        dns_error_patterns = [
            "getaddrinfo",
            "Servname not supported",
            "Name or service not known",
            "No address associated",
            "Temporary failure in name resolution",
            "Connection refused",
            "Network is unreachable",
        ]
        combined = output + err_output
        if any(pat.lower() in combined.lower() for pat in dns_error_patterns):
            raise HTTPException(
                status_code=502,
                detail="Whois lookup failed: Unable to reach whois server. This may be due to network restrictions in this environment.",
            )

        if proc.returncode and proc.returncode != 0 and not output.strip():
            raise HTTPException(
                status_code=502,
                detail=f"Whois lookup failed: {err_output.strip() or 'Unknown error from whois command'}",
            )

        result = output + err_output if not output.strip() else output
    except HTTPException:
        raise
    except asyncio.TimeoutError:
        raise HTTPException(status_code=504, detail="Whois lookup timed out after 15 seconds. Try again later.")
    except FileNotFoundError:
        raise HTTPException(status_code=503, detail="Whois tool not available. Install with: apt install whois")
    except Exception as e:
        error_msg = str(e)
        if any(p in error_msg.lower() for p in ["getaddrinfo", "name resolution", "servname"]):
            raise HTTPException(
                status_code=502,
                detail="Whois lookup failed: Unable to reach whois server. This may be due to network restrictions in this environment.",
            )
        raise HTTPException(status_code=500, detail=f"Whois lookup failed: An unexpected error occurred. Please try again.")

    return {
        "target": target,
        "result": result,
    }


class CaptureRequest(BaseModel):
    interface: str = "any"
    filter: str = ""
    duration: int = 10
    count: int = 100


@router.post("/capture")
async def packet_capture(
    request: CaptureRequest,
    current_user: User = Depends(get_current_user),
) -> Dict[str, Any]:
    if not shutil.which('tcpdump'):
        raise HTTPException(status_code=503, detail="tcpdump is not installed on this system")

    if request.duration < 1 or request.duration > 60:
        raise HTTPException(status_code=400, detail="Duration must be between 1 and 60 seconds")
    if request.count < 1 or request.count > 1000:
        raise HTTPException(status_code=400, detail="Packet count must be between 1 and 1000")

    iface = request.interface.strip()
    if not re.match(r'^[a-zA-Z0-9]+$', iface):
        raise HTTPException(status_code=400, detail="Invalid interface name")

    bpf_filter = request.filter.strip()
    if bpf_filter and not re.match(r'^[a-zA-Z0-9\s\.\:\-\/\!\(\)]+$', bpf_filter):
        raise HTTPException(status_code=400, detail="Invalid BPF filter")

    cmd = ['tcpdump', '-i', iface, '-c', str(request.count), '-nn', '-tttt', '-l']
    if bpf_filter:
        cmd.extend(bpf_filter.split())

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(),
            timeout=request.duration + 5,
        )
        raw_output = stdout.decode()
        stderr_output = stderr.decode() if stderr else ""
    except asyncio.TimeoutError:
        try:
            proc.terminate()
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5)
            raw_output = stdout.decode() if stdout else ""
            stderr_output = stderr.decode() if stderr else ""
        except Exception:
            raw_output = ""
            stderr_output = "Capture timed out"
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Capture failed: {str(e)}")

    packets: List[Dict[str, str]] = []
    for line in raw_output.strip().split('\n'):
        line = line.strip()
        if not line:
            continue
        ts_match = re.match(r'^(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+)\s+(.+)', line)
        if ts_match:
            timestamp = ts_match.group(1)
            rest = ts_match.group(2)
        else:
            timestamp = ""
            rest = line

        parts = rest.split()
        protocol = ""
        source = ""
        destination = ""
        length = ""
        info = rest

        if "IP" in parts or "IP6" in parts:
            try:
                ip_idx = parts.index("IP") if "IP" in parts else parts.index("IP6")
                protocol = parts[ip_idx]
                if ip_idx + 1 < len(parts):
                    source = parts[ip_idx + 1].rstrip(':')
                if ip_idx + 3 < len(parts) and parts[ip_idx + 2] == '>':
                    destination = parts[ip_idx + 3].rstrip(':')
                len_match = re.search(r'length\s+(\d+)', rest)
                if len_match:
                    length = len_match.group(1)
            except (ValueError, IndexError):
                pass
        elif "ARP" in parts:
            protocol = "ARP"

        packets.append({
            "timestamp": timestamp,
            "source": source,
            "destination": destination,
            "protocol": protocol,
            "length": length,
            "info": info[:200],
        })

    capture_summary = ""
    summary_match = re.search(r'(\d+)\s+packets?\s+captured', stderr_output)
    if summary_match:
        capture_summary = f"{summary_match.group(1)} packets captured"

    return {
        "packets": packets,
        "raw_output": raw_output,
        "summary": capture_summary,
        "total_packets": len(packets),
    }
