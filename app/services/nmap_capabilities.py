"""Detect what the local nmap install supports and plan scans around it.

nmap is a hard requirement for scan execution, but *which* command is best
depends on the installation: raw-socket privileges decide between a SYN and a
TCP connect scan, and the NSE script directory decides whether a vulnerability
scan can run targeted checks or only the generic ``vuln`` category.

``detect_capabilities`` probes all of that once and caches the snapshot for
:data:`CAPABILITY_TTL_SECONDS`. ``plan_command`` turns a named profile plus that
snapshot into an argv list -- never a shell string -- so callers can hand it
straight to ``asyncio.create_subprocess_exec``.
"""
from __future__ import annotations

import os
import re
import shutil
import struct
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

CAPABILITY_TTL_SECONDS = 300

# Bump this (and the entries below) whenever the catalog is refreshed. The
# version is surfaced in scan notes and in GET /nmap/capabilities so operators
# can tell which list a scan used.
CATALOG_VERSION = "2026.10"

# Installed NSE script stem -> what it checks. Only scripts that ship with
# modern nmap belong here; detect_capabilities intersects this catalog with the
# files actually on disk, so a stale entry is harmless but a wrong CVE is not.
VULN_SCRIPT_CATALOG: dict[str, dict[str, str | None]] = {
    "smb-vuln-ms17-010": {
        "cve": "CVE-2017-0143",
        "summary": "EternalBlue SMBv1 remote code execution (MS17-010).",
    },
    "smb-vuln-ms08-067": {
        "cve": "CVE-2008-4250",
        "summary": "Windows Server service SMB path handling remote code execution (MS08-067).",
    },
    "smb-vuln-cve2009-3103": {
        "cve": "CVE-2009-3103",
        "summary": "SMB2 malformed packet denial of service (MS09-050).",
    },
    "smb-vuln-cve-2017-7494": {
        "cve": "CVE-2017-7494",
        "summary": "Samba shared-library loading remote code execution (SambaCry).",
    },
    "http-vuln-cve2017-5638": {
        "cve": "CVE-2017-5638",
        "summary": "Apache Struts 2 Jakarta Multipart parser remote code execution.",
    },
    "http-vuln-cve2014-3704": {
        "cve": "CVE-2014-3704",
        "summary": "Drupal SQL injection (Drupalgeddon).",
    },
    "http-vuln-cve2015-1635": {
        "cve": "CVE-2015-1635",
        "summary": "Windows HTTP.sys range header remote code execution (MS15-034).",
    },
    "http-vuln-cve2012-1823": {
        "cve": "CVE-2012-1823",
        "summary": "PHP-CGI query-string argument injection and remote code execution.",
    },
    "http-vuln-cve2010-0738": {
        "cve": "CVE-2010-0738",
        "summary": "JBoss JMX console authentication bypass.",
    },
    "ssl-heartbleed": {
        "cve": "CVE-2014-0160",
        "summary": "OpenSSL Heartbeat information disclosure (Heartbleed).",
    },
    "ssl-poodle": {
        "cve": "CVE-2014-3566",
        "summary": "SSLv3 CBC padding oracle (POODLE).",
    },
    "ssl-ccs-injection": {
        "cve": "CVE-2014-0224",
        "summary": "OpenSSL ChangeCipherSpec man-in-the-middle injection.",
    },
    "ssl-dh-params": {
        "cve": None,
        "summary": "Weak or common Diffie-Hellman parameters (Logjam class; no single CVE).",
    },
    "rdp-vuln-ms12-020": {
        "cve": None,
        "summary": "Remote Desktop denial of service (MS12-020; CVE varies by bulletin).",
    },
    "ftp-vuln-cve2010-4221": {
        "cve": "CVE-2010-4221",
        "summary": "ProFTPD response-pool buffer overflow.",
    },
    "mysql-vuln-cve2012-2122": {
        "cve": "CVE-2012-2122",
        "summary": "MySQL authentication bypass after repeated failed logins.",
    },
    "smtp-vuln-cve2011-1764": {
        "cve": "CVE-2011-1764",
        "summary": "Exim DKIM format-string vulnerability.",
    },
    "http-shellshock": {
        "cve": "CVE-2014-6271",
        "summary": "Bash environment-function injection reachable through CGI (Shellshock).",
    },
}

NMAP_INSTALL_HINT = (
    "nmap is required but was not found on PATH. Install it with your package manager "
    "(for example 'apt install nmap' or 'brew install nmap'), or from "
    "https://nmap.org/download, then restart Netpulse."
)

_MAX_SCRIPT_FILES = 2000
_SCRIPT_HEADER_BYTES = 4096

_SCRIPTS_DIR_CANDIDATES: tuple[str, ...] = (
    "/usr/share/nmap/scripts",
    "/usr/local/share/nmap/scripts",
    r"C:\Program Files (x86)\Nmap\scripts",
    r"C:\Program Files\Nmap\scripts",
)

_VERSION_PATTERN = re.compile(r"Nmap version\s+(\S+)")
_CATEGORIES_PATTERN = re.compile(r"categories\s*=\s*\{([^}]*)\}")


class NmapUnavailableError(RuntimeError):
    """Raised when a scan plan is requested but nmap is not installed."""


@dataclass(frozen=True)
class NmapCapabilities:
    """Snapshot of what the local nmap install can do."""

    available: bool
    version: str | None
    privileged: bool
    script_categories: frozenset[str]
    vuln_scripts: tuple[str, ...]
    scripts_dir: str | None
    detected_at: datetime


@dataclass(frozen=True)
class NmapPlan:
    """A ready-to-execute nmap invocation.

    ``argv`` is passed to ``create_subprocess_exec`` as-is; the target is always
    the last element so it can never be mistaken for an option.
    """

    profile: str
    argv: list[str]
    display: str
    notes: list[str]
    vuln_scripts: list[str]


# (id, label, description), in the order the UI should offer them.
_PROFILES: tuple[tuple[str, str, str], ...] = (
    ("sweep", "Ping Sweep", "Host discovery only: find live hosts without scanning ports."),
    ("quick", "Quick Scan", "The 100 most common TCP ports with light timing."),
    ("services", "Service Detection", "Version detection on the most common TCP ports."),
    ("full", "Full Port Scan", "All 65535 TCP ports with a minimum packet rate."),
    ("vuln", "Vulnerability Scan", "Version detection plus installed vulnerability NSE scripts."),
)
_PROFILE_IDS = frozenset(profile_id for profile_id, _label, _description in _PROFILES)


# Module-level cache; a timestamp check instead of lru_cache so `force=True`
# can bypass it and so the dataclass stays a plain value object.
_capabilities_cache: NmapCapabilities | None = None
_capabilities_cache_at: float = 0.0


def detect_capabilities(force: bool = False) -> NmapCapabilities:
    """Return the cached capability snapshot, re-probing when stale or forced.

    Never raises: a broken nmap binary or an unreadable scripts directory
    degrades to ``version=None`` and no scripts instead of failing the caller.
    """
    global _capabilities_cache, _capabilities_cache_at

    now = time.monotonic()
    if (
        not force
        and _capabilities_cache is not None
        and now - _capabilities_cache_at < CAPABILITY_TTL_SECONDS
    ):
        return _capabilities_cache

    capabilities = _probe_capabilities()
    _capabilities_cache = capabilities
    _capabilities_cache_at = now
    return capabilities


def available_profiles() -> list[dict[str, str]]:
    """Scan profiles the planner understands, in presentation order."""
    return [
        {"id": profile_id, "label": label, "description": description}
        for profile_id, label, description in _PROFILES
    ]


def plan_command(
    profile: str,
    target: str,
    caps: NmapCapabilities,
    ports: str | None = None,
) -> NmapPlan:
    """Build an argv list for *profile* against *target*.

    Raises NmapUnavailableError when nmap is missing and ValueError for an
    unknown profile. The target is appended last as its own argv element.
    """
    if not caps.available:
        raise NmapUnavailableError(NMAP_INSTALL_HINT)

    canonical = (profile or "").strip().lower()
    if canonical not in _PROFILE_IDS:
        choices = ", ".join(profile_id for profile_id, _label, _description in _PROFILES)
        raise ValueError(f"Unknown nmap profile: {profile!r}. Choose one of: {choices}")

    target = (target or "").strip()
    scan_flag = "-sS" if caps.privileged else "-sT"
    notes: list[str] = []
    vuln_scripts: list[str] = []
    installed_vuln = sorted(set(caps.vuln_scripts) & set(VULN_SCRIPT_CATALOG))

    # Without raw sockets nmap cannot craft ARP/ICMP itself: `--unprivileged`
    # makes it discover hosts with TCP connect() instead, and `-Pn` stops it
    # from trying (and dying on) a raw ping probe first.
    unprivileged_args = [] if caps.privileged else ["--unprivileged", "-Pn"]

    if canonical == "sweep":
        # `-Pn` belongs nowhere near `-sn`: it tells nmap every address is up,
        # which turns a ping sweep into a list of all 256 hosts. `-PE` needs a
        # raw socket, so it is only offered when raw access actually exists.
        if caps.privileged:
            argv = ["nmap", "-sn", "-PE", "-PS22,80,443", "-T4", target]
        else:
            argv = ["nmap", "-sn", "-PS22,80,443", "-T4", "--unprivileged", target]
        notes.append("host discovery only")
        if not caps.privileged:
            notes.append(
                "No raw-socket access (Npcap driver stopped or no root): "
                "discovering via TCP connect instead of ARP/ICMP"
            )
    elif canonical == "quick":
        argv = ["nmap", scan_flag]
        if ports:
            argv.extend(["-p", ports])
        else:
            argv.append("-F")
        argv.extend(["--max-retries", "2", "-T4", *unprivileged_args, target])
    elif canonical == "services":
        argv = [
            "nmap", scan_flag, "-sV", "--version-light", "-F", "-T4",
            *unprivileged_args, target,
        ]
    elif canonical == "full":
        argv = [
            "nmap", scan_flag, "-p-", "--min-rate", "1000", "--max-retries", "2",
            "-T4", *unprivileged_args, target,
        ]
    else:  # vuln
        argv = ["nmap", scan_flag, "-sV", "-T4"]
        if installed_vuln:
            vuln_scripts = installed_vuln
            argv.extend(["--script", ",".join(installed_vuln)])
            notes.append(f"Targeted vulnerability checks: {len(installed_vuln)} installed catalog scripts")
        elif "vuln" in caps.script_categories:
            argv.extend(["--script", "vuln"])
            notes.append("Installed vulnerability scripts not found; using the generic 'vuln' NSE category")
        else:
            notes.append(
                "The 'vuln' NSE category is unavailable and no catalog scripts are installed; "
                "running service detection only"
            )
        notes.append(
            f"Vulnerability script catalog {CATALOG_VERSION}: "
            f"{len(installed_vuln)} of {len(VULN_SCRIPT_CATALOG)} scripts installed"
        )
        argv.extend([*unprivileged_args, target])

    if not caps.privileged and canonical != "sweep":
        notes.append("No raw-socket privileges, using TCP connect scan")

    return NmapPlan(
        profile=canonical,
        argv=argv,
        display=" ".join(argv),
        notes=notes,
        vuln_scripts=vuln_scripts,
    )


def _probe_capabilities() -> NmapCapabilities:
    """Run the actual detection. Kept separate so the cache stays trivial."""
    nmap_path = shutil.which("nmap")
    scripts_dir = _find_scripts_dir()
    script_files = _list_script_files(scripts_dir)
    installed_scripts = {path.stem for path in script_files}

    return NmapCapabilities(
        available=nmap_path is not None,
        version=_read_version(nmap_path is not None),
        privileged=_has_raw_socket_privileges(),
        script_categories=frozenset(_collect_categories(script_files)),
        vuln_scripts=tuple(sorted(installed_scripts & set(VULN_SCRIPT_CATALOG))),
        scripts_dir=str(scripts_dir) if scripts_dir is not None else None,
        detected_at=datetime.now(timezone.utc),
    )


def _read_version(available: bool) -> str | None:
    """Parse the first 'Nmap version X.Y' line; None on any failure."""
    if not available:
        return None

    try:
        completed = subprocess.run(
            ["nmap", "--version"],
            capture_output=True,
            timeout=5,
            text=True,
            check=False,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return None

    output = f"{completed.stdout or ''}\n{completed.stderr or ''}"
    match = _VERSION_PATTERN.search(output)
    return match.group(1) if match else None


def _npcap_driver_running() -> bool:
    """True when the Npcap/WinPcap packet driver is actually running.

    Windows grants SYN scans through Npcap rather than EUID 0, but only while
    its kernel driver is started. A machine can have Npcap *installed* with the
    driver stopped or disabled, and then every raw scan dies with "dnet: Failed
    to open device <iface>" — a failure that looks like a Netpulse bug from the
    UI. Querying the service is the reliable signal; sc.exe is present on every
    Windows install and needs no elevation to read status.
    """
    for service in ("npcap", "npf"):
        try:
            completed = subprocess.run(
                ["sc", "query", service],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, ValueError, subprocess.SubprocessError):
            continue
        if "RUNNING" in (completed.stdout or ""):
            return True
    return False


# CAP_NET_RAW in the Linux capability numbering.
_CAP_NET_RAW = 13


def _linux_process_has_cap_net_raw() -> bool:
    """CAP_NET_RAW bit of this process's effective set, or False.

    Linux grants raw sockets by capability rather than only by UID, so a
    service account can scan raw without being root.
    """
    try:
        with open("/proc/self/status", encoding="utf-8") as handle:
            for line in handle:
                if line.startswith("CapEff:"):
                    mask = int(line.split(":", 1)[1].strip(), 16)
                    return bool((mask >> _CAP_NET_RAW) & 1)
    except (OSError, ValueError):
        return False
    return False


def _linux_binary_has_cap_net_raw(path: str | None) -> bool:
    """True when *path* carries CAP_NET_RAW with file capabilities enabled.

    ``sudo setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap`` is the common
    way to let a non-root install scan raw. Those bits live on the binary and
    are applied to nmap when it is executed, so reading our own CapEff would
    wrongly report the box as unprivileged.
    """
    getxattr = getattr(os, "getxattr", None)
    if not path or getxattr is None:
        return False

    try:
        raw = getxattr(path, "security.capability")
    except OSError:
        return False
    if len(raw) < 12:
        return False

    # struct vfs_cap_data: magic (revision | VFS_CAP_FLAGS_EFFECTIVE), then
    # permitted/inheritable words in host byte order (little-endian here).
    magic = struct.unpack("<I", raw[:4])[0]
    if not magic & 0x1:
        return False
    if (magic & 0xFF000000) not in (0x02000000, 0x03000000):
        return False

    permitted_low = struct.unpack("<I", raw[4:8])[0]
    return bool((permitted_low >> _CAP_NET_RAW) & 1)


def _npcap_can_enumerate_devices() -> bool:
    """True when nmap can actually list the interfaces a raw scan would use.

    The Npcap service can report RUNNING while its device list is unusable — a
    half-installed driver fails ``PacketGetAdapterNames`` with error 259 — and
    every raw scan then dies at run time with ``dnet: Failed to open device
    eth<N>``. Checking the service alone therefore over-reports privilege, and
    the failure surfaces in the UI as a scan that started and instantly failed
    for no visible reason.

    ``nmap --iflist`` is the authoritative answer: it exits non-zero and prints
    QUITTING when pcap is unusable, and exits 0 on a working install.
    """
    try:
        completed = subprocess.run(
            ["nmap", "--iflist"],
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        return False

    if completed.returncode != 0:
        return False

    output = f"{completed.stdout or ''}{completed.stderr or ''}"
    return "pcap_findalldevs" not in output and "QUITTING" not in output


def _has_raw_socket_privileges() -> bool:
    """True when nmap may open raw sockets.

    On Windows Npcap's driver handles raw sockets, so an ordinary user can run
    SYN scans — provided the driver is running *and* nmap can enumerate the
    devices behind it. On Linux it is EUID 0 or CAP_NET_RAW, either on this
    process or on the nmap binary itself.
    """
    if os.name == "nt":
        return _npcap_driver_running() and _npcap_can_enumerate_devices()

    geteuid = getattr(os, "geteuid", None)
    if geteuid is not None:
        try:
            if geteuid() == 0:
                return True
        except OSError:
            pass

    if sys.platform.startswith("linux"):
        return _linux_process_has_cap_net_raw() or _linux_binary_has_cap_net_raw(
            shutil.which("nmap")
        )

    return False


def _find_scripts_dir() -> Path | None:
    """First existing candidate scripts directory, or None."""
    for candidate in _SCRIPTS_DIR_CANDIDATES:
        path = Path(candidate)
        try:
            if path.is_dir():
                return path
        except OSError:
            continue
    return None


def _list_script_files(scripts_dir: Path | None) -> list[Path]:
    """Sorted .nse files, capped so a pathological directory stays cheap."""
    if scripts_dir is None:
        return []
    try:
        files = sorted(scripts_dir.glob("*.nse"), key=lambda path: path.name)
    except OSError:
        return []
    return files[:_MAX_SCRIPT_FILES]


def _collect_categories(script_files: list[Path]) -> set[str]:
    """Union of ``categories = {...}`` tokens from each script header.

    Only the first 4096 bytes are read: nmap puts the categories assignment in
    the script header, so there is no need to load multi-megabyte scripts.
    """
    categories: set[str] = set()

    for path in script_files:
        try:
            with path.open("rb") as handle:
                header = handle.read(_SCRIPT_HEADER_BYTES)
        except OSError:
            # Unreadable script: skip it, the rest of the catalog is still useful.
            continue

        match = _CATEGORIES_PATTERN.search(header.decode("utf-8", errors="replace"))
        if match is None:
            continue

        for token in re.split(r"[,\s]+", match.group(1)):
            token = token.strip().strip("\"'")
            if token:
                categories.add(token)

    return categories
