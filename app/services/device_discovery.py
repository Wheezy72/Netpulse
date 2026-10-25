"""Device-only network discovery.

The deliberately light-weight counterpart to the nmap scan pipeline. It answers
exactly one question — *what hosts are on this network?* — and writes them into
the ``devices`` table so the inventory and the detail drawer have something to
show. No port scanning, no NSE scripts, no vulnerability probing.

Two sweep strategies, used together where possible:

1. **ARP sweep** (scapy ``srp``) — fast and trustworthy on a directly attached
   L2 segment, since ARP cannot be filtered the way ICMP can. Needs raw-socket
   privileges (root / CAP_NET_RAW, or Npcap on Windows).
2. **nmap ``-sn`` ping sweep** — works for routed ranges we are not L2-adjacent
   to, and is the fallback when raw sockets are unavailable. Requires the nmap
   binary.

Whichever strategy runs, results are enriched the same way (reverse DNS, OUI
vendor, type/OS heuristics) and upserted through a single code path, so the
on-demand endpoint and the background beat task can never drift apart.

Import discipline: this module imports stdlib only at module level. ``scapy``
and ``nmap`` are imported inside the functions that need them, and SQLAlchemy
inside the upsert. That keeps the module importable — and its parsing and
classification logic testable — in the minimal CI environment, which installs
neither scapy, nmap, nor SQLAlchemy.
"""
from __future__ import annotations

import asyncio
import logging
import socket
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from app.core.config import settings
from app.services import fingerprint
from app.services.oui import is_locally_administered, lookup_vendor, normalize_mac
from app.services.scan_policy import is_restricted_target, subnets_to_sweep, validate_target

logger = logging.getLogger("netpulse.device_discovery")

# A discovery sweep is I/O heavy; never let two run at once against the network.
_discovery_lock = asyncio.Lock()

DEFAULT_ARP_TIMEOUT = 2.0
DEFAULT_HOST_TIMEOUT = 60
REVERSE_DNS_TIMEOUT = 0.5


@dataclass(slots=True)
class DiscoveredHost:
    """A single host observed on the network, before or after enrichment."""

    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_type: Optional[str] = None
    os: Optional[str] = None
    is_gateway: bool = False
    source: str = "arp"


@dataclass(slots=True)
class DiscoveryOutcome:
    """Everything a caller needs to explain the result to a human."""

    hosts: List[DiscoveredHost] = field(default_factory=list)
    created: int = 0
    updated: int = 0
    subnets: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=list)
    skipped_restricted: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def classify_host(
    hostname: Optional[str],
    vendor: Optional[str],
    *,
    is_gateway: bool = False,
    mac_address: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """Guess ``(device_type, os)`` from hostname, vendor and MAC.

    Returns ``(None, None)`` when there is no positive evidence. An earlier
    version of this heuristic labelled every unrecognised host
    "Linux Workstation" — a confident claim with nothing behind it — which is
    worse than showing "Unknown" in the UI.

    Randomised MACs (the default on Android, iOS, Windows and macOS for
    privacy) carry no real vendor prefix, so the hostname/vendor rules below
    would misfire — e.g. a phone whose random MAC happened to collide with an
    "HP" OUI getting called a Windows workstation. When the MAC is locally
    administered we only trust an explicit hostname match and never fall back
    to the vendor rules, because those vendor strings cannot be relied on.
    """
    h = (hostname or "").lower()
    v = (vendor or "").lower()
    randomised_mac = is_locally_administered(mac_address)

    # Hostname rules first — a hostname is self-reported and stands on its own.
    if is_gateway or any(k in h for k in ("router", "gateway", "pfsense", "opnsense")):
        return "Router", "Linux/Embedded"
    if any(k in h for k in ("switch", "cisco", "catalyst")):
        return "Switch (Cisco)", "Cisco IOS"
    if "printer" in h or any(k in h for k in ("laserjet", "deskjet", "officejet", "pixma", "ecotank", "workcentre")):
        return "Printer", "Embedded"
    if any(k in h for k in ("nas", "storage", "synology", "qnap")):
        return "NAS", "Linux/Embedded"
    if any(k in h for k in ("tv", "roku", "chromecast", "firetv", "appletv")):
        return "Smart TV", "Android/tvOS"
    if any(k in h for k in ("iphone", "ipad")):
        return "Phone/Tablet (Apple)", "iOS"
    if any(
        k in h
        for k in (
            "android", "pixel", "galaxy", "oneplus", "redmi", "xiaomi",
            "sm-g", "sm-a", "sm-s", "huawei", "honor", "oppo", "vivo",
            "realme", "nothing-phone", "motorola", "moto-",
        )
    ):
        return "Phone/Tablet (Android)", "Android"
    if any(
        k in h
        for k in (
            "desktop-", "laptop-", "win-", "windows", "win11", "win10",
            "surface", "thinkpad", "ideapad", "pavilion", "vostro",
            "inspiron", "latitude", "thinkcentre", "elitedesk",
        )
    ) or h.endswith("-pc") or h.startswith("pc-"):
        return "Windows Workstation", "Windows"
    if any(k in h for k in ("macbook", "imac", "mac-mini", "macmini")):
        return "Apple Computer", "macOS"
    if any(k in h for k in ("ubuntu", "debian", "fedora", "centos", "archlinux", "raspberry")):
        return "Linux Workstation", "Linux"

    # Nothing in the hostname. A randomised MAC carries no real vendor prefix,
    # so every rule below that leans on the vendor string would be a guess
    # dressed as fact (a phone whose random MAC collided with an "HP" OUI
    # getting called a Windows workstation). Report the honest answer instead.
    if randomised_mac:
        return None, None

    if "printer" in v or v in ("epson", "canon", "brother"):
        return "Printer", "Embedded"
    if v in ("apple", "samsung"):
        return None, None
    if v in ("intel", "microsoft", "dell", "hp"):
        return "Windows Workstation", None
    return None, None


def hostname_from_entry(entry: Dict[str, Any]) -> Optional[str]:
    """Extract the first usable hostname from a python-nmap host entry."""
    for record in entry.get("hostnames") or []:
        name = (record or {}).get("name")
        if name:
            return str(name)
    return None


def hosts_from_scan_data(scan_data: Dict[str, Any]) -> List[DiscoveredHost]:
    """Convert python-nmap's ``scan`` mapping into :class:`DiscoveredHost` list.

    Kept pure and dependency-free on purpose: this is the piece worth testing,
    so it takes a plain dict rather than a live ``PortScanner``.
    """
    hosts: List[DiscoveredHost] = []
    for host_key, entry in (scan_data or {}).items():
        if not isinstance(entry, dict):
            continue

        status = (entry.get("status") or {}).get("state")
        if status == "down":
            continue

        addresses = entry.get("addresses") or {}
        ip_address = addresses.get("ipv4") or addresses.get("ipv6") or host_key
        if not ip_address:
            continue

        mac = normalize_mac(addresses.get("mac"))
        vendor = None
        for mac_key, vendor_name in (entry.get("vendor") or {}).items():
            if normalize_mac(mac_key) == (mac or normalize_mac(mac_key)):
                vendor = vendor_name or None
                break
        # nmap only reports a vendor when it was able to fingerprint the host.
        vendor = vendor or lookup_vendor(mac)

        hostname = hostname_from_entry(entry)
        device_type, os_label = classify_host(hostname, vendor, mac_address=mac)

        hosts.append(
            DiscoveredHost(
                ip_address=str(ip_address),
                mac_address=mac,
                hostname=hostname,
                vendor=vendor,
                device_type=device_type,
                os=os_label,
                source="nmap",
            )
        )
    return hosts


def hosts_from_arp_pairs(
    pairs: Iterable[Tuple[str, str]],
    *,
    vendor_overrides: Optional[Dict[str, str]] = None,
) -> List[DiscoveredHost]:
    """Build unenriched hosts from ``(ip, mac)`` pairs observed via ARP."""
    overrides = vendor_overrides or {}
    hosts: List[DiscoveredHost] = []
    seen: set[str] = set()

    for ip_address, mac in pairs:
        if not ip_address or ip_address in seen:
            continue
        seen.add(ip_address)
        mac_normalized = normalize_mac(mac)
        hosts.append(
            DiscoveredHost(
                ip_address=ip_address,
                mac_address=mac_normalized,
                vendor=overrides.get(ip_address) or lookup_vendor(mac_normalized),
                source="arp",
            )
        )
    return hosts


def os_from_ttl(
    ttl: Optional[int],
    *,
    mac_address: Optional[str] = None,
) -> Tuple[Optional[str], Optional[str]]:
    """Coarse OS family from an ICMP reply's TTL.

    TTL is a real signal rather than a guess: hosts decrement it from their
    stack's initial value, and the initial value is effectively fixed per
    family (64 Unix-like, 128 Windows, 255 network gear). It cannot separate
    Android from Linux from macOS on its own, so the MAC is used to narrow it:
    a locally administered (randomised) address on a 64-TTL host is the
    signature of a phone or tablet, both of which rotate their MAC per network
    and neither of which answers NBNS.

    Returns ``(device_type, os)`` with ``(None, None)`` when TTL is unknown.
    """
    if ttl is None:
        return None, None

    randomised = is_locally_administered(mac_address)
    if ttl <= 64:
        if randomised:
            return "Mobile device", "Android/Linux"
        return None, "Linux/Unix"
    if ttl <= 128:
        return "Windows Workstation", "Windows"
    return "Network device", "Embedded"


def _gateway_from_os_commands() -> Optional[str]:
    """Read the default gateway straight from the OS when scapy is absent.

    Each platform gets its own fixed command and parser:
      * Linux:   ``ip route show default``  → "default via 192.168.1.1 …"
      * Windows: ``route print 0.0.0.0``    → the first 0.0.0.0 row's gateway
      * macOS:   ``route -n get default``   → "gateway: 192.168.1.1"

    All arguments are fixed literals; nothing user-controlled reaches a shell.
    """
    import shutil
    import subprocess
    import sys

    def _run(cmd: list[str]) -> str:
        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, shell=False, timeout=5
            )
        except Exception:
            return ""
        return proc.stdout or ""

    try:
        if sys.platform.startswith("linux"):
            if not shutil.which("ip"):
                return None
            for line in _run(["ip", "route", "show", "default"]).splitlines():
                parts = line.split()
                if "via" in parts:
                    candidate = parts[parts.index("via") + 1]
                    if candidate and candidate != "0.0.0.0":
                        return candidate
            return None

        if sys.platform.startswith("win"):
            if not shutil.which("route"):
                return None
            for line in _run(["route", "print", "0.0.0.0"]).splitlines():
                parts = line.split()
                if len(parts) >= 4 and parts[0] == "0.0.0.0":
                    candidate = parts[2]
                    if candidate and candidate != "0.0.0.0":
                        return candidate
            return None

        if sys.platform.startswith("darwin"):
            if not shutil.which("route"):
                return None
            for line in _run(["route", "-n", "get", "default"]).splitlines():
                parts = line.split()
                if parts[:1] == ["gateway"] and len(parts) >= 2:
                    return parts[1]
            return None
    except Exception:
        return None

    return None


def detect_gateway_ips() -> set[str]:
    """IPs that should be flagged ``is_gateway``: the real one and any override.

    The gateway is *detected*, never guessed: scapy asks the kernel routing
    table, and — when scapy is unavailable — the platform's own route tooling
    answers instead. The manual settings override is honoured on top.
    """
    gateway_ips: set[str] = set()

    override = getattr(settings, "pulse_gateway_ip", None)
    if override:
        gateway_ips.add(str(override))

    try:
        from scapy.all import conf

        detected = conf.route.route("0.0.0.0")[2]
        if detected and detected != "0.0.0.0":
            gateway_ips.add(str(detected))
    except Exception:
        # scapy unavailable or no route table — fall back to OS tooling.
        fallback = _gateway_from_os_commands()
        if fallback:
            gateway_ips.add(fallback)

    return gateway_ips


def _os_output(cmd: list[str], timeout: float = 8.0) -> str:
    """stdout of *cmd*, or an empty string when the tool is missing/fails.

    Every caller passes fixed literals, so nothing user-controlled ever
    reaches a command line. Missing tools are common on minimal installs and
    must degrade to "unknown", never to an exception.
    """
    import shutil
    import subprocess

    try:
        if not shutil.which(cmd[0]):
            return ""
        proc = subprocess.run(
            cmd, capture_output=True, text=True, shell=False, timeout=timeout
        )
    except Exception:
        return ""
    return proc.stdout or ""


def _interface_from_os() -> Optional[str]:
    """Default-route interface name from the OS, without scapy or root.

    Linux answers with ``ip route show default`` and macOS with ``route -n get
    default``. This is what makes a USB Wi-Fi adapter work: its name is
    ``wlx0013ef...`` or ``wlan0``, never the ``eth0`` that used to be assumed,
    and scapy cannot report it while the capture driver is not running.
    """
    import sys

    if sys.platform.startswith("linux"):
        for line in _os_output(["ip", "route", "show", "default"]).splitlines():
            parts = line.split()
            if "dev" in parts:
                index = parts.index("dev")
                if index + 1 < len(parts):
                    return parts[index + 1]
        return None

    if sys.platform.startswith("darwin"):
        for line in _os_output(["route", "-n", "get", "default"]).splitlines():
            key, _, value = line.partition(":")
            if key.strip() == "interface" and value.strip():
                return value.strip()
        return None

    return None


def default_interface() -> Optional[str]:
    """Name of the interface carrying the default route, or ``None``.

    scapy is preferred because on Windows its name is the one ``sniff`` wants
    (the Npcap device name); on Linux/macOS the kernel's own answer is used as
    a fallback so discovery works without packet-capture privileges.
    """
    try:
        from scapy.all import conf
    except Exception:
        return _interface_from_os()

    try:
        return conf.route.route("0.0.0.0")[0] or conf.iface or _interface_from_os()
    except Exception:
        return _interface_from_os()


def _primary_local_address() -> Optional[str]:
    """The source address the kernel would use to reach the outside world.

    A UDP ``connect()`` sends no packet; it only asks the routing table, so it
    works without any packet-capture driver.
    """
    for probe in ("1.1.1.1", "8.8.8.8"):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((probe, 53))
            address = sock.getsockname()[0]
        except OSError:
            continue
        finally:
            sock.close()
        if address and not address.startswith("127."):
            return address
    return None


def _subnet_for_address(address: str) -> Optional[str]:
    """``address/prefix`` for the interface that owns *address*, via OS tools.

    Every argument is a fixed literal and nothing user-controlled reaches the
    command line. This is the fallback used when scapy cannot enumerate
    interfaces (typically: packet-capture driver stopped), which previously
    left discovery reporting "could not determine local subnets".
    """
    import ipaddress
    import sys

    _run = _os_output

    def _cidr(netmask: str) -> Optional[str]:
        try:
            network = ipaddress.ip_network(
                f"{address}/{netmask}", strict=False
            )
        except ValueError:
            return None
        return str(network)

    try:
        if sys.platform.startswith("win"):
            lines = _run(["ipconfig"]).splitlines()
            for index, line in enumerate(lines):
                if address not in line or "IPv4" not in line:
                    continue
                # ipconfig prints "Subnet Mask . . . : 255.255.255.0" a couple
                # of lines below the address, inside the same adapter block.
                for follow in lines[index + 1: index + 5]:
                    if "Subnet Mask" in follow or "Subnet mask" in follow:
                        mask = follow.split(":", 1)[-1].strip()
                        return _cidr(mask)
                return None
            return None

        if sys.platform.startswith("linux"):
            for line in _run(["ip", "-o", "-4", "addr", "show"]).splitlines():
                for token in line.split():
                    if token.startswith(f"{address}/"):
                        return _cidr(token.split("/", 1)[1])
            return None

        if sys.platform.startswith("darwin"):
            lines = _run(["ifconfig"]).splitlines()
            for index, line in enumerate(lines):
                if f"inet {address} " not in line:
                    continue
                for token_index, token in enumerate(line.split()):
                    if token == "netmask":
                        raw = line.split()[token_index + 1]
                        try:
                            mask = ipaddress.IPv4Address(int(raw, 16))
                        except ValueError:
                            return None
                        return _cidr(str(mask))
            return None
    except Exception:
        return None

    return None


def local_subnets(iface: Optional[str] = None) -> Tuple[List[str], Optional[str]]:
    """Directly attached subnets worth sweeping.

    Returns ``(subnets, resolved_iface)``. scapy is preferred because it reads
    the routing table directly, but it cannot enumerate interfaces while the
    packet-capture driver is stopped — so the OS's own tooling answers instead
    (``ipconfig`` / ``ip`` / ``ifconfig``). Discovery therefore still knows
    which subnet to sweep on a box without Npcap or root.
    """

    def _compute(net, mask) -> Optional[str]:
        if mask in (0, 0xFFFFFFFF):
            return None
        network = "%d.%d.%d.%d" % (
            (net >> 24) & 0xFF,
            (net >> 16) & 0xFF,
            (net >> 8) & 0xFF,
            net & 0xFF,
        )
        if network.startswith(("127.", "224.", "240.", "255.")):
            return None
        prefix = bin(mask & 0xFFFFFFFF).count("1")
        return f"{network}/{prefix}"

    try:
        from scapy.all import conf
    except Exception:
        conf = None  # type: ignore[assignment]

    if conf is not None:
        try:
            resolved_iface = iface or conf.route.route("0.0.0.0")[0] or conf.iface
        except Exception:
            resolved_iface = iface

        if resolved_iface:
            candidates: List[str] = []
            for net, mask, gateway, route_iface, _addr, _metric in conf.route.routes:
                if route_iface != resolved_iface or gateway != "0.0.0.0":
                    continue
                cidr = _compute(net, mask)
                if cidr:
                    candidates.append(cidr)
            if candidates:
                return subnets_to_sweep(candidates), resolved_iface

    # --- OS fallback -----------------------------------------------------
    address = _primary_local_address()
    if not address:
        return [], None
    cidr = _subnet_for_address(address)
    if not cidr:
        return [], None
    return subnets_to_sweep([cidr]), iface or _interface_from_os()


async def _reverse_dns(ip_address: str, timeout: float = REVERSE_DNS_TIMEOUT) -> Optional[str]:
    """Best-effort PTR lookup that cannot stall the sweep.

    Uses a bounded wait instead of ``socket.setdefaulttimeout()`` — the latter
    mutates process-global state and would affect unrelated callers.
    """
    def _lookup() -> Optional[str]:
        try:
            return socket.gethostbyaddr(ip_address)[0] or None
        except Exception:
            return None

    try:
        return await asyncio.wait_for(asyncio.to_thread(_lookup), timeout=timeout)
    except (asyncio.TimeoutError, asyncio.CancelledError):
        return None
    except Exception:
        return None


async def _fingerprint_host(
    host: DiscoveredHost,
    ssdp_hints: Optional[Dict[str, fingerprint.FingerprintHints]] = None,
) -> fingerprint.FingerprintHints:
    """Best-effort OS probes for one host: DHCP cache, SSDP, NBNS/LLMNR/mDNS.

    Every step is bounded and failure-proof — an unresponsive device just
    yields an empty hint and classification keeps the hostname/OUI verdict.
    """
    hints = fingerprint.dhcp_hint_for(host.mac_address) or fingerprint.FingerprintHints()
    if ssdp_hints:
        hints.merge(ssdp_hints.get(host.ip_address) or fingerprint.FingerprintHints())
    if hints.confidence < fingerprint.MIN_CONFIDENCE:
        try:
            hints.merge(await fingerprint.probe_host(host.ip_address, host.hostname))
        except Exception as exc:  # probes must never break a sweep
            logger.debug("Active fingerprint of %s failed: %s", host.ip_address, exc)
    if logger.isEnabledFor(logging.DEBUG) and hints.os_family:
        logger.debug(
            "Fingerprint %s -> %s (conf %.2f): %s",
            host.ip_address,
            hints.os_family,
            hints.confidence,
            "; ".join(hints.evidence),
        )
    return hints


async def enrich_hosts(
    hosts: Sequence[DiscoveredHost],
    *,
    gateway_ips: Optional[set[str]] = None,
    probe: bool = True,
) -> List[DiscoveredHost]:
    """Fill in hostname, vendor, type/OS and gateway flag for each host.

    When hostname + OUI leave the OS blank, ask the device itself: passive
    DHCP fingerprints first (free), then NBNS/LLMNR/mDNS/SSDP probes. Probe
    hints only ever fill blanks — a hostname verdict keeps priority, same as
    the upsert merge policy. ``probe=False`` skips network probes (tests).
    """
    gateway_ips = gateway_ips if gateway_ips is not None else detect_gateway_ips()

    # One multicast M-SEARCH covers every host on the segment — a per-host
    # SSDP probe would multiply a ~1s wait by the number of devices.
    ssdp_hints: Dict[str, fingerprint.FingerprintHints] = {}
    if probe:
        unknown = [
            h.ip_address
            for h in hosts
            if (not h.device_type or not h.os) and h.ip_address not in gateway_ips
        ]
        if unknown:
            try:
                ssdp_hints = await fingerprint.ssdp_sweep(unknown)
            except Exception as exc:
                logger.debug("SSDP sweep failed: %s", exc)

    async def _enrich(host: DiscoveredHost) -> DiscoveredHost:
        if not host.hostname:
            host.hostname = await _reverse_dns(host.ip_address)
        if not host.vendor:
            host.vendor = lookup_vendor(host.mac_address)
        host.is_gateway = host.ip_address in gateway_ips

        device_type, os_label = classify_host(
            host.hostname,
            host.vendor,
            is_gateway=host.is_gateway,
            mac_address=host.mac_address,
        )
        # A gateway is authoritative: keep the Router label even if the
        # hostname heuristic had nothing to say.
        host.device_type = device_type or host.device_type
        host.os = os_label or host.os

        # OS still unknown? Consult DHCP cache, SSDP, then active probes.
        if probe and (not host.device_type or not host.os) and not host.is_gateway:
            hints = await _fingerprint_host(host, ssdp_hints)
            if not host.hostname and hints.hostname:
                host.hostname = hints.hostname
            hint_type, hint_os = fingerprint.labels_for_hints(hints)
            host.device_type = host.device_type or hint_type
            host.os = host.os or hint_os

        # Still nothing? The host's own ICMP reply carries a TTL, and that is
        # the last free signal before we admit we don't know.
        if probe and (not host.device_type or not host.os):
            ttl_type, ttl_os = await _classify_by_ttl(host)
            host.device_type = host.device_type or ttl_type
            host.os = host.os or ttl_os
        return host

    return list(await asyncio.gather(*(_enrich(host) for host in hosts)))


def arp_sweep(
    subnet: str,
    iface: Optional[str],
    timeout: float,
) -> List[Tuple[str, str]]:
    """Blocking ARP sweep of one subnet, returning ``(ip, mac)`` pairs.

    Public because the background beat task reuses it for its active sweep, so
    there is exactly one implementation of "ask every address who is there".
    Raises on unusable raw sockets; callers decide how to degrade.
    """
    from scapy.all import ARP, Ether, conf, srp

    target_iface = iface or conf.iface
    answered, _unanswered = srp(
        Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet),
        iface=target_iface,
        timeout=timeout,
        retry=0,
        verbose=False,
    )
    pairs: List[Tuple[str, str]] = []
    for _sent, received in answered:
        if received.haslayer(ARP) and received[ARP].psrc and received[ARP].hwsrc:
            pairs.append((str(received[ARP].psrc), str(received[ARP].hwsrc)))
    return pairs


def _ping_command(address: str) -> List[str]:
    """The platform's one-shot ping argv for *address* (fixed literals only)."""
    import sys

    if sys.platform.startswith("win"):
        return ["ping", "-n", "1", "-w", "600", address]
    if sys.platform.startswith("darwin"):
        return ["ping", "-c", "1", "-W", "600", address]
    return ["ping", "-c", "1", "-W", "1", address]


def _ping_replies(completed: Any) -> bool:
    """True when ping's output shows a reply (TTL present, command succeeded)."""
    output = f"{getattr(completed, 'stdout', '') or ''}"
    if getattr(completed, "returncode", 1) != 0:
        return False
    lowered = output.lower()
    return "ttl=" in lowered or "bytes from" in lowered


def _icmp_sweep_sync(target: str, concurrency: int = 64) -> List[str]:
    """Best-effort ICMP sweep using the OS ``ping`` binary.

    ping needs no special privileges and no packet-capture driver, which is
    precisely the situation where nmap's connect() sweep misses phones and
    other hosts that close the common ports. Every probe is a separate argv
    with a validated address — nothing user-supplied reaches a shell.
    """
    import ipaddress
    import subprocess
    from concurrent.futures import ThreadPoolExecutor

    try:
        network = ipaddress.ip_network(target, strict=False)
    except ValueError:
        return []

    hosts = [str(host) for host in network.hosts()]
    # A /24 is cheap; refuse to spawn thousands of ping processes.
    if len(hosts) > 1024:
        return []

    def _probe(address: str) -> Optional[str]:
        try:
            completed = subprocess.run(
                _ping_command(address),
                capture_output=True,
                text=True,
                shell=False,
                timeout=5,
            )
        except Exception:
            return None
        return address if _ping_replies(completed) else None

    alive: List[str] = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        for result in pool.map(_probe, hosts):
            if result:
                alive.append(result)
    return alive


def arp_table_pairs(within: Optional[str] = None) -> List[Tuple[str, str]]:
    """``(ip, mac)`` pairs from the operating system's neighbour table.

    Reading the table needs no privileges and no packet-capture driver — the
    kernel already did the ARP exchange. That makes it the only way to recover
    MAC addresses when a raw sweep is unavailable, and it is why a machine
    whose Npcap driver is stopped can still list real devices rather than an
    empty inventory.
    """
    import ipaddress
    import re
    import sys

    mac_re = re.compile(r"^([0-9a-f]{2}[:-]){5}[0-9a-f]{2}$", re.IGNORECASE)
    # normalize_mac strips separators, so compare in that form.
    useless_macs = {"000000000000", "FFFFFFFFFFFF"}

    _run = _os_output

    pairs: List[Tuple[str, str]] = []

    if sys.platform.startswith("win"):
        for line in _run(["arp", "-a"]).splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            ip_candidate, mac_candidate = parts[0], parts[1]
            if mac_re.match(mac_candidate):
                pairs.append((ip_candidate, mac_candidate))
    elif sys.platform.startswith("linux"):
        for line in _run(["ip", "neigh", "show"]).splitlines():
            parts = line.split()
            if "lladdr" not in parts or not parts:
                continue
            if "FAILED" in parts or "INCOMPLETE" in parts:
                continue
            index = parts.index("lladdr")
            if index + 1 >= len(parts):
                continue
            mac_candidate = parts[index + 1]
            if mac_re.match(mac_candidate):
                pairs.append((parts[0], mac_candidate))
    else:
        # macOS / BSD: "? (192.168.1.1) at 8c:44:bb:7:6c:10 on en0 [ethernet]"
        for line in _run(["arp", "-an"]).splitlines():
            fields = line.replace("(", " ").replace(")", " ").split()
            if "at" not in fields:
                continue
            index = fields.index("at")
            if index + 1 >= len(fields) or len(fields) < 2:
                continue
            mac_candidate = fields[index + 1]
            if mac_re.match(mac_candidate):
                pairs.append((fields[1], mac_candidate))

    network = None
    if within:
        try:
            network = ipaddress.ip_network(within, strict=False)
        except ValueError:
            network = None

    cleaned: List[Tuple[str, str]] = []
    seen: set[str] = set()
    for ip_candidate, mac_candidate in pairs:
        try:
            parsed = ipaddress.ip_address(ip_candidate)
        except ValueError:
            continue
        if parsed.is_multicast or parsed.is_unspecified or parsed.is_loopback:
            continue
        if network is not None and parsed not in network:
            continue
        normalized = normalize_mac(mac_candidate)
        if not normalized or normalized in useless_macs:
            continue
        if ip_candidate in seen:
            continue
        seen.add(ip_candidate)
        cleaned.append((ip_candidate, normalized))

    return cleaned


def _nmap_sweep_sync(target: str, host_timeout: int) -> Dict[str, Any]:
    """Blocking ``nmap -sn`` sweep, returned in python-nmap's scan shape."""
    import nmap  # python-nmap

    from app.services.nmap_capabilities import detect_capabilities

    # Without raw sockets plain `-sn` dies on "Failed to open device"; the
    # unprivileged mode discovers hosts with connect() instead.
    unprivileged = "" if detect_capabilities().privileged else " --unprivileged"
    scanner = nmap.PortScanner()
    scanner.scan(
        hosts=target,
        arguments=f"-sn -T4 --host-timeout {int(host_timeout)}s{unprivileged}",
    )

    scan_data: Dict[str, Any] = {}
    for host in scanner.all_hosts():
        entry = scanner[host]
        scan_data[host] = {
            "status": entry.get("status", {}),
            "addresses": entry.get("addresses", {}),
            "hostnames": entry.get("hostnames", []),
            "vendor": entry.get("vendor", {}),
        }
    return scan_data


def nmap_available() -> bool:
    """True when the nmap binary is on PATH (python-nmap shells out to it)."""
    import shutil

    return shutil.which("nmap") is not None


async def sweep_target(
    target: str,
    *,
    iface: Optional[str] = None,
    arp_timeout: float = DEFAULT_ARP_TIMEOUT,
    host_timeout: int = DEFAULT_HOST_TIMEOUT,
    outcome: DiscoveryOutcome,
) -> List[DiscoveredHost]:
    """Discover hosts within *target*, preferring ARP and falling back to nmap.

    Warnings are recorded on *outcome* rather than raised, because a sweep that
    half-worked should still report the hosts it did find.
    """
    discovered: List[DiscoveredHost] = []

    try:
        pairs = await asyncio.to_thread(arp_sweep, target, iface, arp_timeout)
        if pairs:
            discovered.extend(hosts_from_arp_pairs(pairs))
            outcome.methods.append("arp")
    except Exception as exc:
        logger.debug("ARP sweep of %s unavailable: %s", target, exc)

    if not discovered:
        if not nmap_available():
            outcome.warnings.append(
                "nmap is not installed and the ARP sweep was unavailable; "
                "install nmap (or grant raw-socket privileges) for discovery to run."
            )
        else:
            try:
                scan_data = await asyncio.to_thread(_nmap_sweep_sync, target, host_timeout)
                hosts = hosts_from_scan_data(scan_data)
                if hosts:
                    discovered.extend(hosts)
                    outcome.methods.append("nmap")
            except Exception as exc:
                outcome.warnings.append(f"nmap sweep failed: {exc}")

        # nmap's unprivileged mode can only connect() to ports, so a phone that
        # closes 80/443 looks dead. OS ping sends real ICMP without privileges
        # and catches exactly those hosts.
        try:
            alive = await asyncio.to_thread(_icmp_sweep_sync, target)
        except Exception as exc:  # pragma: no cover - defensive
            logger.debug("ICMP sweep of %s failed: %s", target, exc)
            alive = []
        if alive:
            outcome.methods.append("icmp")
            known = {host.ip_address for host in discovered}
            for ip_address in alive:
                if ip_address not in known:
                    discovered.append(
                        DiscoveredHost(ip_address=ip_address, source="icmp")
                    )
                    known.add(ip_address)

    # The kernel's neighbour table is free and privilege-free: use it to attach
    # MACs the connect sweep cannot see, and to surface hosts that answered
    # ARP recently but not ICMP (phones frequently block the latter).
    try:
        table_pairs = await asyncio.to_thread(arp_table_pairs, target)
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("Neighbour table read failed for %s: %s", target, exc)
        table_pairs = []

    if table_pairs:
        by_ip = {host.ip_address: host for host in discovered}
        added = 0
        for ip_address, mac in table_pairs:
            existing = by_ip.get(ip_address)
            if existing is not None:
                if not existing.mac_address:
                    existing.mac_address = mac
                    existing.vendor = existing.vendor or lookup_vendor(mac)
                continue
            fresh = hosts_from_arp_pairs([(ip_address, mac)])[0]
            fresh.source = "arp-table"
            discovered.append(fresh)
            by_ip[ip_address] = fresh
            added += 1
        if added or outcome.methods:
            outcome.methods.append("arp-table")

    return discovered


async def _classify_by_ttl(host: DiscoveredHost) -> Tuple[Optional[str], Optional[str]]:
    """Ping the host once and classify it from the reply's TTL.

    Failures are silent by design: a host that cannot be pinged simply keeps
    whatever the hostname/OUI rules already decided.
    """
    from app.services.icmp import ping

    outcome = await ping(host.ip_address, count=1, timeout_s=1.0)
    if not outcome.reachable or outcome.ttl is None:
        return None, None
    return os_from_ttl(outcome.ttl, mac_address=host.mac_address)


async def upsert_discovered_hosts(
    db: Any,
    hosts: Sequence[DiscoveredHost],
    *,
    now: Optional[datetime] = None,
    network_id: Optional[int] = None,
) -> Tuple[int, int]:
    """Insert new devices and refresh known ones. Returns ``(created, updated)``.

    ``network_id`` scopes the whole merge to one network. Home networks reuse
    the same addresses, so without it the ``192.168.1.10`` of one house would
    overwrite the other house's row. Rows that predate networks (NULL) are
    adopted by the first sweep that matches them.

    Merge policy:
      * ``last_seen`` is always refreshed.
      * Identity follows the *device*, not the address it had last week.
        A row is matched by IP first; failing that, by the MAC observed at a
        different address (DHCP move); failing that — when both MACs are
        randomised — by an unambiguous hostname (Android/iOS/Windows rotate
        their private address *and* their MAC between reboots). The matched
        row migrates to the new address so its ports, vulnerabilities and
        history stay attached to the machine that produced them.
      * Rows whose identity demonstrably moved elsewhere in the same sweep
        are retired (deleted). That is what used to leave an "offline
        Immortan" ghost next to the live one: address-keyed upserts inserted
        a second row on every IP change and never cleaned the old one up.
        A stale row with no observed successor just ages out via
        ``last_seen`` — only provable duplicates are deleted.
      * Descriptive fields (hostname/vendor/type/OS) fill blanks but never
        overwrite a value we already hold, so enrichment from a richer scan is
        not clobbered by the next shallow sweep.
      * ``is_gateway`` latches true.
    """
    # Imported here so the module stays importable without SQLAlchemy.
    from sqlalchemy import or_, select, update as sa_update

    from app.models.device import Device
    from app.models.script_job import ScriptJob

    observed_at = now or datetime.now(timezone.utc)
    created = 0
    updated = 0

    stmt = select(Device)
    if network_id is not None:
        stmt = stmt.where(
            or_(Device.network_id == network_id, Device.network_id.is_(None))
        )
    result = await db.execute(stmt)
    rows: List[Device] = list(result.scalars().all())
    by_ip = {row.ip_address: row for row in rows}
    observed_ips = {host.ip_address for host in hosts}
    # Rows already claimed this sweep — one physical row cannot absorb two
    # observed hosts, however odd the network looks.
    claimed: set[int] = set()

    def _find_identity(host: DiscoveredHost) -> Optional[Device]:
        # 1. Exact address match (the common case).
        row = by_ip.get(host.ip_address)
        if row is not None:
            return row

        # 2. Same MAC seen at an address that was *not* observed in this
        #    sweep: the device got a new DHCP lease. Old address is empty,
        #    so this is a move, not two machines.
        mac = (host.mac_address or "").upper()
        if mac:
            for row in rows:
                if row.id in claimed:
                    continue
                if (row.mac_address or "").upper() == mac and row.ip_address not in observed_ips:
                    return row

        # 3. Randomised MAC behind a known hostname: phones/laptops rotate
        #    both. A host that answered ICMP but left no ARP entry arrives
        #    with no MAC at all, which is the same situation from the row's
        #    point of view. Only an *unambiguous* match counts — two devices
        #    sharing a generic name must never be fused.
        name = (host.hostname or "").strip().lower()
        if name and (not host.mac_address or is_locally_administered(host.mac_address)):
            candidates = [
                row
                for row in rows
                if row.id not in claimed
                and row.ip_address not in observed_ips
                and (row.hostname or "").strip().lower() == name
                and (
                    not row.mac_address
                    or is_locally_administered(row.mac_address)
                )
            ]
            if len(candidates) == 1:
                return candidates[0]

        return None

    # The same machine often answers twice in one sweep: once at the address
    # its ARP entry still names, and once at the address it really holds. A
    # host that replied to ICMP but has no ARP entry carries no MAC, so it
    # cannot be told apart from a new device by address alone. If a single
    # host in this sweep already reports the same hostname *with* a MAC, the
    # MAC-less answer is the same machine and is dropped rather than turned
    # into a twin row.
    named_with_mac: Dict[str, int] = {}
    for candidate in hosts:
        if candidate.mac_address and (candidate.hostname or "").strip():
            key = candidate.hostname.strip().lower()
            named_with_mac[key] = named_with_mac.get(key, 0) + 1

    pending: List[Device] = []
    for host in hosts:
        device = _find_identity(host)

        if device is None and not host.mac_address and host.hostname:
            name = host.hostname.strip().lower()
            if named_with_mac.get(name) == 1:
                logger.info(
                    "Skipping MAC-less duplicate at %s (hostname=%r)",
                    host.ip_address,
                    host.hostname,
                )
                continue

        if device is None:
            device = Device(
                ip_address=host.ip_address,
                network_id=network_id,
                mac_address=host.mac_address,
                hostname=host.hostname,
                vendor=host.vendor,
                device_type=host.device_type,
                os=host.os,
                last_seen=observed_at,
                is_gateway=host.is_gateway,
            )
            db.add(device)
            by_ip[host.ip_address] = device
            pending.append(device)
            created += 1
            continue

        claimed.add(device.id)
        if network_id is not None and device.network_id is None:
            # Pre-network row: the sweep that sees it claims it.
            device.network_id = network_id
        if device.ip_address != host.ip_address:
            # The device moved (or rotated). Carry the row to its current
            # address instead of duplicating it. Drop the by_ip entry that
            # pointed at the old address so later lookups stay honest.
            logger.info(
                "Device identity moved: %s -> %s (mac=%s, hostname=%s)",
                device.ip_address,
                host.ip_address,
                host.mac_address,
                host.hostname,
            )
            by_ip.pop(device.ip_address, None)
            device.ip_address = host.ip_address
            by_ip[host.ip_address] = device

        if host.mac_address and device.mac_address != host.mac_address:
            device.mac_address = host.mac_address
        device.hostname = device.hostname or host.hostname
        device.vendor = device.vendor or host.vendor
        device.device_type = device.device_type or host.device_type
        device.os = device.os or host.os
        device.last_seen = observed_at
        if host.is_gateway:
            device.is_gateway = True
        updated += 1
        pending.append(device)

    # --- retire provable duplicates -------------------------------------
    # A row that was not observed this sweep while a surviving row now holds
    # its MAC (or its unique randomised hostname) is a stale twin of the same
    # machine — the phantom "offline" entry. Anything else just goes quiet.
    survivors = pending + [device for device in rows if device.id in claimed]
    survivor_macs = {
        (device.mac_address or "").upper()
        for device in survivors
        if device.mac_address
    }
    survivor_names = {
        (device.hostname or "").strip().lower()
        for device in survivors
        if device.hostname
    }
    # Hostname-based retirement needs the *same uniqueness rule adoption has*:
    # if several unseen rows share one name ("Android"), none of them can be
    # proven to be the machine that just reappeared, so none are retired.
    stale_name_counts: Dict[str, int] = {}
    for row in rows:
        if row.id in claimed or row.ip_address in observed_ips:
            continue
        name = (row.hostname or "").strip().lower()
        if name:
            stale_name_counts[name] = stale_name_counts.get(name, 0) + 1

    for row in rows:
        if row.id in claimed or row.ip_address in observed_ips:
            continue
        row_mac = (row.mac_address or "").upper()
        row_name = (row.hostname or "").strip().lower()
        mac_moved = bool(row_mac) and row_mac in survivor_macs
        # A twin with no MAC is the common case when a host answered the sweep
        # but had no ARP entry: nothing proves it is a different machine, and
        # its unique hostname already points at the survivor.
        name_moved = (
            bool(row_name)
            and row_name in survivor_names
            and stale_name_counts.get(row_name) == 1
            and (not row_mac or is_locally_administered(row_mac))
        )
        if not (mac_moved or name_moved):
            continue

        # The ghost may hold the only copy of descriptive fields (a hostname
        # that reverse DNS no longer answers for). Carry blanks over to the
        # surviving row with the same MAC before the row goes away.
        twin = next(
            (
                device
                for device in survivors
                if device.ip_address != row.ip_address
                and device.mac_address
                and (device.mac_address or "").upper() == row_mac
            ),
            None,
        )
        if twin is not None:
            twin.hostname = twin.hostname or row.hostname
            twin.vendor = twin.vendor or row.vendor
            twin.device_type = twin.device_type or row.device_type
            twin.os = twin.os or row.os

        # script_jobs holds an FK without ON DELETE CASCADE; detach its
        # history rows first so the delete cannot violate the constraint.
        await db.execute(
            sa_update(ScriptJob)
            .where(ScriptJob.device_id == row.id)
            .values(device_id=None)
        )
        logger.info(
            "Retiring stale duplicate device row #%s %s (mac=%s, hostname=%r) — "
            "its identity now lives on a row observed at %s.",
            row.id,
            row.ip_address,
            row_mac,
            row_name,
            ", ".join(sorted(observed_ips)),
        )
        await db.delete(row)

    await db.commit()
    return created, updated


def _local_hosts_for_subnets(subnets: Sequence[str]) -> List[DiscoveredHost]:
    """Self-observation: this machine's own interface on each swept subnet.

    A host cannot ARP itself, so without this the running machine never
    appears in its own sweep — its row goes stale and every DHCP move leaves
    an "offline ghost" twin behind. The outbound interface for a probe
    address inside the subnet identifies which local address belongs there.
    """
    import ipaddress
    import uuid

    hosts: List[DiscoveredHost] = []
    try:
        mac = "%012X" % uuid.getnode()
    except Exception:  # pragma: no cover - defensive; UUID backend missing
        return hosts
    hostname = socket.gethostname()

    for subnet in subnets:
        try:
            network = ipaddress.ip_network(subnet, strict=False)
            probe_ip = str(network.network_address + 1)
        except ValueError:
            continue
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.connect((probe_ip, 53))  # no packet sent — route lookup only
            local_ip = sock.getsockname()[0]
        except OSError:
            continue
        finally:
            sock.close()
        # Only claim membership on subnets this machine is actually part of:
        # a sweep aimed elsewhere must not drag our own row into its results.
        try:
            if ipaddress.ip_address(local_ip) not in network:
                continue
        except ValueError:
            continue
        if local_ip.startswith("127.") or local_ip in {h.ip_address for h in hosts}:
            continue
        hosts.append(
            DiscoveredHost(
                ip_address=local_ip,
                mac_address=mac,
                hostname=hostname,
                device_type="",
                os="",
                vendor=lookup_vendor(mac),
                source="local",
            )
        )
    return hosts


async def run_device_discovery(
    db: Any,
    *,
    target: Optional[str] = None,
    iface: Optional[str] = None,
    arp_timeout: float = DEFAULT_ARP_TIMEOUT,
    host_timeout: int = DEFAULT_HOST_TIMEOUT,
    persist: bool = True,
) -> DiscoveryOutcome:
    """Discover devices on *target* (or the local subnets) and record them.

    Discovery only. Restricted/fragile VLANs are refused outright rather than
    probed, and an explicit target is validated before it reaches a subprocess.
    """
    outcome = DiscoveryOutcome()

    if _discovery_lock.locked():
        outcome.warnings.append("A discovery run is already in progress.")
        return outcome

    async with _discovery_lock:
        targets: List[str]
        if target:
            if not validate_target(target):
                raise ValueError("Invalid target format")
            if is_restricted_target(target):
                # Passive monitoring only — never actively probe these ranges.
                outcome.skipped_restricted.append(target)
                return outcome
            targets = [target]
        else:
            targets, resolved_iface = local_subnets(iface)
            iface = resolved_iface
            if not targets:
                outcome.warnings.append(
                    "Could not determine local subnets (scapy unavailable or no "
                    "attached route); supply an explicit target instead."
                )
                return outcome

        outcome.subnets = list(targets)

        collected: Dict[str, DiscoveredHost] = {}
        for candidate in targets:
            for host in await sweep_target(
                candidate,
                iface=iface,
                arp_timeout=arp_timeout,
                host_timeout=host_timeout,
                outcome=outcome,
            ):
                # First observation wins; a later sweep is not more truthful.
                collected.setdefault(host.ip_address, host)

        # Include this machine itself so its row stays live and DHCP-move
        # merges (ghost retirement) have a survivor to attach to.
        for local_host in _local_hosts_for_subnets(targets):
            collected.setdefault(local_host.ip_address, local_host)

        enriched = await enrich_hosts(list(collected.values()))
        outcome.hosts = enriched
        # de-duplicate methods while keeping order
        outcome.methods = list(dict.fromkeys(outcome.methods))

        if persist and enriched:
            from app.services.network_identity import current_network_id

            outcome.created, outcome.updated = await upsert_discovered_hosts(
                db,
                enriched,
                network_id=await current_network_id(db),
            )

    return outcome
