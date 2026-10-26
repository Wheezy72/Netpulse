"""Operating-system identification for a discovered host.

There is no single foolproof passive signal for "this phone runs Android".
Everything available to a LAN observer is evidence rather than proof:

* **nmap OS detection** compares TCP/IP stack fingerprints (SYN window sizes,
  options, TTL, ICMP replies) against a shipped database. It is the strongest
  signal available on a LAN and reports an accuracy percentage per match.
  It needs raw sockets, so it needs admin/root (or Npcap on Windows).
* **Hostnames** are self-reported. `DESKTOP-8FJ2` is Windows, `android-abc123`
  is Android, `Bobss-MacBook-Pro` is macOS. Reliable when present.
* **Open ports**. 139/445 only ever come from Windows; 62078 (lockdownd) and
  5555 (adb) are Apple and Android respectively; a host with 22 open and no
  445 is very likely Unix-like.
* **MAC vendor** is a weak hint on its own — and useless when the device
  randomises its MAC, which phones do by default — but it is decisive for
  Apple and Microsoft hardware.

Every answer carries a confidence so callers can show "Android (likely)" as
distinctly from a fingerprint nmap actually matched.
"""
from __future__ import annotations

import logging
import shutil
from typing import Any, Iterable, Optional, Tuple

logger = logging.getLogger("netpulse.os_fingerprint")

# (operating system, confidence) — confidence is "high" | "medium" | "low".
OSGuess = Tuple[Optional[str], Optional[str]]

# Ports that are effectively signatures of one platform.
PORT_WINDOWS = {139, 445}
PORT_APPLE_LOCKDOWN = {62078}
PORT_MDNS = {5353, 5350}
PORT_ADB = {5555}

# Vendor families. Only used when the MAC is not randomly generated.
ANDROID_VENDORS = {
    "samsung",
    "lg electronics",
    "xiaomi",
    "huawei",
    "google",
    "oneplus",
    "oppo",
    "vivo",
    "realme",
    "motorola",
    "honor",
    "tecno",
    "infinix",
}
APPLE_VENDORS = {"apple"}
MICROSOFT_VENDORS = {"microsoft"}
LINUX_VENDORS = {"raspberry pi foundation", "raspberry pi"}

# Hypervisor OUIs. A virtual machine answers exactly like the OS it runs, so
# these do not change the family; they explain why a Kali box is a Kali box and
# let the label say so ("Linux (virtual machine)") instead of pretending the
# stack fingerprint identified the distro.
HYPERVISOR_VENDORS = {
    "vmware",
    "virtualbox",
    "qemu",
    "xensource",
    "microsoft corporation",
    "parallels",
    "innotek gmbh",
}

# Distribution signatures. These are self-reported strings -- a service banner,
# an mDNS record, a DHCP hostname -- and self-reported beats inferred, because
# nothing else on a LAN can tell Kali from Debian: they run the same kernel, so
# their TCP/IP stacks are byte-for-byte identical. nmap can say "Linux 5.x";
# only a banner or a hostname can say "Kali".
DISTRO_SIGNATURES: tuple[tuple[tuple[str, ...], str], ...] = (
    (("kali",), "Kali Linux"),
    (("raspbian", "raspberry pi os", "raspberrypi"), "Raspberry Pi OS"),
    (("ubuntu", "canonical"), "Ubuntu"),
    (("debian", "deb12", "deb11", "deb10"), "Debian"),
    (("almalinux",), "AlmaLinux"),
    (("rocky linux", "rockylinux"), "Rocky Linux"),
    (("centos",), "CentOS"),
    (("red hat", "rhel", "redhat"), "Red Hat"),
    (("fedora",), "Fedora"),
    (("alpine",), "Alpine Linux"),
    (("arch linux", "manjaro"), "Arch Linux"),
    (("opensuse", "suse"), "openSUSE"),
)

# A virtual-machine vendor plus a Unix banner is still Linux; the hint is only
# used to annotate the label, never to replace it.
VM_SUFFIX = " (virtual machine)"


def _clean(value: Optional[str]) -> str:
    return (value or "").strip().lower()


def os_label_from_banner(banner: str) -> Optional[str]:
    """A distribution name when *banner* names one, else ``None``.

    Banners are the one signal that separates distributions: OpenSSH built by
    Debian says ``OpenSSH_9.2p1 Debian-2``, an Ubuntu package says ``Ubuntu``,
    and a Kali host usually says either, so Kali wins only when it is spelled
    out. That is deliberate -- guessing "Kali" from Debian would mislabel every
    Debian server on the LAN.
    """
    text = _clean(banner)
    if not text:
        return None
    for needles, label in DISTRO_SIGNATURES:
        if any(needle in text for needle in needles):
            return label
    return None


def os_family_from_ttl(ttl: Optional[int]) -> OSGuess:
    """Coarse family from the reply's TTL.

    TTL is decremented per hop, so the initial value is rounded up to the
    nearest conventional maximum. 64 = Unix-like, 128 = Windows, 255 = network
    equipment. This is a hint, never proof: it cannot name a distribution and a
    middlebox can rewrite it.
    """
    if not ttl or ttl <= 0 or ttl > 255:
        return None, None
    if ttl <= 32:
        # Rare initial values; most likely a heavily routed 64.
        return None, None
    if ttl <= 64:
        return "Linux/Unix", "low"
    if ttl <= 128:
        return "Windows", "low"
    return "Network device", "low"


def infer_os_from_host(
    *,
    hostname: Optional[str] = None,
    vendor: Optional[str] = None,
    open_ports: Iterable[int] = (),
    mac_randomised: bool = False,
    service_banners: Iterable[str] = (),
    ttl: Optional[int] = None,
) -> OSGuess:
    """Infer ``(os, confidence)`` from signals other than nmap's fingerprint.

    Pure and synchronous so it can be unit tested and reused by the discovery
    path, the deep-scan path and any future passive collector.
    """
    host = _clean(hostname)
    vend = _clean(vendor)
    ports = {int(p) for p in open_ports if p}
    is_vm = any(marker in vend for marker in HYPERVISOR_VENDORS)

    # 1. Service banners: the only signal that names a distribution.
    for banner in service_banners:
        label = os_label_from_banner(str(banner))
        if label:
            return label + (VM_SUFFIX if is_vm else ""), "high"

    # 2. Hostname: self-reported and specific.
    if host:
        if "android" in host or host.startswith(("sm-", "pixel-")):
            return "Android", "high"
        if any(token in host for token in ("iphone", "ipad", "ipod")):
            return "iOS", "high"
        if any(token in host for token in ("macbook", "imac", "mac mini", "macmini", "mac-")):
            return "macOS", "high"
        if host.startswith(("desktop-", "laptop-", "win-", "ms surface")) or "-pc" in host:
            return "Windows", "high"
        if "kali" in host:
            return "Kali Linux" + (VM_SUFFIX if is_vm else ""), "high"
        if any(token in host for token in ("ubuntu", "debian", "fedora", "arch", "raspberrypi")):
            return "Linux", "high"

    # 3. Ports: a platform's own services.
    if PORT_WINDOWS & ports:
        return "Windows", "high"
    if PORT_ADB & ports:
        return "Android", "high"
    if PORT_APPLE_LOCKDOWN & ports:
        return "iOS", "high"
    if ports and 22 in ports and not (PORT_WINDOWS & ports):
        # SSH with no Windows file sharing: a Unix-like host. Distinguishing
        # Linux from macOS needs nmap's fingerprint.
        return "Linux", "medium"

    # 4. TTL, when nothing more specific answered. A Unix-like TTL is exactly
    # what a Kali VM answers with, so it supports "Linux" without inventing a
    # distribution the network cannot see.
    ttl_family, ttl_confidence = os_family_from_ttl(ttl)
    if ttl_family:
        if ttl_family == "Linux/Unix" and is_vm:
            return "Linux" + VM_SUFFIX, "medium"
        return ttl_family, ttl_confidence

    # 5. Vendor — only trustworthy on a real (non-randomised) MAC.
    if mac_randomised:
        return None, None
    if vend in MICROSOFT_VENDORS:
        return "Windows", "medium"
    if vend in APPLE_VENDORS:
        # An Apple OUI covers both desktop and mobile; mDNS tips it either way.
        return ("macOS", "medium") if PORT_MDNS & ports else ("macOS/iOS", "low")
    if vend in ANDROID_VENDORS:
        return "Android", "medium"
    if vend in LINUX_VENDORS:
        return "Linux", "high"

    return None, None


def nmap_os_detect(ip_address: str, *, timeout_seconds: int = 60) -> OSGuess:
    """Ask nmap to fingerprint the host's IP stack.

    Runs blocking nmap (`-O --osscan-guess`); call it from a worker thread.
    Returns ``(None, None)`` when nmap is missing, unprivileged, or unmatched.
    """
    if shutil.which("nmap") is None:
        return None, None

    # -O needs raw sockets. Without Npcap/root nmap fails the whole scan with
    # "Failed to open device", which used to cost the caller a dozen seconds
    # before falling back anyway. Ask the capability probe first.
    try:
        from app.services.nmap_capabilities import detect_capabilities

        if not detect_capabilities().privileged:
            return None, None
    except Exception:  # noqa: BLE001 - capability probe is advisory
        pass

    try:
        import nmap  # python-nmap
    except Exception:  # noqa: BLE001 - optional dependency
        return None, None

    try:
        scanner = nmap.PortScanner()
        # -Pn: assume the host is up, since many firewalls drop ICMP echo.
        scanner.scan(
            hosts=ip_address,
            arguments=f"-O --osscan-guess -Pn --host-timeout {int(timeout_seconds)}s",
        )
    except Exception as exc:  # noqa: BLE001 - fingerprinting is best-effort
        logger.info("nmap OS detection failed for %s: %s", ip_address, exc)
        return None, None

    try:
        entry: Any = scanner[ip_address]
        matches = list(entry.get("osmatch") or [])
    except Exception:  # noqa: BLE001 - host absent from the scan result
        return None, None

    if not matches:
        return None, None

    # nmap sorts by accuracy; take the best and carry its accuracy through as
    # confidence so an 89% match is not shown like a certainty.
    best = max(matches, key=lambda m: int(m.get("accuracy") or 0))
    label = (best.get("name") or "").strip()
    if not label:
        return None, None

    accuracy = int(best.get("accuracy") or 0)
    confidence = "high" if accuracy >= 95 else "medium" if accuracy >= 80 else "low"
    return label, confidence


def resolve_device_os(
    *,
    ip_address: str,
    hostname: Optional[str] = None,
    vendor: Optional[str] = None,
    open_ports: Iterable[int] = (),
    mac_randomised: bool = False,
    prefer_nmap: bool = True,
    service_banners: Iterable[str] = (),
    ttl: Optional[int] = None,
) -> OSGuess:
    """Best available OS label for one host.

    Order is deliberate. A banner or hostname that names a distribution wins,
    because that is the only evidence that can distinguish Kali from Debian.
    nmap's stack fingerprint answers next -- it is the strongest generic answer
    and the only one that can say "Windows 10" without ports. TTL and vendor
    fill in the rest.
    """
    banners = [str(banner) for banner in service_banners if banner]
    label, confidence = infer_os_from_host(
        hostname=hostname,
        open_ports=open_ports,
        mac_randomised=mac_randomised,
        service_banners=banners,
    )
    if label and confidence == "high":
        return label, confidence

    if prefer_nmap:
        nmap_label, nmap_confidence = nmap_os_detect(ip_address)
        if nmap_label:
            return nmap_label, nmap_confidence

    if label:
        return label, confidence

    return infer_os_from_host(
        vendor=vendor,
        open_ports=open_ports,
        mac_randomised=mac_randomised,
        ttl=ttl,
    )
