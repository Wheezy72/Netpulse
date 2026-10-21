"""Device-class fingerprints: DHCP options plus SSDP/NBNS/LLMNR/mDNS probes.

Hostname + OUI heuristics cannot tell an Android phone from a Linux box when
the phone randomises its MAC and its owner named it "Bob". This module asks
the device itself, using protocols most stacks answer by default:

* **NBNS node status** (UDP/137) — Windows and Samba reply with their NetBIOS
  names and adapter MAC. A reply with a workstation (0x00) or file-server
  (0x20) name is a strong Windows signal, and it also yields the machine's
  self-published name when reverse DNS is silent.
* **LLMNR** (UDP/5355) — Windows (Vista+) and systemd-resolved Linux answer
  an A query for the name the host already carries; Apple and Android do not.
  Presence narrows the field away from Apple/Android rather than pinning it.
* **mDNS** (UDP/5353) — Apple/Android/Linux answer ``<name>.local`` queries;
  the TXT record's ``model=`` (Apple gear) separates iPhone/iPad from Mac.
* **SSDP/UPnP** (multicast 1900) — the ``Server:`` header names the OS
  outright: ``Windows/10.0 …``, ``Android/14 …``, ``Linux/…``.

DHCP fingerprints (option 55 parameter-request-list + option 60 vendor class)
are recorded passively by the monitor that already sniffs ports 67/68; the
cache here is consulted for free during enrichment. Option-55 sets are
matched *exactly* against commonly observed signatures — fuzzy matching would
manufacture confidence that is not there.

Evidence is weighted: probes return :class:`FingerprintHints` with a
confidence and human-readable evidence strings, and only hints at or above
``MIN_CONFIDENCE`` ever reach classification, only as *fill-in for blanks*
(hostname evidence keeps priority, exactly like the upsert merge policy).

Import discipline matches device_discovery: stdlib (plus the oui helpers)
at module level, nothing else, so the parsers stay unit-testable in the
minimal CI environment.
"""
from __future__ import annotations

import asyncio
import logging
import re
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from app.services.oui import normalize_mac

logger = logging.getLogger("netpulse.fingerprint")

# Hints below this confidence never influence classification.
MIN_CONFIDENCE = 0.55

# Per-probe deadline. Probes run concurrently, so a full host probe costs
# about one PROBE_TIMEOUT, not three.
PROBE_TIMEOUT = 0.7
# One multicast M-SEARCH collects every SSDP responder on the segment.
SSDP_TIMEOUT = 1.0
SSDP_ADDR = ("239.255.255.250", 1900)

# DHCP hint cache lifetime: a lease cycle is the evidence's shelf life.
DHCP_HINT_TTL_S = 24 * 3600.0


@dataclass(slots=True)
class FingerprintHints:
    """What the probes believe, with the receipts."""

    os_family: Optional[str] = None  # windows | apple | android | linux
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    hostname: Optional[str] = None  # self-published name (NBNS/DHCP)

    def merge(self, other: "FingerprintHints") -> "FingerprintHints":
        """Keep the stronger hint; accumulate evidence from both."""
        if other is None:
            return self
        for item in other.evidence:
            if item not in self.evidence:
                self.evidence.append(item)
        if other.hostname and not self.hostname:
            self.hostname = other.hostname
        if other.confidence > self.confidence:
            self.os_family = other.os_family
            self.confidence = other.confidence
        return self


def _clamp(value: float) -> float:
    return max(0.0, min(1.0, value))


# ---------------------------------------------------------------------------
# NBNS (NetBIOS name service) node status — RFC 1002
# ---------------------------------------------------------------------------


def encode_netbios_name(raw: bytes) -> str:
    """Encode a 16-byte NetBIOS name into the 32-character DNS label."""
    if len(raw) != 16:
        raise ValueError("NetBIOS name must be exactly 16 bytes")
    out = []
    for b in raw:
        out.append(chr(ord("A") + ((b >> 4) & 0x0F)))
        out.append(chr(ord("A") + (b & 0x0F)))
    return "".join(out)


def build_nbstat_query() -> bytes:
    """Wildcard node-status query (``*`` + suffix 0x00), as ``nbtstat -A`` sends."""
    name = b"*" + b"\x00" * 15
    header = struct.pack(">HHHHHH", 0x0000, 0x0000, 1, 0, 0, 0)
    question = bytes([len(label := encode_netbios_name(name))]) + label.encode("ascii")
    question += struct.pack(">HH", 0x0021, 0x0001)  # TYPE NBSTAT, CLASS IN
    return header + question


@dataclass(slots=True)
class NbstatResult:
    names: List[str] = field(default_factory=list)
    mac: Optional[str] = None


def parse_nbstat_response(data: bytes) -> Optional[NbstatResult]:
    """Parse a node-status reply into names + MAC. None when malformed."""
    try:
        if len(data) < 12:
            return None
        _txid, _flags, qd, an, _ns, _ar = struct.unpack_from(">HHHHHH", data, 0)
        pos = 12

        def skip_name(offset: int) -> int:
            while offset < len(data):
                length = data[offset]
                if length == 0:
                    return offset + 1
                if length & 0xC0 == 0xC0:  # compression pointer
                    return offset + 2
                offset += 1 + length
            raise ValueError("truncated name")

        for _ in range(qd):
            pos = skip_name(pos)
            pos += 4  # type + class
        if an < 1:
            return None

        pos = skip_name(pos)
        rtype, _rclass, _ttl, rdlen = struct.unpack_from(">HHIH", data, pos)
        pos += 8
        if rtype != 0x0021 or pos + rdlen > len(data):
            return None
        rdata = data[pos : pos + rdlen]
        if not rdata:
            return None

        count = rdata[0]
        names: List[str] = []
        offset = 1
        for _ in range(count):
            if offset + 18 > len(rdata):
                break
            raw = rdata[offset : offset + 15].decode("ascii", errors="replace").rstrip(" \x00")
            suffix = rdata[offset + 15]
            flags = rdata[offset + 16] << 8 | rdata[offset + 17]
            group = bool(flags & 0x8000)
            if raw and (not group) and suffix in (0x00, 0x03, 0x20):
                names.append(raw)
            offset += 18
        mac = None
        stats = rdata[offset:]
        if len(stats) >= 6:
            mac = normalize_mac(":".join(f"{b:02x}" for b in stats[:6]))
        return NbstatResult(names=names, mac=mac)
    except (struct.error, ValueError, IndexError):
        return None


def hints_from_nbstat(result: NbstatResult) -> FingerprintHints:
    """NBSTAT evidence: workstation/file-server names ⇒ Windows/Samba host."""
    hints = FingerprintHints()
    if not result.names:
        return hints
    hints.hostname = result.names[0]
    hints.os_family = "windows"
    hints.confidence = 0.7  # Samba answers too — strong, not certain
    hints.evidence.append(
        f"NetBIOS node status answered with {', '.join(result.names[:3])} "
        "(Windows or Samba)"
    )
    return hints


# ---------------------------------------------------------------------------
# LLMNR / mDNS — DNS wire format over UDP (RFC 4795 / RFC 6762)
# ---------------------------------------------------------------------------


def build_dns_query(name: str, qtype: int) -> bytes:
    """A one-question DNS message suitable for LLMNR or mDNS."""
    labels = [part for part in name.strip(".").split(".") if part]
    qname = b"".join(bytes([len(p)]) + p.encode("idna") for p in labels) + b"\x00"
    header = struct.pack(">HHHHHH", 0x0000, 0x0000, 1, 0, 0, 0)
    return header + qname + struct.pack(">HH", qtype, 0x0001)


def parse_dns_response(data: bytes) -> Optional[Dict[str, object]]:
    """Minimal DNS response parser: answers as {type, name, a, txt} entries."""
    try:
        if len(data) < 12:
            return None
        _id, flags, qd, an, _ns, _ar = struct.unpack_from(">HHHHHH", data, 0)
        if (flags & 0x8000) == 0 or an < 1:  # not a response / no answers
            return None
        pos = 12

        def read_name(offset: int) -> Tuple[str, int]:
            labels: List[str] = []
            jumped = False
            end = offset
            for _ in range(64):
                if offset >= len(data):
                    raise ValueError("truncated name")
                length = data[offset]
                if length == 0:
                    if not jumped:
                        end = offset + 1
                    break
                if length & 0xC0 == 0xC0:
                    pointer = ((length & 0x3F) << 8) | data[offset + 1]
                    if not jumped:
                        end = offset + 2
                    offset = pointer
                    jumped = True
                    continue
                labels.append(data[offset + 1 : offset + 1 + length].decode("ascii", errors="replace"))
                offset += 1 + length
                if not jumped:
                    end = offset
            return ".".join(labels), end

        for _ in range(qd):
            _qname, pos = read_name(pos)
            pos += 4

        answers: List[Dict[str, object]] = []
        for _ in range(an):
            rname, pos = read_name(pos)
            rtype, _rclass, ttl, rdlen = struct.unpack_from(">HHIH", data, pos)
            pos += 8
            rdata = data[pos : pos + rdlen]
            pos += rdlen
            entry: Dict[str, object] = {"name": rname, "type": rtype, "ttl": ttl}
            if rtype == 1 and len(rdata) == 4:
                entry["a"] = socket.inet_ntoa(rdata)
            elif rtype == 16:  # TXT: sequence of length-prefixed strings
                strings: List[str] = []
                offset = 0
                while offset < len(rdata):
                    length = rdata[offset]
                    strings.append(
                        rdata[offset + 1 : offset + 1 + length].decode("utf-8", errors="replace")
                    )
                    offset += 1 + length
                entry["txt"] = strings
            answers.append(entry)
        return {"answers": answers}
    except (struct.error, ValueError, IndexError):
        return None


_APPLE_MODEL_KEYS = ("ipad", "iphone", "mac", "imac", "macbook", "appletv", "airplay")


def hints_from_llmnr(result: Dict[str, object]) -> FingerprintHints:
    """An LLMNR answer means Windows or systemd-resolved Linux — not Apple/Android."""
    hints = FingerprintHints()
    answers = result.get("answers") or []
    if not isinstance(answers, list) or not answers:
        return hints
    first = answers[0]
    if isinstance(first, dict):
        name = str(first.get("name") or "")
        if "." in name:
            hints.hostname = name.split(".", 1)[0]
    hints.os_family = "linux"  # placeholder family; confidence is deliberately
    # below certainty — LLMNR only *excludes* Apple/Android, so it cannot pick
    # a winner alone and will usually lose the merge to a stronger hint.
    hints.confidence = 0.35
    hints.evidence.append("LLMNR answered (Windows or systemd-resolved Linux)")
    return hints


def hints_from_mdns(result: Dict[str, object]) -> FingerprintHints:
    """mDNS answer ⇒ Apple/Linux/Android; Apple TXT ``model=`` pins the family."""
    hints = FingerprintHints()
    answers = result.get("answers") or []
    if not isinstance(answers, list) or not answers:
        return hints
    joined = " ".join(
        " ".join(a.get("txt", [])) if isinstance(a, dict) else "" for a in answers
    ).lower()
    lowered = joined.replace("_", "-")
    for key in _APPLE_MODEL_KEYS:
        if f"model={key}" in lowered or f"model={key}" in joined:
            hints.os_family = "apple"
            hints.confidence = 0.9
            hints.evidence.append(f"mDNS TXT model identifies Apple hardware ({joined[:80]})")
            return hints
    if "android" in lowered or "adb" in lowered:
        hints.os_family = "android"
        hints.confidence = 0.85
        hints.evidence.append("mDNS response carries Android markers")
        return hints
    hints.os_family = "linux"
    hints.confidence = 0.6
    hints.evidence.append("mDNS answered .local query (Apple/Linux/Android)")
    return hints


# ---------------------------------------------------------------------------
# SSDP / UPnP
# ---------------------------------------------------------------------------

SSDP_MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 1\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
).encode("ascii")

_SSDP_OS_RULES: Tuple[Tuple[str, str], ...] = (
    ("windows", "windows"),
    ("microsoft", "windows"),
    ("xbox", "windows"),
    ("android", "android"),
    ("linux", "linux"),
    ("freebsd", "linux"),
    ("intel/", "linux"),  # Intel UPnP SDK ships with Linux media stacks
    ("mac os", "apple"),
    ("darwin", "apple"),
    ("airtunes", "apple"),
    ("airport", "apple"),
    ("udap", "apple"),  # Apple-ecosystem UPnP bridge
)


def parse_ssdp_reply(data: bytes) -> Optional[Dict[str, str]]:
    """First line + headers of an HTTPU response, lower-cased keys."""
    try:
        text = data.decode("utf-8", errors="replace")
        lines = text.split("\r\n")
        if not lines or not lines[0].startswith("HTTP/1.1 200"):
            return None
        headers: Dict[str, str] = {}
        for line in lines[1:]:
            if ":" in line:
                key, value = line.split(":", 1)
                headers[key.strip().lower()] = value.strip()
        return headers
    except Exception:  # pragma: no cover - decode never raises with errors=replace
        return None


def hints_from_ssdp(headers: Dict[str, str]) -> FingerprintHints:
    """Map a Server/ST header pair onto an OS family."""
    hints = FingerprintHints()
    blob = " ".join(
        str(headers.get(key, "")) for key in ("server", "st", "usn", "location")
    ).lower()
    if not blob.strip():
        return hints
    for needle, family in _SSDP_OS_RULES:
        if needle in blob:
            hints.os_family = family
            # Server headers are self-declared strings — good, not forensic.
            hints.confidence = 0.8 if family != "windows" else 0.85
            hints.evidence.append(f"SSDP Server header: {headers.get('server', '')[:90]}")
            return hints
    if blob.strip():
        hints.evidence.append(f"SSDP responder present ({headers.get('st', '')[:60]})")
    return hints


async def ssdp_sweep(ips: Iterable[str], *, timeout: float = SSDP_TIMEOUT) -> Dict[str, FingerprintHints]:
    """One multicast M-SEARCH; replies keyed by responder IP."""
    wanted = set(ips)
    found: Dict[str, FingerprintHints] = {}
    if not wanted:
        return found

    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setblocking(False)
        await loop.sock_bind(sock, ("", 0))
    except OSError as exc:
        logger.debug("SSDP socket unavailable: %s", exc)
        sock.close()
        return found

    received: List[Tuple[str, bytes]] = []

    async def _reader() -> None:
        while True:
            try:
                data, addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 4096), timeout)
            except (asyncio.TimeoutError, OSError):
                return
            received.append((addr[0], data))

    reader = asyncio.create_task(_reader())
    try:
        await loop.sock_sendto(sock, SSDP_MSEARCH, SSDP_ADDR)
        await reader
    finally:
        if not reader.done():
            reader.cancel()
        sock.close()

    for ip, data in received:
        if ip not in wanted:
            continue
        headers = parse_ssdp_reply(data)
        if headers:
            found[ip] = hints_from_ssdp(headers)
    return found


# ---------------------------------------------------------------------------
# Per-host active probe (NBNS + LLMNR + mDNS against one address)
# ---------------------------------------------------------------------------


async def _unicast_query(
    query: bytes,
    address: Tuple[str, int],
    *,
    timeout: float = PROBE_TIMEOUT,
) -> Optional[bytes]:
    """Fire one UDP query, wait briefly for the first reply. Never raises."""
    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.setblocking(False)
        await loop.sock_bind(sock, ("", 0))
        await loop.sock_sendto(sock, query, address)
        data, _addr = await asyncio.wait_for(loop.sock_recvfrom(sock, 4096), timeout)
        return data
    except (asyncio.TimeoutError, OSError):
        return None
    finally:
        sock.close()


async def probe_host(ip: str, hostname: Optional[str] = None) -> FingerprintHints:
    """NBNS node status + LLMNR + mDNS probes against one host, merged.

    All three run concurrently under one deadline; silence is a valid answer
    and yields an empty hint (callers then keep the hostname/OUI verdict).
    """
    queries: List[asyncio.Task[FingerprintHints]] = [
        asyncio.create_task(_probe_nbstat(ip)),
    ]
    if hostname:
        safe = re.sub(r"[^A-Za-z0-9._-]", "", hostname).strip(".")
        if safe:
            queries.append(asyncio.create_task(_probe_llmnr(ip, safe)))
            if "." not in safe:
                queries.append(asyncio.create_task(_probe_mdns(ip, f"{safe}.local")))

    try:
        results = await asyncio.wait_for(
            asyncio.gather(*queries), timeout=PROBE_TIMEOUT + 0.3
        )
    except asyncio.TimeoutError:
        for task in queries:
            task.cancel()
        results = []
    except Exception as exc:  # pragma: no cover - defensive
        logger.debug("probe_host(%s) failed: %s", ip, exc)
        results = []

    merged = FingerprintHints()
    for hints in results:
        merged.merge(hints)
    return merged


async def _probe_nbstat(ip: str) -> FingerprintHints:
    data = await _unicast_query(build_nbstat_query(), (ip, 137))
    if not data:
        return FingerprintHints()
    result = parse_nbstat_response(data)
    if result is None:
        return FingerprintHints()
    return hints_from_nbstat(result)


async def _probe_llmnr(ip: str, hostname: str) -> FingerprintHints:
    data = await _unicast_query(build_dns_query(hostname, 1), (ip, 5355))
    if not data:
        return FingerprintHints()
    parsed = parse_dns_response(data)
    if parsed is None:
        return FingerprintHints()
    return hints_from_llmnr(parsed)


async def _probe_mdns(ip: str, fqdn: str) -> FingerprintHints:
    data = await _unicast_query(build_dns_query(fqdn, 16), (ip, 5353))  # TXT
    if not data:
        # Some stacks answer A but not TXT for legacy unicast queries.
        data = await _unicast_query(build_dns_query(fqdn, 1), (ip, 5353))
    if not data:
        return FingerprintHints()
    parsed = parse_dns_response(data)
    if parsed is None:
        return FingerprintHints()
    return hints_from_mdns(parsed)


# ---------------------------------------------------------------------------
# Passive DHCP fingerprints (recorded by the monitor, read here)
# ---------------------------------------------------------------------------

# Option-60 vendor classes are self-declared and short-circuit the match.
_VENDOR_FAMILY_RULES: Tuple[Tuple[str, str], ...] = (
    ("msft", "windows"),
    ("microsoft", "windows"),
    ("android", "android"),
    ("apple", "apple"),
    ("dhcpcd-", "linux"),
    ("dhclient", "linux"),
    ("isc-", "linux"),
)

# Exact option-55 sets, commonly observed signatures. Exact equality only —
# a subset match would blur Android (dhcpcd) into Linux with false certainty.
_PARAM_SET_RULES: Tuple[Tuple[frozenset], ...] = (
    (frozenset({1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 121, 124, 125}), "windows",
     "DHCP parameter list matches the Windows signature"),
    (frozenset({1, 3, 6, 15, 116, 17, 31, 33, 121, 175, 252}), "apple",
     "DHCP parameter list matches the Apple signature"),
    (frozenset({1, 3, 6, 12, 15, 28, 33, 42, 119, 249, 252}), "linux",
     "DHCP parameter list matches the dhclient signature"),
)

_dhcp_cache: Dict[str, Tuple[FingerprintHints, float]] = {}


def classify_dhcp_options(
    param_list: Sequence[int], vendor_class: str = "", hostname: str = ""
) -> FingerprintHints:
    """Turn DHCP option 55/60/12 into a hint. Empty when nothing is decisive."""
    hints = FingerprintHints()
    vendor = (vendor_class or "").strip().lower()
    for needle, family in _VENDOR_FAMILY_RULES:
        if needle in vendor:
            hints.os_family = family
            hints.confidence = 0.9
            hints.evidence.append(f"DHCP vendor class {vendor_class!r}")
            break
    if hints.os_family is None and param_list:
        signature = frozenset(int(p) for p in param_list)
        for known, family, note in _PARAM_SET_RULES:
            if signature == known:
                hints.os_family = family
                hints.confidence = 0.8
                hints.evidence.append(note)
                break
    if hostname:
        hints.hostname = hostname.strip()
    return hints


def record_dhcp_hint(
    mac: str,
    *,
    param_list: Sequence[int] = (),
    vendor_class: str = "",
    hostname: str = "",
) -> None:
    """Cache a passive DHCP observation keyed by the client MAC."""
    key = normalize_mac(mac)
    if not key:
        return
    hints = classify_dhcp_options(param_list, vendor_class, hostname)
    if hints.os_family is None and not hints.hostname:
        return
    existing = _dhcp_cache.get(key)
    if existing and existing[0].confidence >= hints.confidence:
        # Keep the stronger record but always refresh the hostname.
        if hostname:
            existing[0].hostname = hostname
        return
    now = time.monotonic()
    # Opportunistic prune so the cache cannot grow without bound.
    for stale_key, (_hints, seen) in list(_dhcp_cache.items()):
        if now - seen > DHCP_HINT_TTL_S:
            _dhcp_cache.pop(stale_key, None)
    _dhcp_cache[key] = (hints, now)


def dhcp_hint_for(mac: Optional[str]) -> Optional[FingerprintHints]:
    """Cached DHCP hint for a MAC, if one is still fresh."""
    key = normalize_mac(mac or "")
    if not key:
        return None
    entry = _dhcp_cache.get(key)
    if entry is None:
        return None
    hints, seen = entry
    if time.monotonic() - seen > DHCP_HINT_TTL_S:
        _dhcp_cache.pop(key, None)
        return None
    return hints


# ---------------------------------------------------------------------------
# Family → inventory labels (same vocabulary as classify_host)
# ---------------------------------------------------------------------------

_FAMILY_LABELS: Dict[str, Tuple[str, str]] = {
    "windows": ("Windows Workstation", "Windows"),
    "android": ("Phone/Tablet (Android)", "Android"),
    "apple": ("Apple Computer", "macOS/iOS"),
    "linux": ("Linux Workstation", "Linux"),
}


def labels_for_hints(hints: Optional[FingerprintHints]) -> Tuple[Optional[str], Optional[str]]:
    """(device_type, os) labels for a hint, or (None, None) when too weak."""
    if hints is None or hints.os_family is None:
        return None, None
    if hints.confidence < MIN_CONFIDENCE:
        return None, None
    return _FAMILY_LABELS.get(hints.os_family, (None, None))
