"""Ask the router who is connected, and mark the inventory accordingly.

Discovery answers "what did something on this segment reply to?" — ARP from
the console's own neighbour table, ICMP echoes, nmap probes. That is the only
thing an endpoint can know, and it produces the two failure modes an operator
actually sees:

  * a ghost — a stale neighbour entry for a machine that left the network an
    hour ago still sits in the table and gets drawn again;
  * a miss — a phone under Wi-Fi client isolation, a sleeping laptop, or
    anything on a segment this console is not attached to never answers at all.

The device that hands out addresses knows both answers: it wrote the lease and
it holds the MAC in its ARP/bridge table. This module reads those tables and
marks devices ``verified`` (the router lists them) or leaves them ``observed``
(they answered, the router does not list them).

Configuration is deliberately thin — ``ROUTER_SOURCE=auto`` is the default and
it discovers what it can by itself:

  1. a dnsmasq/Pi-hole leases file, if one exists on this machine
     (/var/lib/misc/dnsmasq.leases, /etc/pihole/dnsmasq.leases, OpenWrt, …);
  2. the RouterOS API, if ROUTEROS_URL and ROUTEROS_USER are set;
  3. SNMPv2c against the detected gateway with the default community.

So on a MikroTik or an OpenWrt/Huawei/ZTE/Ubiquiti/Cisco router with SNMP on,
it works with no configuration at all. Cheap consumer Tenda boxes usually have
no SNMP and no local leases file — the source then reports that plainly and
those devices simply stay "observed", rather than the console pretending to be
sure about them. Setting ROUTER_HOST/ROUTER_SNMP_COMMUNITY/ROUTEROS_* is only
needed when the defaults are wrong (a different gateway, a renamed community,
a router on another subnet).

Nothing here writes devices: verification only marks rows discovery created,
so identity rules stay in ``device_discovery``. Entries the router lists that
NetPulse has never seen are reported as ``unmatched`` — a router that names a
device the console has not swept yet is exactly the signal worth showing.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.models.device import Device
from app.services import snmp_client

logger = logging.getLogger("netpulse.router_source")

# IP-MIB ipNetToMediaTable: column 2 is the MAC, column 3 the IP, indexed by
# (ifIndex, ip-address). The legacy MIB-II atTable carries the same pair and
# is what older Huawei/ZTE firmware still implements.
_OID_IPNET_PHYS = "1.3.6.1.2.1.4.22.1.2"
_OID_IPNET_NET = "1.3.6.1.2.1.4.22.1.3"
_OID_AT_PHYS = "1.3.6.1.2.1.3.1.1.2"
_OID_AT_NET = "1.3.6.1.2.1.3.1.1.3"

# Places dnsmasq-family servers keep a lease file, checked in order. Reading
# one of these is how "auto" finds a router's leases with no configuration at
# all: Pi-hole, OpenWrt export, plain dnsmasq and ISC dhcpd's sibling installs
# all use one of these paths.
_AUTO_LEASE_PATHS = (
    "/var/lib/misc/dnsmasq.leases",
    "/var/lib/dnsmasq/dnsmasq.leases",
    "/etc/pihole/dnsmasq.leases",
    "/tmp/dhcp.leases",
    "/var/lib/dhcp/dhcpd.leases",
)


@dataclass
class RouterEntry:
    """One device the router says is present."""

    ip_address: str
    mac_address: Optional[str] = None
    hostname: Optional[str] = None
    kind: str = "arp"  # "arp" or "lease"


@dataclass
class RouterPull:
    """Result of one query against one source."""

    source: str
    target: str
    entries: List[RouterEntry] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None


@dataclass
class VerifyOutcome:
    """What one verification pass changed."""

    source: str = ""
    target: str = ""
    entries: int = 0
    verified: int = 0
    unverified: int = 0
    unmatched: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def ok(self) -> bool:
        return self.error is None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "entries": self.entries,
            "verified": self.verified,
            "unverified": self.unverified,
            "unmatched": self.unmatched,
            "warnings": self.warnings,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# SNMP helpers
# ---------------------------------------------------------------------------


def _index_suffix(oid: str, root: str) -> Optional[str]:
    """Index of *oid* below the walked root, ``None`` when it is not below it.

    ``1.3.6.1.2.1.4.22.1.2.1.192.168.1.100`` below root
    ``1.3.6.1.2.1.4.22.1.2`` -> ``1.192.168.1.100``. Matching on the root
    rather than searching for ``".2."`` anywhere in the OID is what keeps the
    join correct: the base OID itself contains ".2.", and an address like
    ``10.0.2.15`` contains it too.
    """
    prefix = f"{root}."
    if not oid.startswith(prefix):
        return None
    return oid[len(prefix) :]


def _correlate(
    phys: List[Tuple[str, Any]],
    net: List[Tuple[str, Any]],
    phys_root: str,
    net_root: str,
) -> List[RouterEntry]:
    """Join the two walked columns back together on their shared index."""
    macs: Dict[str, str] = {}
    for oid, value in phys:
        key = _index_suffix(oid, phys_root)
        mac = snmp_client.mac_to_str(value)
        if key is not None and mac:
            macs[key] = mac

    entries: List[RouterEntry] = []
    seen: set[str] = set()
    for oid, value in net:
        key = _index_suffix(oid, net_root)
        ip = snmp_client.to_ip(value)
        if key is None or not ip or ip in seen:
            continue
        seen.add(ip)
        entries.append(RouterEntry(ip_address=ip, mac_address=macs.get(key), kind="arp"))
    return entries


async def _from_snmp(host: str) -> RouterPull:
    pull = RouterPull(source="snmp", target=f"{host}:{settings.router_snmp_port}")
    kwargs = {
        "community": settings.router_snmp_community or "public",
        "port": settings.router_snmp_port,
        "timeout": settings.router_snmp_timeout,
        "retries": settings.router_snmp_retries,
    }

    def _read() -> Tuple[List[RouterEntry], Optional[str]]:
        for phys_oid, net_oid, note in (
            (_OID_IPNET_PHYS, _OID_IPNET_NET, None),
            (_OID_AT_PHYS, _OID_AT_NET, "answered with the legacy atTable"),
        ):
            try:
                phys = snmp_client.walk(host, phys_oid, **kwargs)
                net = snmp_client.walk(host, net_oid, **kwargs)
            except snmp_client.SnmpError as exc:
                return [], str(exc)
            if phys and net:
                return _correlate(phys, net, phys_oid, net_oid), note
        return [], "no ARP table available over SNMP (community wrong, or the table is disabled)"

    entries, note = await asyncio.to_thread(_read)
    if note and not entries:
        pull.error = note
    elif note:
        pull.warnings.append(note)
    pull.entries = entries
    return pull


# ---------------------------------------------------------------------------
# Other sources
# ---------------------------------------------------------------------------


def _parse_routeros_url(url: str) -> Tuple[str, int]:
    raw = url.strip()
    if "://" in raw:
        raw = raw.split("://", 1)[1]
    if ":" in raw:
        host, _, port = raw.rpartition(":")
        try:
            return host, int(port)
        except ValueError:
            return raw, 8728
    return raw, 8728


async def _from_routeros() -> RouterPull:
    host, port = _parse_routeros_url(settings.routeros_url)
    pull = RouterPull(source="routeros", target=f"{host}:{port}")
    if not settings.routeros_user:
        pull.error = "ROUTEROS_USER is not set"
        return pull

    from app.services.routers.mikrotik import MikroTikRouterDriver

    driver = MikroTikRouterDriver(
        host=host,
        username=settings.routeros_user,
        password=settings.routeros_pass or "",
        port=port,
    )
    try:
        arp_rows = await driver.get_arp_table()
        lease_rows = await driver.get_dhcp_leases()
    except Exception as exc:  # noqa: BLE001 - reported, never raised into a sweep
        pull.error = f"RouterOS API unreachable: {exc}"
        return pull

    by_ip: Dict[str, RouterEntry] = {}
    for row in arp_rows:
        ip = (row.get("address") or "").strip()
        if not ip:
            continue
        by_ip[ip] = RouterEntry(
            ip_address=ip,
            mac_address=snmp_client.mac_to_str(row.get("mac-address")),
            kind="arp",
        )

    for row in lease_rows:
        ip = (row.get("address") or "").strip()
        if not ip:
            continue
        entry = by_ip.get(ip)
        if entry is None:
            entry = RouterEntry(ip_address=ip, kind="lease")
            by_ip[ip] = entry
        mac = snmp_client.mac_to_str(row.get("mac-address"))
        if mac:
            entry.mac_address = mac
        hostname = (row.get("host-name") or "").strip()
        if hostname and hostname != "*":
            entry.hostname = hostname

    pull.entries = list(by_ip.values())
    return pull


def _find_lease_file() -> Optional[str]:
    """An explicitly configured path, else the first candidate that exists."""
    configured = (settings.router_dhcp_leases_file or "").strip()
    if configured:
        return configured
    for candidate in _AUTO_LEASE_PATHS:
        try:
            if Path(candidate).is_file():
                return candidate
        except OSError:
            continue
    return None


def _from_dnsmasq(path: str) -> RouterPull:
    pull = RouterPull(source="dnsmasq", target=path)
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        pull.error = f"leases file unreadable: {exc}"
        return pull

    for line in text.splitlines():
        parts = line.split()
        # <expiry> <mac> <ip> <hostname> <client-id>
        if len(parts) < 4:
            continue
        ip = snmp_client.to_ip(parts[2])
        if not ip:
            continue
        hostname = parts[3] if parts[3] != "*" else None
        pull.entries.append(
            RouterEntry(
                ip_address=ip,
                mac_address=snmp_client.mac_to_str(parts[1]),
                hostname=hostname,
                kind="lease",
            )
        )
    return pull


# ---------------------------------------------------------------------------
# Pulling
# ---------------------------------------------------------------------------


def _snmp_target() -> Optional[str]:
    if settings.router_host:
        return settings.router_host
    gateway = (settings.pulse_gateway_ip or "").strip()
    if not gateway or gateway == "auto":
        return None
    return gateway


def _enabled_sources() -> List[str]:
    """Sources worth trying, cheapest/most reliable first.

    ``auto`` needs no configuration: it probes whatever the environment already
    suggests. Anything explicitly named in ROUTER_SOURCE runs that one source
    instead, so an operator can pin SNMP when the gateway is not the router.
    """
    choice = settings.router_source.strip().lower()
    if choice in {"", "none", "disabled", "off"}:
        return []
    if choice in {"snmp", "routeros", "dnsmasq"}:
        return [choice]

    ordered: List[str] = []
    if _find_lease_file():
        ordered.append("dnsmasq")
    if settings.routeros_url and settings.routeros_user:
        ordered.append("routeros")
    if _snmp_target():
        ordered.append("snmp")
    return ordered


async def pull_router_entries() -> Optional[RouterPull]:
    """Query the configured source(s) once. ``None`` when verification is off."""
    sources = _enabled_sources()
    if not sources:
        return None

    pulls: List[RouterPull] = []
    for source in sources:
        if source == "snmp":
            target = _snmp_target()
            if not target:
                pulls.append(
                    RouterPull(
                        source="snmp",
                        target="(unset)",
                        error="ROUTER_HOST is not set and no gateway could be detected",
                    )
                )
            else:
                pulls.append(await _from_snmp(target))
        elif source == "routeros":
            pulls.append(await _from_routeros())
        elif source == "dnsmasq":
            pulls.append(_from_dnsmasq(_find_lease_file() or ""))

    if not pulls:
        return None

    usable = [pull for pull in pulls if pull.ok]
    if usable:
        # Prefer the source that actually produced data; a source that answered
        # with an empty table becomes a note instead of hiding the useful one.
        chosen = max(usable, key=lambda pull: len(pull.entries))
        for other in pulls:
            if other is chosen:
                continue
            if other.error:
                chosen.warnings.append(f"{other.source}: {other.error}")
            elif not other.entries:
                chosen.warnings.append(f"{other.source}: no entries returned")
        return chosen

    failure = pulls[0]
    failure.error = failure.error or "no source returned data"
    failure.warnings.extend(
        f"{pull.source}: {pull.error}" for pull in pulls[1:] if pull.error
    )
    return failure


# ---------------------------------------------------------------------------
# Verification
# ---------------------------------------------------------------------------


def _matches(
    devices: List[Device],
    entries: List[RouterEntry],
) -> Tuple[Dict[int, RouterEntry], List[RouterEntry]]:
    """Pair inventory rows with router entries.

    Address first (the usual case, and the one that cannot be ambiguous), then
    MAC for rows whose address changed since the last sweep. An entry that
    matches nothing is returned separately so the caller can show the gap
    instead of inventing a device.
    """
    by_ip: Dict[str, RouterEntry] = {entry.ip_address: entry for entry in entries}
    by_mac: Dict[str, RouterEntry] = {
        entry.mac_address.upper(): entry for entry in entries if entry.mac_address
    }

    matched: Dict[int, RouterEntry] = {}
    taken: set[str] = set()

    for device in devices:
        entry = by_ip.get(device.ip_address)
        if entry is None and device.mac_address:
            entry = by_mac.get(device.mac_address.upper())
        if entry is not None and entry.ip_address not in taken:
            matched[device.id] = entry
            taken.add(entry.ip_address)

    unmatched = [entry for entry in entries if entry.ip_address not in taken]
    return matched, unmatched


# Repeating the same router failure on every sweep would bury the log. The
# signature is remembered so the first failure is a WARNING and later ones are
# DEBUG until the message changes.
_last_failure: Optional[str] = None


def describe_backoff() -> Dict[str, float]:
    """Seconds until the next attempt, and how many failures led there."""
    return {"retry_in_seconds": round(_backoff_remaining(), 1), "failures": _failure_count}


def _report_failure(source: str, target: str, error: str) -> None:
    global _last_failure
    signature = f"{source}|{target}|{error}"
    if signature == _last_failure:
        logger.debug("Router verification still failing: %s", error)
        return
    _last_failure = signature
    logger.warning("Router verification failed (%s %s): %s", source, target, error)


async def verify_devices(db: AsyncSession) -> VerifyOutcome:
    """Run one verification pass and update the flags on the inventory."""
    global _last_failure

    pull = await pull_router_entries()
    if pull is None:
        return VerifyOutcome(warnings=["Router verification is turned off"])
    if not pull.ok:
        _report_failure(pull.source, pull.target, pull.error or "unknown error")
        return VerifyOutcome(
            source=pull.source,
            target=pull.target,
            error=pull.error,
            warnings=pull.warnings,
        )

    _last_failure = None
    rows = await db.execute(select(Device))
    devices = list(rows.scalars().all())
    matched, unmatched = _matches(devices, pull.entries)
    now = datetime.now(timezone.utc)
    outcome = VerifyOutcome()

    for device in devices:
        entry = matched.get(device.id)
        if entry is not None:
            device.verified = True
            device.verified_at = now
            device.verified_source = pull.source
            # A MAC the router knows beats one a stale neighbour entry carried,
            # and a hostname from a DHCP lease beats nothing at all.
            if entry.mac_address and not device.mac_address:
                device.mac_address = entry.mac_address
            if entry.hostname and not device.hostname:
                device.hostname = entry.hostname
        elif device.verified:
            # Not listed any more: gone, or simply idle. The flag follows the
            # router — it is what the router would say today.
            device.verified = False
        outcome.verified += 1 if entry is not None else 0

    outcome.unverified = len(devices) - outcome.verified
    outcome.entries = len(pull.entries)
    outcome.unmatched = [entry.ip_address for entry in unmatched]
    outcome.warnings = list(pull.warnings)
    outcome.source = pull.source
    outcome.target = pull.target
    await db.commit()
    return outcome


# Backoff after failed pulls, indexed by consecutive failures. A router that
# refuses SNMP (the common case on ISP-supplied kit) is not going to start
# answering because we asked again 300 seconds later; retrying at full rate just
# fills the log and the sweep budget. Recovery is still automatic — a router
# that gets SNMP enabled is picked up within the hour.
_FAILURE_BACKOFF_SECONDS = (0.0, 0.0, 300.0, 900.0, 1800.0, 3600.0)
_failure_count = 0
_next_attempt_at = 0.0


def _backoff_remaining() -> float:
    return max(0.0, _next_attempt_at - time.monotonic())


def reset_backoff() -> None:
    """Forget past failures, e.g. after the operator changes the settings."""
    global _failure_count, _next_attempt_at
    _failure_count = 0
    _next_attempt_at = 0.0


async def verify_if_configured(db: AsyncSession) -> Optional[VerifyOutcome]:
    """Verification pass, or ``None`` when the feature is off or backing off.

    The guard lives here so call sites (discovery, the scheduler) cannot forget
    to check the flag and end up probing the router on installs that never
    asked for it.
    """
    global _failure_count, _next_attempt_at

    if not settings.router_source_configured:
        return None
    if _backoff_remaining() > 0:
        return None

    outcome = await verify_devices(db)
    if outcome.error:
        _failure_count += 1
        delay = _FAILURE_BACKOFF_SECONDS[min(_failure_count, len(_FAILURE_BACKOFF_SECONDS) - 1)]
        if delay:
            _next_attempt_at = time.monotonic() + delay
            logger.info(
                "Router verification paused for %.0fs after %d failed attempt(s).",
                delay,
                _failure_count,
            )
    else:
        reset_backoff()
    return outcome


def describe_configuration() -> Dict[str, Any]:
    """What the API reports, so a failed pull is diagnosable without logs."""
    sources = _enabled_sources()
    target = ""
    if "dnsmasq" in sources:
        target = _find_lease_file() or "(missing)"
    elif "routeros" in sources:
        target = settings.routeros_url or "(unset)"
    elif "snmp" in sources:
        target = _snmp_target() or "(unset)"
    return {
        "enabled": bool(sources),
        "source": settings.router_source.strip().lower() or "off",
        "sources": sources,
        "target": target,
        "snmp_community_set": bool(settings.router_snmp_community),
        "interval_seconds": settings.router_verify_interval,
    }
