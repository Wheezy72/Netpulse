"""Delete the device rows a proxy-ARP router or captive portal invented.

A hotspot or a router doing proxy ARP answers for addresses it does not own, so
one sweep reports a whole /24 as "hosts" that all share its MAC address. The
discovery code now collapses that fan-out (``collapse_proxy_arp``), but rows
written before the fix stay in the inventory: the console shows 255 nodes, the
topology map has one dot in the middle, and every count is wrong.

This script finds those rows and removes them, keeping the lowest address of
each shared MAC -- the router's own address in the layout that produces this.
The threshold matches discovery (``PROXY_ARP_ADDRESS_LIMIT``), so it only
touches what the scanner would now refuse to record. A machine with several
NICs has a different MAC per address, and a NAT router with a handful of extra
addresses stays under the limit, so neither is affected.

Dry run by default:

    python scripts/prune_phantom_devices.py                  # report only
    python scripts/prune_phantom_devices.py --apply          # delete them
    python scripts/prune_phantom_devices.py --network-id 3   # one network
    python scripts/prune_phantom_devices.py --limit 16       # a looser rule

Child rows go first: metrics and vulnerabilities belong to the device and are
deleted with it, ports cascade, and script jobs are kept but lose their device
link because a run that happened is history, not an address.
"""
from __future__ import annotations

import argparse
import asyncio
import ipaddress
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Sequence

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy import delete, select, update  # noqa: E402
from sqlalchemy.exc import OperationalError  # noqa: E402

from app.db.session import async_session_factory, engine  # noqa: E402
from app.models.device import Device  # noqa: E402
from app.models.device_port import DevicePort  # noqa: E402
from app.models.metric import Metric  # noqa: E402
from app.models.script_job import ScriptJob  # noqa: E402
from app.models.vulnerability import Vulnerability  # noqa: E402

# Same threshold as PROXY_ARP_ADDRESS_LIMIT in app/services/device_discovery.py.
# It is repeated rather than imported so this script does not pull in scapy just
# to read one integer; tests/test_prune_phantom_devices.py keeps them in sync.
DEFAULT_LIMIT = 8


@dataclass(frozen=True)
class Clump:
    """One MAC answering for too many addresses on one network."""

    network_id: int | None
    mac: str
    keep_id: int
    keep_ip: str
    keep_hostname: str | None
    keep_is_gateway: bool
    delete_ids: tuple[int, ...]
    first_dropped: str | None
    last_dropped: str | None

    @property
    def rows(self) -> int:
        """How many rows the clump holds, counting the one that stays."""
        return len(self.delete_ids) + 1


def _ip_key(address: str) -> tuple:
    """Order addresses numerically, falling back to text for odd input."""
    try:
        return (0, int(ipaddress.ip_address(address)))
    except ValueError:
        return (1, address)


def _normalise(mac: str | None) -> str | None:
    """MACs are written in several cases by different sources."""
    if not mac:
        return None
    cleaned = mac.strip().upper().replace("-", ":")
    return cleaned or None


def plan_purge(
    rows: Iterable[Sequence[Any]],
    limit: int = DEFAULT_LIMIT,
) -> list[Clump]:
    """Group device rows by MAC and return the ones over *limit*.

    *rows* are ``(id, network_id, mac_address, ip_address, hostname,
    is_gateway)`` sequences. Grouping is per network: five homes can all run
    192.168.1.10, and a MAC seen in two of them is two separate questions.
    """
    if limit < 1:
        raise ValueError("limit must be at least 1")

    grouped: dict[tuple[int | None, str], list[tuple]] = defaultdict(list)
    for device_id, network_id, mac, ip_address, hostname, is_gateway in rows:
        normalised = _normalise(mac)
        if normalised is None:
            continue
        grouped[(network_id, normalised)].append(
            (device_id, ip_address, hostname, bool(is_gateway))
        )

    clumps: list[Clump] = []
    for (network_id, mac), members in grouped.items():
        if len(members) <= limit:
            continue
        ordered = sorted(members, key=lambda member: (_ip_key(member[1]), member[0]))
        keep_id, keep_ip, keep_hostname, keep_is_gateway = ordered[0]
        dropped = ordered[1:]
        addresses = [member[1] for member in dropped]
        clumps.append(
            Clump(
                network_id=network_id,
                mac=mac,
                keep_id=keep_id,
                keep_ip=keep_ip,
                keep_hostname=keep_hostname,
                keep_is_gateway=keep_is_gateway,
                delete_ids=tuple(member[0] for member in dropped),
                first_dropped=min(addresses, key=_ip_key) if addresses else None,
                last_dropped=max(addresses, key=_ip_key) if addresses else None,
            )
        )

    clumps.sort(key=lambda clump: (clump.network_id is None, clump.network_id or 0, clump.mac))
    return clumps


def _network_label(network_id: int | None) -> str:
    return "no network" if network_id is None else f"network {network_id}"


def _report(clumps: Sequence[Clump]) -> None:
    for clump in clumps:
        print(
            f"\n{_network_label(clump.network_id)}  MAC {clump.mac}  "
            f"answers for {clump.rows} addresses"
        )
        role = " (gateway)" if clump.keep_is_gateway else ""
        named = f'  "{clump.keep_hostname}"' if clump.keep_hostname else ""
        print(f"  keep {clump.keep_ip}{named}{role}  [device {clump.keep_id}]")
        span = ""
        if clump.first_dropped and clump.last_dropped:
            span = f"  ({clump.first_dropped} … {clump.last_dropped})"
        print(f"  drop {len(clump.delete_ids)} rows{span}")


async def _run(args: argparse.Namespace) -> int:
    try:
        return await _prune(args)
    finally:
        # The engine is module-level; leave the pool closed rather than letting
        # the interpreter tear it down mid-connection.
        await engine.dispose()


async def _prune(args: argparse.Namespace) -> int:
    query = select(
        Device.id,
        Device.network_id,
        Device.mac_address,
        Device.ip_address,
        Device.hostname,
        Device.is_gateway,
    ).order_by(Device.id)
    if args.network_id is not None:
        query = query.where(Device.network_id == args.network_id)

    async with async_session_factory() as session:
        rows = (await session.execute(query)).all()
        clumps = plan_purge(rows, args.limit)

        if not clumps:
            print(
                f"No MAC holds more than {args.limit} addresses"
                f"{' on this network' if args.network_id is not None else ''}. "
                "Nothing to prune."
            )
            return 0

        _report(clumps)
        doomed = [device_id for clump in clumps for device_id in clump.delete_ids]
        print(
            f"\n{len(clumps)} MAC(s) over the limit of {args.limit}: "
            f"{len(doomed)} of {len(rows)} device row(s) would be deleted."
        )

        if not args.apply:
            print("Dry run, nothing was deleted. Re-run with --apply to remove them.")
            return 0

        # Children before parents: metrics and vulnerabilities point at the
        # device and go with it, ports cascade, and a script job that ran keeps
        # its record but loses the link to an address that never existed.
        await session.execute(delete(Metric).where(Metric.device_id.in_(doomed)))
        await session.execute(
            delete(Vulnerability).where(Vulnerability.device_id.in_(doomed))
        )
        await session.execute(delete(DevicePort).where(DevicePort.device_id.in_(doomed)))
        await session.execute(
            update(ScriptJob).where(ScriptJob.device_id.in_(doomed)).values(device_id=None)
        )
        result = await session.execute(delete(Device).where(Device.id.in_(doomed)))
        await session.commit()

    deleted = result.rowcount if result.rowcount is not None and result.rowcount >= 0 else len(doomed)
    print(f"Deleted {deleted} device row(s). Sweep again to rebuild the inventory.")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Remove device rows invented by proxy ARP or a captive portal.",
    )
    parser.add_argument(
        "--apply",
        action="store_true",
        help="delete the rows instead of only reporting them",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=DEFAULT_LIMIT,
        help=f"how many addresses one MAC may hold before it is a clump (default: {DEFAULT_LIMIT})",
    )
    parser.add_argument(
        "--network-id",
        type=int,
        default=None,
        help="only look at this network",
    )
    args = parser.parse_args(argv)

    if args.limit < 1:
        parser.error("--limit must be at least 1")

    try:
        return asyncio.run(_run(args))
    except (OperationalError, OSError) as exc:
        print(f"Could not reach the database: {exc}", file=sys.stderr)
        print(
            "Start the stack first (docker compose up -d), or run the equivalent "
            "SQL inside the container:\n"
            "  docker compose exec db psql -U netpulse -d netpulse -c "
            "\"SELECT mac_address, count(*) FROM devices GROUP BY mac_address ORDER BY 2 DESC;\"",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
