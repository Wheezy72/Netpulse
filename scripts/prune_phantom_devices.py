"""Delete the device rows a proxy-ARP router or captive portal invented.

A hotspot or a router doing proxy ARP answers for addresses it does not own, so
one sweep reports a whole /24 as "hosts" that all share its MAC address. The
discovery code now collapses that fan-out (``collapse_proxy_arp``), but rows
written before the fix stay in the inventory: the console shows 255 nodes, the
topology map has one dot in the middle, and every count is wrong.

This is the command-line front end for
``app/services/phantom_devices.py`` -- the same logic the System tab uses, so
the two can never disagree about what is phantom.

Dry run by default:

    python scripts/prune_phantom_devices.py                  # report only
    python scripts/prune_phantom_devices.py --apply          # delete them
    python scripts/prune_phantom_devices.py --network-id 3   # one network
    python scripts/prune_phantom_devices.py --limit 16       # a looser rule
"""
from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from sqlalchemy.exc import OperationalError  # noqa: E402

from app.db.session import async_session_factory, engine  # noqa: E402
from app.services.phantom_devices import (  # noqa: E402
    DEFAULT_LIMIT,
    Clump,
    apply as apply_purge,
    scan,
)


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
    async with async_session_factory() as session:
        clumps, inspected = await scan(
            session, limit=args.limit, network_id=args.network_id
        )

        if not clumps:
            print(
                f"No MAC holds more than {args.limit} addresses"
                f"{' on this network' if args.network_id is not None else ''}. "
                "Nothing to prune."
            )
            return 0

        _report(clumps)
        removable = sum(len(clump.delete_ids) for clump in clumps)
        print(
            f"\n{len(clumps)} MAC(s) over the limit of {args.limit}: "
            f"{removable} of {inspected} device row(s) would be deleted."
        )

        if not args.apply:
            print("Dry run, nothing was deleted. Re-run with --apply to remove them.")
            return 0

        deleted = await apply_purge(session, clumps)

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
