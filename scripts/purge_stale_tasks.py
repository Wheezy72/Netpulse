"""Drain the Celery queue of work that is no longer worth running.

Two kinds of junk pile up in Redis on a long-lived install:

* messages naming a task this codebase no longer defines (the worker logs a
  multi-line "Received unregistered task" traceback for each one and drops it),
* periodic snapshots published by a beat that has since stopped -- 900 latency
  polls from three hours ago are not work, they are history.

Both starve real jobs: a scan queued behind 9k stale messages waits behind all of
them. This script pops the queue, re-pushes the messages that still matter, and
reports what it dropped.

Policy: unknown task names are always dropped; periodic tasks keep only their
newest ``--keep-periodic`` instance; everything else (script jobs, audit
entries, pcap indexing) is kept unchanged.

Usage::

    python scripts/purge_stale_tasks.py            # report only
    python scripts/purge_stale_tasks.py --apply    # rewrite the queue
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.core.celery_app import celery_app  # noqa: E402
from app.core.config import settings  # noqa: E402

QUEUE = "default"

# Tasks whose every run is just a fresh reading of current state. Replaying an
# old one wastes a worker slot and tells nobody anything.
PERIODIC_TASKS = {
    "app.tasks.monitor_latency_task",
    "app.tasks.uptime_monitor_task",
    "app.tasks.passive_arp_discovery_task",
    "app.tasks.vulnerability_alert_task",
    "app.tasks.scheduled_scan_reminder_task",
}


def _known_tasks() -> set[str]:
    # Importing app.tasks is what registers the handlers; celery_app only
    # declares where they live.
    import app.tasks  # noqa: F401

    return set(celery_app.tasks.keys())


def _task_name(raw: str) -> str:
    try:
        body = json.loads(raw)
    except (TypeError, ValueError):
        return "<unparseable>"
    headers = body.get("headers") if isinstance(body, dict) else None
    if isinstance(headers, dict) and headers.get("task"):
        return str(headers["task"])
    return "<unknown>"


def main() -> int:
    parser = argparse.ArgumentParser(description="Drop stale Celery queue messages.")
    parser.add_argument("--apply", action="store_true", help="rewrite the queue instead of only reporting")
    parser.add_argument("--queue", default=QUEUE, help="queue name (default: default)")
    parser.add_argument(
        "--keep-periodic",
        type=int,
        default=1,
        help="how many of the newest periodic snapshots to keep (default: 1)",
    )
    args = parser.parse_args()

    import redis

    client = redis.Redis.from_url(settings.celery_broker_url)
    known = _known_tasks()
    total = client.llen(args.queue)
    if not total:
        print(f"Queue '{args.queue}' is empty; nothing to do.")
        return 0

    # LPOP walks oldest -> newest, so the tail of `messages` is the newest work.
    messages: list[tuple[str, str]] = []
    while True:
        raw = client.lpop(args.queue)
        if raw is None:
            break
        text = raw.decode("utf-8", errors="replace")
        messages.append((_task_name(text), text))

    dropped: Counter[str] = Counter()
    unknown = {
        name for name, _ in messages if name not in known
    }
    for name in unknown:
        dropped[name] = sum(1 for n, _ in messages if n == name)

    stock = Counter(name for name, _ in messages if name in known)
    surplus = {
        name: max(0, count - args.keep_periodic)
        for name, count in stock.items()
        if name in PERIODIC_TASKS
    }

    # Keep the newest `keep_periodic` of each periodic task; walk backwards so
    # the countdown matches the tail of the queue.
    keep_newest = dict(surplus)
    kept_reversed: list[str] = []
    for name, text in reversed(messages):
        if name in unknown:
            continue
        if keep_newest.get(name, 0) > 0:
            keep_newest[name] -= 1
            continue
        kept_reversed.append(text)

    for name, count in surplus.items():
        dropped[name] += count
    kept = list(reversed(kept_reversed))

    print(f"Queue '{args.queue}': {total} message(s) inspected")
    for name, count in sorted(dropped.items(), key=lambda kv: -kv[1]):
        print(f"  drop {count:>6}  {name}")
    print(f"  keep {len(kept):>6}  message(s)")

    if not args.apply:
        for name, text in messages:
            client.rpush(args.queue, text)
        print("\nDry run, queue restored. Re-run with --apply to drop the stale messages.")
        return 0

    if kept:
        client.rpush(args.queue, *kept)
    print(f"\nDropped {sum(dropped.values())} stale message(s), kept {len(kept)}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
