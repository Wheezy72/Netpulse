#!/usr/bin/env python3
"""Remove NetPulse from this machine.

The installers (``setup_linux.sh``, ``setup_macos.sh``,
``windows_setup.bat``) between them create a virtualenv, a built frontend,
package trees, logs, runtime state and a PostgreSQL database. Undoing that by
hand means knowing which of those exist and which of them hold your data, so
this script enumerates exactly what it will touch and then does it.

Two levels, because they are not the same decision:

* default  -- generated artefacts (``.venv``, ``node_modules``, ``dist``,
  caches, logs, runtime data, Docker containers). Your inventory lives in
  PostgreSQL and is untouched.
* ``--purge`` -- also remove ``.env`` and destroy the database: Docker volumes
  with ``docker compose down -v``, and for a bare-metal install it prints the
  one ``DROP DATABASE`` statement it will not run for you.

Nothing outside this checkout is modified. Use ``--dry-run`` first.

    python scripts/uninstall.py --dry-run
    python scripts/uninstall.py            # confirm interactively
    python scripts/uninstall.py --yes      # no prompt (CI, scripted teardown)
    python scripts/uninstall.py --yes --purge
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Generated directories, safe to delete: they are rebuilt by setup.
ARTEFACTS = (
    ".venv",
    "venv",
    "frontend/node_modules",
    "frontend/dist",
    ".pytest_cache",
    ".ruff_cache",
    ".mypy_cache",
    "logs",
    "data",
    "scripts/temp",
)

# Generated files.
FILES = (".env",)


def _is_checkout() -> bool:
    """Refuse to act on something that is not a NetPulse checkout.

    The script deletes trees; running it from a copied folder or a system
    directory because someone typed the wrong path is not recoverable.
    """
    return (ROOT / "pyproject.toml").is_file() and (ROOT / "app" / "main.py").is_file()


def _size(path: Path) -> int:
    if path.is_file():
        return path.stat().st_size
    total = 0
    for base, _dirs, files in os.walk(path):
        for name in files:
            try:
                total += (Path(base) / name).stat().st_size
            except OSError:
                pass
    return total


def _human(count: int) -> str:
    value = float(count)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} GB"


def _pycache_dirs() -> list[Path]:
    return sorted(ROOT.rglob("__pycache__"))


def _docker_running() -> bool:
    try:
        result = subprocess.run(
            ["docker", "compose", "ps", "--quiet"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return False
    return bool(result.stdout.strip())


def _docker_compose(*args: str) -> int:
    try:
        result = subprocess.run(
            ["docker", "compose", *args],
            cwd=ROOT,
            text=True,
            timeout=180,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        print(f"    docker compose {args[0]} failed: {exc}")
        return 1
    return result.returncode


def main() -> int:
    parser = argparse.ArgumentParser(description="Remove NetPulse from this machine.")
    parser.add_argument("--yes", action="store_true", help="do not ask for confirmation")
    parser.add_argument(
        "--purge",
        action="store_true",
        help="also delete .env and destroy the database (inventory included)",
    )
    parser.add_argument(
        "--keep-docker", action="store_true", help="leave Docker containers and volumes alone"
    )
    parser.add_argument("--dry-run", action="store_true", help="list what would be removed")
    args = parser.parse_args()

    if not _is_checkout():
        print(f"Refusing to run: {ROOT} is not a NetPulse checkout.", file=sys.stderr)
        print("Run this from the repository you want to remove.", file=sys.stderr)
        return 2

    targets: list[Path] = []
    for relative in ARTEFACTS:
        path = ROOT / relative
        if path.exists():
            targets.append(path)
    if args.purge:
        for relative in FILES:
            path = ROOT / relative
            if path.exists():
                targets.append(path)
    caches = _pycache_dirs()

    total = sum(_size(path) for path in targets) + sum(_size(path) for path in caches)

    print(f"NetPulse uninstall - {ROOT}")
    print(f"Mode: {'purge (data destroyed)' if args.purge else 'artefacts only (data kept)'}")
    print()
    if targets:
        print("Will remove:")
        for path in targets:
            print(f"  {path.relative_to(ROOT)}{os.sep}  ({_human(_size(path))})")
    else:
        print("No generated directories or files found.")
    if caches:
        print(f"Will remove: {len(caches)} __pycache__ director{'y' if len(caches) == 1 else 'ies'}")
    if not args.keep_docker:
        print("Will stop the Compose stack" + (" and delete its volumes" if args.purge else ""))
    print(f"Total reclaimed: {_human(total)}")
    print()

    if args.dry_run:
        print("Dry run - nothing was changed.")
        return 0

    if not args.yes:
        warning = " This DESTROYS the database." if args.purge else " Your inventory is kept."
        answer = input(f"Continue?{warning} [y/N] ").strip().lower()
        if answer not in {"y", "yes"}:
            print("Cancelled.")
            return 1

    if not args.keep_docker and _docker_running():
        print("Stopping the Compose stack...")
        _docker_compose("down", "-v" if args.purge else "--remove-orphans")

    for path in targets:
        try:
            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
        except OSError as exc:
            print(f"  could not remove {path}: {exc}")
        else:
            print(f"  removed {path.relative_to(ROOT)}")

    for path in caches:
        try:
            shutil.rmtree(path)
        except OSError:
            pass
    print(f"  removed {len(caches)} __pycache__ directories")

    print()
    print("NetPulse removed from this checkout.")
    if not args.purge:
        print("The PostgreSQL database and your inventory were left untouched.")
        print("Re-run with --purge to destroy those as well.")
    else:
        print("Docker volumes were removed with the stack.")
        print("For a bare-metal PostgreSQL install, drop the database yourself:")
        print("  psql -U postgres -c 'DROP DATABASE netpulse;'")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
