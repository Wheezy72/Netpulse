"""Filesystem anchors for the backend.

Every path the API writes to is derived from the checkout root instead of the
current working directory. A relative ``data/scans`` resolves against whatever
directory the process happened to start in, so ``uvicorn`` launched from
``/etc`` (a systemd unit, a Windows shortcut, an IDE run configuration) would
create its artifacts somewhere unexpected and then fail to find them again.

``PROJECT_ROOT`` is two levels above ``app/core``: the directory that holds
``app/``, ``frontend/`` and ``data/``. In the container the layout is identical
(``/app/app/core/paths.py`` -> ``/app``), so this needs no container special
case, and it uses forward-slash-free ``pathlib`` joins so it is identical on
Windows, Linux and macOS.
"""

from __future__ import annotations

from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data"
SCANS_DIR = DATA_DIR / "scans"
BACKUP_DIR = DATA_DIR / "backups"
LOGS_DIR = PROJECT_ROOT / "logs"


def ensure_dir(path: Path) -> Path:
    """Create *path* (and parents) if needed and hand it back."""
    path.mkdir(parents=True, exist_ok=True)
    return path
