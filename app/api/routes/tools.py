"""Desktop tool launcher: open a terminal (MobaXterm on Windows).

Security model — this endpoint launches a desktop application, so it is built
to be unusable as a command-injection primitive:

  * The list of candidate applications is a hardcoded constant. The client can
    never supply a path, executable name, or argument.
  * ``open`` accepts only an ``index`` into the freshly re-detected allowlist,
    and the server re-verifies the executable still exists before launching.
  * Execution always uses an argument list with ``shell=False`` (or
    ``os.startfile`` on Windows), so nothing is ever interpreted by a shell.
  * Detection (GET) requires a signed-in user; launching (POST) requires admin.

On Windows the star of the show is MobaXterm when it is installed; otherwise we
hand back the official download page. On Linux/macOS we surface the local
terminal emulators instead, since MobaXterm does not exist there.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from app.api.deps import get_current_user, require_admin
from app.models.user import User

router = APIRouter()

MOBAXTERM_DOWNLOAD_URL = "https://mobaxterm.mobatek.net/download-home-edition.html"
WIRESHARK_DOWNLOAD_URL = "https://www.wireshark.org/download.html"

# Windows: common install locations, checked in order. The filename is a
# constant; only the well-known install directories vary.
WINDOWS_TERMINALS: List[Dict[str, str]] = [
    {
        "name": "MobaXterm",
        "filename": "MobaXterm.exe",
        "dirs_env": "ProgramFiles(x86)",
        "subpath": os.path.join("Mobatek", "MobaXterm"),
    },
    {
        "name": "MobaXterm",
        "filename": "MobaXterm.exe",
        "dirs_env": "ProgramFiles",
        "subpath": os.path.join("Mobatek", "MobaXterm"),
    },
    {
        "name": "MobaXterm (portable)",
        "filename": "MobaXterm.exe",
        "dirs_env": "LOCALAPPDATA",
        "subpath": os.path.join("Programs", "MobaXterm"),
    },
]

# POSIX: terminal emulators in preference order. Each entry is a fixed argv
# prefix — never assembled from user input.
POSIX_TERMINALS: List[Dict[str, Any]] = [
    {"name": "x-terminal-emulator", "argv": ["x-terminal-emulator"]},
    {"name": "GNOME Terminal", "argv": ["gnome-terminal"]},
    {"name": "Konsole", "argv": ["konsole"]},
    {"name": "XFCE Terminal", "argv": ["xfce4-terminal"]},
    {"name": "Kitty", "argv": ["kitty"]},
    {"name": "Alacritty", "argv": ["alacritty"]},
    {"name": "Tilix", "argv": ["tilix"]},
    {"name": "xterm", "argv": ["xterm"]},
]


def _windows_candidates() -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    seen_paths: set[str] = set()

    # PATH lookup first, then the known install directories.
    on_path = shutil.which("MobaXterm")
    if on_path:
        found.append({"name": "MobaXterm", "path": on_path})
        seen_paths.add(os.path.normcase(on_path))

    for spec in WINDOWS_TERMINALS:
        root = os.environ.get(spec["dirs_env"])
        if not root:
            continue
        candidate = os.path.join(root, spec["subpath"], spec["filename"])
        key = os.path.normcase(candidate)
        if key in seen_paths:
            continue
        if os.path.isfile(candidate):
            found.append({"name": spec["name"], "path": candidate})
            seen_paths.add(key)
    return found


def _posix_candidates() -> List[Dict[str, Any]]:
    found: List[Dict[str, Any]] = []
    for spec in POSIX_TERMINALS:
        resolved = shutil.which(spec["argv"][0])
        if resolved:
            found.append({"name": spec["name"], "path": resolved, "argv": spec["argv"]})
    return found


WIRESHARK_WINDOWS_DIRS: List[str] = ["ProgramFiles", "ProgramFiles(x86)"]


def _wireshark_candidates() -> List[Dict[str, Any]]:
    """Locate the Wireshark GUI using a fixed filename and known directories."""
    found: List[Dict[str, Any]] = []
    seen: set[str] = set()

    on_path = shutil.which("wireshark")
    if on_path:
        found.append({"name": "Wireshark", "path": on_path})
        seen.add(os.path.normcase(on_path))

    if sys.platform.startswith("win"):
        for env_name in WIRESHARK_WINDOWS_DIRS:
            root = os.environ.get(env_name)
            if not root:
                continue
            candidate = os.path.join(root, "Wireshark", "Wireshark.exe")
            key = os.path.normcase(candidate)
            if key in seen:
                continue
            if os.path.isfile(candidate):
                found.append({"name": "Wireshark", "path": candidate})
                seen.add(key)
    else:
        for candidate in (
            "/usr/bin/wireshark",
            "/usr/local/bin/wireshark",
            "/Applications/Wireshark.app/Contents/MacOS/Wireshark",
        ):
            if os.path.isfile(candidate):
                found.append({"name": "Wireshark", "path": candidate})

    return found


def _detect_wireshark() -> Dict[str, Any]:
    platform = (
        "windows" if sys.platform.startswith("win")
        else "linux" if sys.platform.startswith("linux")
        else "darwin" if sys.platform.startswith("darwin")
        else "other"
    )
    options = _wireshark_candidates()
    return {
        "platform": platform,
        "kind": "wireshark" if options else "wireshark-missing",
        "available": bool(options),
        "options": [{"index": i, "name": opt["name"]} for i, opt in enumerate(options)],
        "download_url": None if options else WIRESHARK_DOWNLOAD_URL,
        "note": None if options else (
            "Wireshark is not installed — download it from the link, install, "
            "and this button will launch it automatically."
        ),
    }


@router.get("/wireshark", response_model=Dict[str, Any])
async def detect_wireshark(_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Report whether Wireshark can be launched on this machine."""
    return _detect_wireshark()


class OpenWiresharkRequest(BaseModel):
    index: int = Field(0, ge=0, le=32)


@router.post("/wireshark/open", response_model=Dict[str, Any])
async def open_wireshark(
    request: OpenWiresharkRequest,
    _user: User = Depends(require_admin),
) -> Dict[str, Any]:
    """Launch Wireshark, mirroring the MobaXterm launcher's safety model."""
    detection = _detect_wireshark()
    if not detection["available"]:
        raise HTTPException(
            status_code=404,
            detail=detection["note"] or "Wireshark is not installed.",
        )

    candidates = _wireshark_candidates()
    if request.index >= len(candidates):
        raise HTTPException(status_code=404, detail="Wireshark is no longer available.")

    chosen = candidates[request.index]
    try:
        if detection["platform"] == "windows":
            os.startfile(chosen["path"])  # noqa: S606 — fixed, existence-checked path
        else:
            subprocess.Popen(  # noqa: S603 — fixed argv, shell=False
                [chosen["path"]],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
                env=os.environ.copy(),
            )
    except PermissionError as exc:
        raise HTTPException(
            status_code=503,
            detail="Launch was denied by the OS — try running with the required privileges.",
        ) from exc
    except OSError as exc:
        raise HTTPException(status_code=503, detail=f"Could not launch Wireshark: {exc}") from exc

    return {"status": "opened", "name": chosen["name"], "platform": detection["platform"]}


def _detect() -> Dict[str, Any]:
    platform = (
        "windows" if sys.platform.startswith("win")
        else "linux" if sys.platform.startswith("linux")
        else "darwin" if sys.platform.startswith("darwin")
        else "other"
    )
    if platform == "windows":
        options = _windows_candidates()
        download_url = MOBAXTERM_DOWNLOAD_URL if not options else None
        kind = "mobaxterm" if options else "mobaxterm-missing"
    else:
        options = _posix_candidates()
        download_url = None
        kind = "terminal" if options else "terminal-missing"

    return {
        "platform": platform,
        "kind": kind,
        "available": bool(options),
        "options": [
            {"index": i, "name": opt["name"]} for i, opt in enumerate(options)
        ],
        "download_url": download_url,
        "note": (
            None if options
            else (
                "MobaXterm is not installed — grab it from the link, install, "
                "and it will show up here automatically."
                if platform == "windows"
                else "No terminal emulator found on PATH. Install one (e.g. "
                "`sudo apt install gnome-terminal`) and it will show up here."
            )
        ),
    }


class OpenTerminalRequest(BaseModel):
    index: int = Field(0, ge=0, le=32)


@router.get("/terminal", response_model=Dict[str, Any])
async def detect_terminal(_user: User = Depends(get_current_user)) -> Dict[str, Any]:
    """Report which terminal we can offer on this machine."""
    return _detect()


@router.post("/terminal/open", response_model=Dict[str, Any])
async def open_terminal(
    request: OpenTerminalRequest,
    _user: User = Depends(require_admin),
) -> Dict[str, Any]:
    """Launch the allowlisted terminal at ``index`` of the current detection."""
    detection = _detect()
    if not detection["available"]:
        raise HTTPException(
            status_code=404,
            detail=detection["note"] or "No terminal emulator is available.",
        )

    # Re-resolve the executable from a fresh scan instead of trusting anything
    # the client could have stashed.
    if detection["platform"] == "windows":
        candidates = _windows_candidates()
    else:
        candidates = _posix_candidates()

    if request.index >= len(candidates):
        raise HTTPException(status_code=404, detail="That terminal is no longer available.")

    chosen = candidates[request.index]

    try:
        if detection["platform"] == "windows":
            os.startfile(chosen["path"])  # noqa: S606 — fixed, existence-checked path
        else:
            argv = list(chosen.get("argv") or [chosen["path"]])
            subprocess.Popen(  # noqa: S603 — fixed argv, shell=False
                argv,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                stdin=subprocess.DEVNULL,
                start_new_session=True,
                env=os.environ.copy(),
            )
    except PermissionError as exc:
        raise HTTPException(
            status_code=503,
            detail="Launch was denied by the OS — try running with the required privileges.",
        ) from exc
    except OSError as exc:
        raise HTTPException(status_code=503, detail=f"Could not launch terminal: {exc}") from exc

    return {"status": "opened", "name": chosen["name"], "platform": detection["platform"]}
