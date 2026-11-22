"""Linux: the desktop's own notifier through ``notify-send`` (libnotify), when it is installed.

No program of Blackbox's own is needed: ``notify-send --app-name Blackbox`` names the sender.
On a machine without a desktop session (a server) nothing can be shown and ``status`` says so.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from ..model import NotifierStatus

TIMEOUT_SECONDS = 5.0
_URGENCY = {"critical": "critical", "warning": "normal", "info": "low"}


def _tool() -> str:
    return shutil.which("notify-send") or ""


def status() -> NotifierStatus:
    if not _tool():
        return NotifierStatus("none", False, "unknown", "notify-send is not installed; the dashboard shows every notification.")
    if not (os.environ.get("DBUS_SESSION_BUS_ADDRESS") or os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        return NotifierStatus("fallback", False, "unknown", "This session has no desktop to show a notification on.")
    return NotifierStatus("fallback", True, "authorized", "Notifications are shown by this desktop's own notifier.")


def send(title: str, body: str, level: str, ident: str) -> bool:
    tool = _tool()
    if not tool or not status().available:
        return False
    try:
        done = subprocess.run([tool, "--app-name", "Blackbox", "--urgency", _URGENCY.get(level, "normal"), "--", title[:200], body[:600]],
                              capture_output=True, timeout=TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return done.returncode == 0


def install(source: Optional[Path] = None, sha256: str = "") -> NotifierStatus:
    return status()   # nothing of Blackbox's own to install


def remove() -> None:
    return None
