"""Linux: the desktop's own notifier through ``notify-send`` (libnotify), when it is installed.

No program of Blackbox's own is needed: ``notify-send --app-name Blackbox`` names the sender.
On a machine without a desktop session (a server) nothing can be shown and ``status`` says so:
"available" means a notification server owns ``org.freedesktop.Notifications`` on the person's
session bus NOW (asked through ``busctl`` or ``gdbus``). KI-662 (Linux round L1): with notify-send
installed on a server, the status said "shown by this desktop's own notifier" because a session
bus exists there too (systemd's user manager), while every send was "not shown".
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from ..model import Delivery, NotifierStatus

TIMEOUT_SECONDS = 5.0
_URGENCY = {"critical": "critical", "warning": "normal", "info": "low"}


def _tool() -> str:
    return shutil.which("notify-send") or ""


#: The bus name a desktop's notification server owns.
SERVER_NAME = "org.freedesktop.Notifications"
_ASK_OWNER = {"busctl": ["--user", "call", "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "NameHasOwner", "s", SERVER_NAME],
              "gdbus": ["call", "--session", "--dest", "org.freedesktop.DBus", "--object-path", "/org/freedesktop/DBus",
                        "--method", "org.freedesktop.DBus.NameHasOwner", SERVER_NAME]}


def server_running() -> Optional[bool]:
    """Whether a notification server runs on the person's session bus now; None when it can not be asked."""
    for program, args in _ASK_OWNER.items():
        found = shutil.which(program)
        if not found:
            continue
        try:
            done = subprocess.run([found, *args], capture_output=True, text=True, timeout=TIMEOUT_SECONDS, check=False)
        except (OSError, subprocess.SubprocessError):
            continue
        if done.returncode == 0:
            return "true" in done.stdout.lower()
    return None


def status() -> NotifierStatus:
    if not _tool():
        return NotifierStatus("none", False, "unknown", "notify-send is not installed; the dashboard shows every notification.")
    if not os.environ.get("DBUS_SESSION_BUS_ADDRESS") and not os.path.exists(f"/run/user/{os.getuid()}/bus"):
        return NotifierStatus("fallback", False, "unknown", "This session has no desktop to show a notification on.")
    running = server_running()
    if running is None:
        return NotifierStatus("fallback", False, "unknown", "Blackbox can not tell whether a desktop shows notifications here; the dashboard shows every one.")
    if not running:
        return NotifierStatus("fallback", False, "unknown", "No desktop notifier runs here (a server); the dashboard shows every notification.")
    return NotifierStatus("fallback", True, "authorized", "Notifications are shown by this desktop's own notifier.")


def send(title: str, body: str, level: str, ident: str) -> Delivery:
    tool = _tool()
    current = status()
    if not tool or not current.available:
        return Delivery("not-shown", current.detail)
    try:
        done = subprocess.run([tool, "--app-name", "Blackbox", "--urgency", _URGENCY.get(level, "normal"), "--", title[:200], body[:600]],
                              capture_output=True, timeout=TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.SubprocessError):
        return Delivery("not-shown", "notify-send could not be run.")
    if done.returncode != 0:
        return Delivery("not-shown", "The desktop's notifier did not take it.")
    return Delivery("delivered", "Handed to this desktop's notifier.")


def request() -> NotifierStatus:
    return status()   # the desktop's notifier asks nothing


def open_settings() -> bool:
    return False   # no one place for notification settings across Linux desktops


def install(source: Optional[Path] = None, sha256: str = "") -> NotifierStatus:
    return status()   # nothing of Blackbox's own to install


def remove() -> None:
    return None
