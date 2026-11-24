"""GUI editors (Cursor, Windsurf) relaunched inside the sandbox on Linux (D10, KI-534). An Electron
editor's own Chromium sandbox makes a user namespace of its own; on Ubuntu 24.04 that is refused
inside ours (AppArmor), so the editor runs with ITS sandbox off (``--no-sandbox``): Blackbox's
sandbox then covers the whole editor, but its web pages lose Chromium's extra isolation — the page
says so before the person chooses it. On X11 an editor needs the display, and any X11 client can
read and drive every window (F11: allowed, with the warning; Wayland is recommended).

Usage::

    open_app("cursor", profile)     # "Cursor is running inside Blackbox's sandbox."
"""

from __future__ import annotations

import os
import subprocess
import time
from typing import Optional

from .profile import SANDBOX

PGREP = "/usr/bin/pgrep"
TIMEOUT_SECONDS = 5.0
#: GUI agents Blackbox can relaunch inside the sandbox (D10): id -> (name, program). The paths the
#: editors' .deb / .rpm packages install.
APPS = {"cursor": ("Cursor", "/usr/share/cursor/cursor"), "windsurf": ("Windsurf", "/usr/share/windsurf/windsurf")}
ELECTRON_FLAGS = ("--no-sandbox",)
STARTED_SECONDS = 4.0
STARTED_POLL_SECONDS = 0.2


def _running(executable: str) -> bool:
    try:
        done = subprocess.run([PGREP, "-f", executable], capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.SubprocessError):
        return True   # cannot tell: refuse (a running copy would take the launch outside the sandbox)
    return done.returncode == 0


def open_app(app: str, profile: str, apps: Optional[dict[str, tuple[str, str]]] = None, log: Optional[str] = None,
             started_seconds: float = STARTED_SECONDS, sandbox: str = SANDBOX) -> str:
    """Starts the GUI agent *app* inside the policy *profile* and answers what happened, for a
    person — only once it is still running :data:`STARTED_SECONDS` later. Refused while it already
    runs (an editor hands a second launch to the copy already running — outside the sandbox).
    *apps*, *log* and *sandbox* are for tests."""
    apps = APPS if apps is None else apps
    if app not in apps:
        raise ValueError(f"unknown app {app!r}")
    name, executable = apps[app]
    if not os.access(executable, os.X_OK):
        raise LookupError(f"{name} is not installed at {executable}.")
    if _running(executable):
        raise RuntimeError(f"Quit {name} first: a copy already running would open outside the sandbox.")
    output = open(log or os.devnull, "ab")   # windows-footgun: ok (binary log)
    try:
        process = subprocess.Popen([sandbox, "run", "--policy", profile, "--", executable, *ELECTRON_FLAGS],
                                   stdin=subprocess.DEVNULL, stdout=output, stderr=output, start_new_session=True,
                                   env={**os.environ, "BLACKBOX_AGENT_SANDBOX": "1"})
    finally:
        output.close()
    deadline = time.monotonic() + started_seconds
    while time.monotonic() < deadline:
        code = process.poll()
        if code is not None:
            raise RuntimeError(f"{name} stopped right after starting inside the sandbox (exit {code}), so it is not "
                               "running. Open it normally if you need it now; its use stays covered by Blackbox's hooks.")
        time.sleep(STARTED_POLL_SECONDS)
    return f"{name} is running inside Blackbox's sandbox."


__all__ = ["APPS", "ELECTRON_FLAGS", "PGREP", "STARTED_POLL_SECONDS", "STARTED_SECONDS", "open_app"]
