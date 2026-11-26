"""GUI editors (Cursor, Windsurf) relaunched inside the profile (D10, KI-534; see the package doc).

Usage::

    open_app("cursor", profile)     # "Cursor is running inside Blackbox's sandbox."
"""

from __future__ import annotations

import os
import plistlib
import subprocess
import time
from typing import Optional

from .profile import SANDBOX_EXEC
from .tools import TIMEOUT_SECONDS

PGREP = "/usr/bin/pgrep"
#: GUI agents Blackbox can relaunch inside the sandbox (D10): id -> (name, app bundle).
APPS = {"cursor": ("Cursor", "/Applications/Cursor.app"), "windsurf": ("Windsurf", "/Applications/Windsurf.app")}
#: An Electron/Chromium editor's own sandbox can not start inside Blackbox's (see the module doc).
ELECTRON_FLAGS = ("--no-sandbox",)
#: How long an editor started inside the sandbox must stay up before it is called running.
STARTED_SECONDS = 4.0
STARTED_POLL_SECONDS = 0.2


def _executable(bundle: str) -> Optional[str]:
    try:
        with open(os.path.join(bundle, "Contents", "Info.plist"), "rb") as handle:   # windows-footgun: ok (binary plist)
            name = plistlib.load(handle).get("CFBundleExecutable")
    except (OSError, ValueError):
        return None
    path = os.path.join(bundle, "Contents", "MacOS", str(name or ""))
    return path if name and os.access(path, os.X_OK) else None


def _running(executable: str) -> bool:
    try:
        done = subprocess.run([PGREP, "-f", executable], capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.SubprocessError):
        return True   # cannot tell: refuse (a running copy would take the launch outside the sandbox)
    return done.returncode == 0


def open_app(app: str, profile: str, apps: Optional[dict[str, tuple[str, str]]] = None, log: Optional[str] = None,
             started_seconds: float = STARTED_SECONDS) -> str:
    """Starts the GUI agent *app* (``cursor`` / ``windsurf``) inside the profile and answers what
    happened, for a person — only once it is still running :data:`STARTED_SECONDS` later (KI-534:
    "is starting" was said for an editor that had already died). Refused while it already runs: an
    editor hands a second launch to the copy already running — outside the sandbox. *apps* and
    *log* (where its output goes) are for tests."""
    apps = APPS if apps is None else apps
    if app not in apps:
        raise ValueError(f"unknown app {app!r}")
    name, bundle = apps[app]
    executable = _executable(bundle)
    if executable is None:
        raise LookupError(f"{name} is not installed in {os.path.dirname(bundle)}.")
    if _running(executable):
        raise RuntimeError(f"Quit {name} first: a copy already running would open outside the sandbox.")
    output = open(log or os.devnull, "ab")   # windows-footgun: ok (binary log)
    try:
        process = subprocess.Popen([SANDBOX_EXEC, "-f", profile, executable, *ELECTRON_FLAGS], stdin=subprocess.DEVNULL,
                                   stdout=output, stderr=output, start_new_session=True,
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
