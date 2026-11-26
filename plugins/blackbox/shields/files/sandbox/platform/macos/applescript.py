"""Running one AppleScript FOR a sandboxed agent, outside the sandbox (sandbox permission
``applescript``: block, or ask each time — never allowed without asking, F5). ``osascript`` stays
refused inside (``APP_DRIVERS`` in the never-list): the script drives other apps, which act
outside the sandbox — a full escape for that run, so the person reads the whole script first.

Usage::

    run_script('tell application "Music" to pause')   # (exit code, output)
"""

from __future__ import annotations

import os
import subprocess

OSASCRIPT = "/usr/bin/osascript"
TIMEOUT_SECONDS = 60
MAX_OUTPUT_CHARS = 64 * 1024


def run_script(script: str) -> tuple[int, str]:
    """Runs *script* (AppleScript text, read by the caller) with a clean environment; ``(exit code, output)``."""
    env = {"HOME": os.path.expanduser("~"), "USER": os.environ.get("USER", ""), "PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"}
    try:
        done = subprocess.run([OSASCRIPT, "-l", "AppleScript", "-"], input=script, capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=TIMEOUT_SECONDS, check=False)
    except subprocess.TimeoutExpired:
        return 124, "the script ran too long and was stopped"
    return done.returncode, (done.stdout + done.stderr)[:MAX_OUTPUT_CHARS]


__all__ = ["OSASCRIPT", "run_script"]
