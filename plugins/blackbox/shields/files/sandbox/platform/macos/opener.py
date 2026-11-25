"""Opening a web link or a file in an app FOR a sandboxed agent, outside the sandbox (sandbox
permissions ``open-links`` / ``open-apps``): ``/usr/bin/open`` with a fixed argv and a clean
environment, run by Blackbox's broker. Inside the sandbox LaunchServices stays refused
(``(deny lsopen)``): an agent that opened ``Terminal`` with a ``.command`` file would run it
outside, so only the broker's checked requests reach ``open``.

Never opened: an app that drives other apps or runs commands (:data:`APP_DRIVER_APPS`).

Usage::

    find_app("Preview")                      # "/System/Applications/Preview.app"
    open_url("https://github.com/login/device")
    open_with("/System/Applications/Preview.app", ["/Users/me/shop/a.pdf"])
"""

from __future__ import annotations

import os
import subprocess
from typing import Sequence

OPEN = "/usr/bin/open"
TIMEOUT_SECONDS = 10
#: Where an installed app is looked for.
APP_FOLDERS = ("/Applications", "/System/Applications", "/System/Applications/Utilities", "{home}/Applications")
#: Apps that run commands or drive other apps: opening one hands the agent a way out of the sandbox.
APP_DRIVER_APPS = frozenset({"terminal", "iterm", "iterm2", "script editor", "automator", "shortcuts", "warp", "alacritty",
                             "kitty", "wezterm", "ghostty", "hyper", "tabby", "console", "system settings",
                             "system preferences", "automator application stub"})


def find_app(name: str) -> str:
    """The installed ``.app`` named *name* (case as on disk; ``Preview`` or ``Preview.app``), "" when none."""
    base = os.path.basename(name.strip())
    base = base[:-4] if base.lower().endswith(".app") else base
    if not base or base.lower() in APP_DRIVER_APPS:
        return ""
    home = os.path.expanduser("~")
    for folder in APP_FOLDERS:
        path = os.path.join(folder.replace("{home}", home), base + ".app")
        if os.path.isdir(path):
            return os.path.realpath(path)
    return ""


def is_driver(app_path: str) -> bool:
    return os.path.basename(app_path)[:-4].lower() in APP_DRIVER_APPS


def _environment() -> dict[str, str]:
    return {"HOME": os.path.expanduser("~"), "USER": os.environ.get("USER", ""), "PATH": "/usr/bin:/bin", "LANG": "en_US.UTF-8"}


def _run(argv: list[str]) -> int:
    done = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, env=_environment(), timeout=TIMEOUT_SECONDS,
                          check=False)
    return done.returncode


def open_url(url: str) -> int:
    """Opens *url* (checked by the caller: http / https) in the person's browser; the exit code."""
    return _run([OPEN, "--", url])


def open_with(app_path: str, files: Sequence[str]) -> int:
    """Opens *files* (checked by the caller) with the app at *app_path*; the exit code."""
    return _run([OPEN, "-a", app_path, "--", *files])


__all__ = ["APP_DRIVER_APPS", "OPEN", "find_app", "is_driver", "open_url", "open_with"]
