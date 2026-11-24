"""Opening a web link or a file in an app FOR a sandboxed agent, outside the sandbox (sandbox
permissions ``open-links`` / ``open-apps``), run by Blackbox's broker: ``xdg-open <url>`` and
``gio launch <app.desktop> <files>`` with a fixed argv and a clean environment that keeps only
what reaches the person's desktop session. Inside the sandbox the session bus is hidden, so only
the broker's checked requests reach the desktop.

Apps are desktop entries (``<data dir>/applications/<id>.desktop``, the XDG data folders). Never
opened: an entry that runs commands or drives other apps — a terminal (``Terminal=true``, the
``TerminalEmulator`` category, or a known terminal's name: :data:`APP_DRIVER_APPS`).

A machine with no desktop session (a server over ssh) has nothing to open with: the broker answers
that the person opens it themselves.

Usage::

    find_app("org.gnome.Evince")                  # "/usr/share/applications/org.gnome.Evince.desktop"
    open_url("https://github.com/login/device")
    open_with("/usr/share/applications/org.gnome.Evince.desktop", ["/home/me/shop/a.pdf"])
"""

from __future__ import annotations

import os
import shutil
import subprocess
from typing import Sequence

TIMEOUT_SECONDS = 10
MAX_ENTRY_BYTES = 64 * 1024
#: The desktop session's variables the opener needs (nothing else of the dashboard's environment).
SESSION_VARIABLES = ("DISPLAY", "WAYLAND_DISPLAY", "XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS", "XDG_DATA_DIRS",
                     "XDG_CURRENT_DESKTOP", "XDG_SESSION_TYPE")
NO_DESKTOP = "this machine has no desktop session for Blackbox to open it in; open it yourself"
#: Apps that run commands or drive other apps: opening one hands the agent a way out of the sandbox.
APP_DRIVER_APPS = frozenset({"gnome-terminal", "org.gnome.terminal", "org.gnome.console", "org.gnome.ptyxis", "konsole",
                             "org.kde.konsole", "xterm", "uxterm", "kitty", "alacritty", "wezterm", "org.wezfurlong.wezterm",
                             "ghostty", "com.mitchellh.ghostty", "tilix", "com.gexperts.tilix", "terminator", "xfce4-terminal",
                             "foot", "guake", "yakuake", "warp", "dev.warp.warp", "tabby", "hyper", "lxterminal",
                             "mate-terminal", "qterminal", "st", "urxvt", "rxvt-unicode", "cool-retro-term", "blackbox",
                             "com.raggesilver.blackbox", "org.gnome.settings", "gnome-control-center", "systemsettings",
                             "org.kde.systemsettings"})


def data_dirs(home: str = "") -> list[str]:
    """The XDG data folders, the person's own first."""
    home = home or os.path.expanduser("~")
    own = os.environ.get("XDG_DATA_HOME") or os.path.join(home, ".local", "share")
    shared = (os.environ.get("XDG_DATA_DIRS") or "/usr/local/share:/usr/share").split(":")
    return list(dict.fromkeys([own, *[folder for folder in shared if folder.startswith("/")],
                               "/var/lib/flatpak/exports/share", os.path.join(home, ".local/share/flatpak/exports/share")]))


def _entry(path: str) -> dict[str, str]:
    """The ``[Desktop Entry]`` keys of a desktop file (the first group only)."""
    try:
        with open(path, encoding="utf-8-sig", errors="replace") as handle:
            text = handle.read(MAX_ENTRY_BYTES)
    except OSError:
        return {}
    keys: dict[str, str] = {}
    group = ""
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("["):
            if group:
                break
            group = line
        elif group == "[Desktop Entry]" and "=" in line:
            key, value = line.split("=", 1)
            keys.setdefault(key.strip(), value.strip())
    return keys


def find_app(name: str, folders: Sequence[str] = ()) -> str:
    """The desktop entry for *name* — its id (``org.gnome.Evince``, with or without ``.desktop``) or
    its shown name (``Document Viewer``, case ignored) —, "" when none or when it is an app driver."""
    wanted = os.path.basename(name.strip()).removesuffix(".desktop")
    if not wanted or wanted.lower() in APP_DRIVER_APPS:
        return ""
    candidates = []
    for folder in folders or data_dirs():
        apps = os.path.join(folder, "applications")
        path = os.path.join(apps, wanted + ".desktop")
        if os.path.isfile(path):
            return "" if is_driver(path) else os.path.realpath(path)
        if os.path.isdir(apps):
            candidates += [os.path.join(apps, entry) for entry in sorted(os.listdir(apps)) if entry.endswith(".desktop")]
    for path in candidates:
        if _entry(path).get("Name", "").lower() == wanted.lower():
            return "" if is_driver(path) else os.path.realpath(path)
    return ""


def is_driver(app_path: str) -> bool:
    """True for a terminal or another app that runs commands (see the module doc)."""
    entry = _entry(app_path)
    stem = os.path.basename(app_path).removesuffix(".desktop").lower()
    program = os.path.basename(entry.get("Exec", "").split(" ", 1)[0]).lower()
    categories = entry.get("Categories", "").split(";")
    return (entry.get("Terminal", "").lower() == "true" or "TerminalEmulator" in categories or stem in APP_DRIVER_APPS
            or program in APP_DRIVER_APPS)


def _environment() -> dict[str, str]:
    env = {"HOME": os.path.expanduser("~"), "USER": os.environ.get("USER", ""), "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8"}
    env.update({name: os.environ[name] for name in SESSION_VARIABLES if os.environ.get(name)})
    if not (env.get("DISPLAY") or env.get("WAYLAND_DISPLAY")):
        raise OSError(NO_DESKTOP)
    return env


def _run(argv: list[str]) -> int:
    env = _environment()
    if not shutil.which(argv[0], path=env["PATH"]):
        raise OSError(f"{argv[0]} is not installed here")
    done = subprocess.run(argv, stdin=subprocess.DEVNULL, capture_output=True, env=env, timeout=TIMEOUT_SECONDS, check=False)
    return done.returncode


def open_url(url: str) -> int:
    """Opens *url* (checked by the caller: http / https) in the person's browser; the exit code."""
    return _run(["xdg-open", url])


def open_with(app_path: str, files: Sequence[str]) -> int:
    """Opens *files* (checked by the caller) with the desktop entry at *app_path*; the exit code."""
    return _run(["gio", "launch", app_path, *files])


__all__ = ["APP_DRIVER_APPS", "NO_DESKTOP", "SESSION_VARIABLES", "data_dirs", "find_app", "is_driver", "open_url", "open_with"]
