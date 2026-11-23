"""An operating system without an agent sandbox yet: nothing is sandboxed, and the shield says so.

The ports, with the same functions (proposal §03):

* Linux (``linux.py``): Landlock (unprivileged, inherited, can not be lifted — ABI v1+ for files,
  kernel 5.13+) can only ALLOW paths, so the agent runs in its own mount namespace where each
  protected item is covered by an empty read-only bind mount, and Landlock denies changing mounts;
  the launcher is the same POSIX shell launcher.
* Windows (``windows.py``): the agent starts with a restricted token (deny-only SIDs on the
  protected items' ACL entries) inside a Job Object it can not leave (no breakaway), or an
  AppContainer where the person's items are not granted; launchers are ``.cmd`` shims first on
  PATH.
"""

from __future__ import annotations

from typing import Optional

from ..places import Places

PROFILE_SUFFIX = ".txt"
SETUID_NOTE = ""
TOOLS_FOLDER = "sandbox-tools"
APPS: dict[str, tuple[str, str]] = {}


def unavailable() -> Optional[str]:
    return "Agent sandboxing works on macOS for now. Blackbox's hooks still protect your files here."


def startup_places(_home: str) -> tuple[list[str], list[str], list[str]]:
    """No startup places are closed where agents are not sandboxed."""
    return [], [], []


def render(_places: Places, digest_line: str = "") -> str:
    return ""


def launcher_script(_command: str, _here: str, _profile: str) -> str:
    return ""


def open_app(app: str, _profile: str, **_options: object) -> str:
    raise ValueError(f"unknown app {app!r}")


def shell_shim(_shell: str, _here: str, _profile: str, _launchers: str = "") -> str:
    return ""


def command_shim(_profile: str, _launchers: str = "") -> str:
    return ""


def brew_shim(_tools: str, _python: str, _dashboard_url: str) -> str:
    return ""


def spawn_brew(_command: list[str], _env: dict[str, str], _cwd: str) -> object:
    raise OSError("Homebrew runs for agents only on macOS")


def stop_group(_process: object) -> None:
    return None


def refresh_tools(_launchers: str, _wanted: bool = True) -> bool:
    return False
