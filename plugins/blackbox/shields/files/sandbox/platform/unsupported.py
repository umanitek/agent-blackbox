"""An operating system without an agent sandbox yet: nothing is sandboxed, and the shield says so.

The ports, with the same functions (proposal §03):

* Linux: ported (``linux/``).
* Windows (``windows.py``): the agent starts with a restricted token (deny-only SIDs on the
  protected items' ACL entries) inside a Job Object it can not leave (no breakaway), or an
  AppContainer where the person's items are not granted; launchers are ``.cmd`` shims first on
  PATH.
"""

from __future__ import annotations

from typing import Optional

from ..places import Places

PROFILE_SUFFIX = ".txt"
PROJECT_INDEX = "projects.idx"
ONCE_SUFFIX, RUN_INFIX, ONCE_MINUTES = ".once.txt", ".run.", 30
SETUID_NOTE = ""
TOOLS_FOLDER = "sandbox-tools"
APPS: dict[str, tuple[str, str]] = {}


def unavailable() -> Optional[str]:
    return "Agent sandboxing works on macOS for now. Blackbox's hooks still protect your files here."


def layers() -> list[dict[str, str]]:
    return []


def prepare(_places: object, _home: str, _state: object) -> list[str]:
    return []


def startup_places(_home: str) -> tuple[list[str], list[str], list[str]]:
    """No startup places are closed where agents are not sandboxed."""
    return [], [], []


def render(_places: Places, digest_line: str = "", allowances: object = None) -> str:
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


def manager_shims(_tools: str, _python: str, _dashboard_url: str) -> dict[str, str]:
    return {}


def open_shim(_tools: str, _python: str, _dashboard_url: str) -> str:
    return ""


def find_app(_name: str) -> str:
    return ""


def is_driver(_app_path: str) -> bool:
    return True


def open_url(_url: str) -> int:
    raise OSError("Blackbox opens links for agents only on macOS")


def open_with(_app_path: str, _files: object) -> int:
    raise OSError("Blackbox opens apps for agents only on macOS")


class ProcessFacts:   # the same shape as macOS's; never built here
    uid: int
    path: str
    args: str


def describe(_pid: int) -> None:
    return None


def is_system(_path: str) -> bool:
    return True


def terminate(_pid: int) -> bool:
    return False


def broker_shims(_tools: str, _python: str, _dashboard_url: str) -> dict[str, str]:
    return {}


def osascript_shim(_tools: str, _python: str, _dashboard_url: str) -> str:
    return ""


def run_script(_script: str) -> tuple[int, str]:
    raise OSError("AppleScript runs only on macOS")


def spawn_brew(_command: list[str], _env: dict[str, str], _cwd: str) -> object:
    raise OSError("Homebrew runs for agents only on macOS")


def stop_group(_process: object) -> None:
    return None


def refresh_tools(_launchers: str, _wanted: bool = True) -> bool:
    return False
