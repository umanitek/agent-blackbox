"""What a system does not have: no Keychain or preferences domains, no systemd lingering, no
per-user PATH in the registry — nothing to remove there. The other modules take the functions
they have no use for from here, and macOS and Linux take the POSIX shell's spelling of the
commands a person types (:func:`manual_removal`), which every Unix shares.

Usage::

    delete_keychain_item("com.example.app", "token", run)   # False: not on this system
    manual_removal([Path("/home/a/agent-blackbox")], [])    # ("rm -rf -- /home/a/agent-blackbox",)
"""

from __future__ import annotations

import shlex
from pathlib import Path
from typing import Callable, Sequence

Runner = Callable[[Sequence[str]], int]


def delete_keychain_item(_service: str, _account: str, _run: Runner) -> bool | None:
    return None   # no Keychain on this system: nothing there to remove


def delete_preferences(_domain: str, _run: Runner) -> bool | None:
    return None   # no preferences domains on this system: nothing there to remove


def disable_linger(_user: str, _run: Runner) -> bool:
    return False


def stop_login_services(_names, _system_units, _run: Runner, _report: list[str]) -> None:
    """No login services Blackbox registers on this system."""


def remove_user_path_entry(_folder: str) -> bool:
    return False


def manual_removal(paths: Sequence[Path], empty_dirs: Sequence[Path]) -> tuple[str, ...]:
    """The shell commands that remove *paths* (files, links as links, folders with what is in
    them) and then each of *empty_dirs* that is empty (``rmdir`` refuses one that is not), quoted
    for a POSIX shell. For the person to type: nothing runs here."""
    commands = [f"rm -rf -- {shlex.join(str(path) for path in paths)}"] if paths else []
    if empty_dirs:
        commands.append(f"rmdir -- {shlex.join(str(path) for path in empty_dirs)} 2>/dev/null")
    return tuple(commands)


__all__ = ["delete_keychain_item", "delete_preferences", "disable_linger", "manual_removal", "remove_user_path_entry",
           "stop_login_services"]
