"""macOS: a Keychain item through ``security delete-generic-password`` and a preferences domain
through ``defaults delete`` — each run with a fixed argv (never a shell), through the caller's
runner (``uninstall``'s, so tests pass a fake).

Usage::

    delete_keychain_item("com.example.app", "token", run)   # True when the item is gone
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Sequence

from .contract import ServiceNames
from .unsupported import disable_linger, remove_user_path_entry

SECURITY = "/usr/bin/security"
DEFAULTS = "/usr/bin/defaults"
Runner = Callable[[Sequence[str]], int]


def delete_keychain_item(service: str, account: str, run: Runner) -> bool:
    """The generic password *service* / *account* removed from the login Keychain."""
    return run([SECURITY, "delete-generic-password", "-s", service, "-a", account]) == 0


def delete_preferences(domain: str, run: Runner) -> bool:
    """The preferences *domain* removed (``defaults delete``, so cfprefsd forgets it too)."""
    return run([DEFAULTS, "delete", domain]) == 0


def stop_login_services(names: ServiceNames, _system_units: tuple[Path, ...], run: Runner, report: list[str]) -> None:
    """Each Blackbox LaunchAgent booted out of the person's GUI domain and its plist removed."""
    uid = os.getuid()
    for label in names.launchd_labels:
        run(["launchctl", "bootout", f"gui/{uid}/{label}"])
        plist = Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"
        if plist.exists():
            plist.unlink()
            report.append(f"removed login service {label}")


__all__ = ["delete_keychain_item", "delete_preferences", "disable_linger", "remove_user_path_entry", "stop_login_services"]
