"""Linux: systemd lingering turned off again for the person (``loginctl disable-linger``) when
Blackbox's installer turned it on (``ensure_user_lingering``, recorded in the install manifest) —
a fixed argv, never a shell, through the caller's runner (``uninstall``'s, so tests pass a fake).

Usage::

    disable_linger("alice", run)   # True when loginctl said yes
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Callable, Sequence

from .contract import ServiceNames
from .unsupported import delete_keychain_item, delete_preferences, manual_removal, remove_user_path_entry

LOGINCTL = "loginctl"
Runner = Callable[[Sequence[str]], int]


def system_package_removal(name: str) -> str:
    """The command that removes the system package *name* (said to the person, never run: it needs
    an administrator) — apt where it exists, else dnf."""
    return f"sudo apt-get remove {name}" if shutil.which("apt-get") else f"sudo dnf remove {name}"


def disable_linger(user: str, run: Runner) -> bool:
    """Lingering off for *user*: their services stop at logout again, as before the install."""
    return run([LOGINCTL, "disable-linger", user]) == 0


def stop_login_services(names: ServiceNames, system_units: tuple[Path, ...], run: Runner, report: list[str]) -> None:
    """Blackbox's systemd user units disabled, stopped and removed; its root units too when this
    runs as root (KI-506), else each named with the root commands that finish it."""
    user_dir = Path.home() / ".config" / "systemd" / "user"
    removed = False
    for unit in names.systemd_units:
        if (user_dir / unit).exists():
            run(["systemctl", "--user", "disable", "--now", unit])
            (user_dir / unit).unlink()
            removed = True
            report.append(f"removed login service {unit}")
    if removed:
        run(["systemctl", "--user", "daemon-reload"])
    _stop_system_units(system_units, run, report)


def _is_root() -> bool:
    return os.geteuid() == 0   # windows-footgun: ok — the Linux module, imported only on Linux


def _stop_system_units(system_units: tuple[Path, ...], run: Runner, report: list[str]) -> None:
    """Linux's root units (``/etc/systemd/system``): stopped, disabled and removed when uninstall
    runs as root (KI-506: they were left enabled even then); otherwise each is named with the root
    commands that finish it."""
    if not system_units:
        return
    if not _is_root():
        for unit in system_units:
            report.append(f"needs root: sudo systemctl disable --now {unit.name} && sudo rm {unit} "
                          "&& sudo systemctl daemon-reload")
        return
    for unit in system_units:
        run(["systemctl", "disable", "--now", unit.name])
        unit.unlink(missing_ok=True)
        report.append(f"removed system service {unit.name}")
    run(["systemctl", "daemon-reload"])


__all__ = ["delete_keychain_item", "delete_preferences", "disable_linger", "manual_removal", "remove_user_path_entry",
           "stop_login_services", "system_package_removal"]
