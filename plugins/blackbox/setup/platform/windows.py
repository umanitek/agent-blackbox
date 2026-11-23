"""Windows: the folder Blackbox's installer put on the person's own PATH (``HKCU\\Environment``,
``Install-BlackboxCommand`` in blackbox-install.ps1, recorded in the install manifest) taken off
it again, every other entry kept in its order. The change is broadcast the way Windows expects
(``WM_SETTINGCHANGE``), so a new terminal sees it.

Usage::

    remove_user_path_entry(r"C:\\Users\\alice\\.local\\bin")   # True when it was there and is gone
"""

from __future__ import annotations

import ctypes
from pathlib import Path

from .contract import Runner, ServiceNames
from .unsupported import delete_keychain_item, delete_preferences, disable_linger

ENVIRONMENT_KEY = "Environment"
PATH_VALUE = "Path"
HWND_BROADCAST, WM_SETTINGCHANGE, SMTO_ABORTIFHUNG, BROADCAST_TIMEOUT_MS = 0xFFFF, 0x001A, 0x0002, 2000


def _same_folder(entry: str, folder: str) -> bool:
    return entry.strip().rstrip("\\").lower() == folder.strip().rstrip("\\").lower()


def remove_user_path_entry(folder: str) -> bool:
    """*folder* taken off the user PATH; False when it was not on it (nothing changed)."""
    # WHY here: the registry module exists only on Windows; the module's other answers (the
    # Scheduled Tasks below) load on any system, so the suite runs them with a fake runner.
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, ENVIRONMENT_KEY, 0,
                        winreg.KEY_READ | winreg.KEY_SET_VALUE) as key:
        try:
            value, kind = winreg.QueryValueEx(key, PATH_VALUE)
        except FileNotFoundError:
            return False
        entries = str(value).split(";")
        kept = [entry for entry in entries if not _same_folder(entry, folder)]
        if len(kept) == len(entries):
            return False
        winreg.SetValueEx(key, PATH_VALUE, 0, kind, ";".join(kept))
    ctypes.windll.user32.SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, ENVIRONMENT_KEY,
                                             SMTO_ABORTIFHUNG, BROADCAST_TIMEOUT_MS, None)
    return True


def stop_login_services(names: ServiceNames, _system_units: tuple[Path, ...], run: Runner, report: list[str]) -> None:
    """Each Blackbox sign-in task ended and deleted."""
    for task in names.windows_tasks:
        run(["schtasks", "/End", "/TN", task])
        if run(["schtasks", "/Delete", "/TN", task, "/F"]) == 0:
            report.append(f"removed scheduled task {task}")


__all__ = ["delete_keychain_item", "delete_preferences", "disable_linger", "remove_user_path_entry", "stop_login_services"]
