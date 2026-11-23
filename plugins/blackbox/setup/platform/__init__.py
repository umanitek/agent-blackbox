"""The operating-system seam of ``blackbox uninstall``: what only the system's own tools can remove
— a Keychain item, a preferences domain (macOS), systemd lingering the installer turned on (Linux),
the folder the installer put on the user PATH (Windows) — one module per OS (per-OS structure, Amos
2026-11-21): ``macos.py``, ``linux.py``, ``windows.py``, ``unsupported.py`` elsewhere; each module
answers the whole contract, False for what its system does not have. Only this machine's module is
imported or copied (``kernel.os_layout``).

Pattern: **Strategy** (one module per OS) behind a **Facade** (this module).

Usage::

    from . import platform
    platform.delete_keychain_item("com.example.app", "token", run)   # True when removed
    platform.delete_preferences("com.example.app", run)
    platform.disable_linger("alice", run)                     # Linux
    platform.remove_user_path_entry(r"C:\\Users\\a\\.local\\bin")  # Windows
    platform.stop_login_services(names, system_units, run, report)   # launchd / systemd / Scheduled Tasks
    platform.manual_removal(paths, empty_dirs)                # the commands a person types to remove them
"""

from __future__ import annotations

import sys

if sys.platform == "darwin":
    from .macos import delete_keychain_item, delete_preferences, disable_linger, manual_removal, \
        remove_user_path_entry, stop_login_services
elif sys.platform.startswith("linux"):
    from .linux import delete_keychain_item, delete_preferences, disable_linger, manual_removal, \
        remove_user_path_entry, stop_login_services
elif sys.platform == "win32":
    from .windows import delete_keychain_item, delete_preferences, disable_linger, manual_removal, \
        remove_user_path_entry, stop_login_services
else:
    from .unsupported import delete_keychain_item, delete_preferences, disable_linger, manual_removal, \
        remove_user_path_entry, stop_login_services

from .contract import ServiceNames

__all__ = ["ServiceNames", "delete_keychain_item", "delete_preferences", "disable_linger", "manual_removal",
           "remove_user_path_entry", "stop_login_services"]
