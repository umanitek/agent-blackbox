"""Where the system protection helper (``blackbox-netd``) is installed on this machine — one
definition for Network Shield, which checks whether it is there, File Shield's real-time watch, the
guard (its key folder is a built-in protected place) and ``blackbox uninstall``, which removes it.

The helper is root-owned: its folder, its program and its service definition (macOS's LaunchDaemon,
Linux's systemd unit: :data:`SERVICE`). It is installed by Blackbox's installer
(``--system-protection``) or by a companion app. Each OS's places are in ``platform/<os>.py``.

Usage::

    from plugins.blackbox.kernel import system_helper
    system_helper.SERVICE.is_file()      # the helper is installed
    system_helper.user_key_folder()      # the person's copy of its plan key
"""

from __future__ import annotations

from .platform import BINARY, HOME, INSTALL_HOW, LABEL, RECEIPT, SERVICE, SERVICE_KIND, user_key_folder

__all__ = ["BINARY", "HOME", "INSTALL_HOW", "KEY_FILE_NAME", "LABEL", "RECEIPT", "SERVICE", "SERVICE_KIND", "installed", "user_key_folder"]

#: The key file in the person's key folder (the helper keeps its own root-only copy).
KEY_FILE_NAME = "plan.key"


def installed() -> bool:
    """True when the helper's service definition is in place (an unreadable folder: not installed)."""
    try:
        return SERVICE.is_file()
    except OSError:
        return False
