"""Where the system protection helper (``blackbox-netd``, macOS) is installed — one definition
for Network Shield, which checks whether it is there, and ``blackbox uninstall``, which removes it.

The helper is root-owned: its folder, its program and its LaunchDaemon (system domain). It is
installed by Blackbox's installer (``--system-protection``) or by a companion app.

Usage::

    from plugins.blackbox.kernel import system_helper
    system_helper.LAUNCH_DAEMON.is_file()
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["BINARY", "HOME", "KEY_FILE_NAME", "LABEL", "LAUNCH_DAEMON", "user_key_folder"]

HOME = Path("/Library/Application Support/Blackbox/netd")
BINARY = HOME / "blackbox-netd"
LABEL = "ai.umanitek.blackbox.netd"
LAUNCH_DAEMON = Path("/Library/LaunchDaemons") / f"{LABEL}.plist"
#: The key file in the person's key folder (the helper keeps its own root-only copy).
KEY_FILE_NAME = "plan.key"


def user_key_folder() -> Path:
    """The person's folder holding the key that signs the helper's plans and checks its reports
    (``~/Library/Application Support/Blackbox/helper``). An agent may not read or name it
    (``detection.paths.guard_secrets``)."""
    return Path.home() / "Library" / "Application Support" / "Blackbox" / "helper"
