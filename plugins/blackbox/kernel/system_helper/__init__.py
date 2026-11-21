"""Where the system protection helper (``blackbox-netd``, macOS) is installed — one definition
for Network Shield, which checks whether it is there, and ``blackbox uninstall``, which removes it.

The helper is root-owned: its folder, its program and its LaunchDaemon (system domain). It is
installed by Blackbox's installer (``--system-protection``) or by Blackbox Desktop.

Usage::

    from plugins.blackbox.kernel import system_helper
    system_helper.LAUNCH_DAEMON.is_file()
"""

from __future__ import annotations

from pathlib import Path

__all__ = ["BINARY", "HOME", "LABEL", "LAUNCH_DAEMON"]

HOME = Path("/Library/Application Support/Blackbox/netd")
BINARY = HOME / "blackbox-netd"
LABEL = "ai.umanitek.blackbox.netd"
LAUNCH_DAEMON = Path("/Library/LaunchDaemons") / f"{LABEL}.plist"
