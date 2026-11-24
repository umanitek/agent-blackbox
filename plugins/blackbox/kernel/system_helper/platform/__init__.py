"""The operating-system seam of :mod:`kernel.system_helper`: where this OS's helper lives — one
module per OS (per-OS structure): ``macos.py`` (a LaunchDaemon under ``/Library``), ``linux.py``
(a systemd unit, ``/usr/local/libexec`` and ``/var/lib/blackbox``). Another OS reads macOS's
places, which never exist there (the helper is "not installed"). Only this machine's module is
imported or copied (``kernel.os_layout``).

Pattern: **Strategy** (one module per OS) behind a **Facade** (``kernel.system_helper``).
"""

from __future__ import annotations

import sys

if sys.platform.startswith("linux"):
    from .linux import BINARY, HOME, LABEL, RECEIPT, SERVICE, SERVICE_KIND, user_key_folder
else:
    from .macos import BINARY, HOME, LABEL, RECEIPT, SERVICE, SERVICE_KIND, user_key_folder

__all__ = ["BINARY", "HOME", "LABEL", "RECEIPT", "SERVICE", "SERVICE_KIND", "user_key_folder"]
