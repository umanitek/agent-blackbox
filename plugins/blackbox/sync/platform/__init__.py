"""The operating-system seam of ``sync.node_service``: how the service registered for this install's
DKG node is found and reached — one module per OS (per-OS structure, KI-628): ``macos.py`` (the
LaunchAgent, ``launchctl``), ``linux.py`` (the systemd unit, ``systemctl``), ``unsupported.py``
elsewhere. ``model.py`` holds the shared names and :class:`NodeService`. Only this machine's module
is imported or copied (``kernel.os_layout``).

Pattern: **Strategy** (one module per OS) behind a **Facade** (this module).

Usage::

    from . import platform
    platform.registered(cfg, Path.home())      # NodeService or None
    platform.service_for_unit("blackbox-dkg.service")
"""

from __future__ import annotations

import sys

if sys.platform == "darwin":
    from .macos import registered, service_for_unit
elif sys.platform.startswith("linux"):
    from .linux import registered, service_for_unit
else:
    from .unsupported import registered, service_for_unit

__all__ = ["registered", "service_for_unit"]
