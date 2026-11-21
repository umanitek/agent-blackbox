"""The operating-system seam of Network Shield's monitor: every program the monitor runs to see
this machine is run here, one module per operating system (per-OS structure, Amos 2026-11-21).

The monitor's other modules parse and combine; they never run a program themselves (a guard in
``tests/plugins/test_blackbox_platform_layout.py`` holds that). Each function answers the
program's raw text, or ``None`` / ``""`` when this machine cannot be read that way, so a missing
tool degrades to "nothing seen", never to an error.

``macos.py`` implements them today; ``unsupported.py`` answers "nothing here" for an operating
system without a port yet. Only this machine's module is imported. Porting = add ``windows.py``
or ``linux.py`` with the same functions and pick it below.

Pattern: **Strategy** (one module per OS) behind a **Facade** (this module).

Usage::

    from . import platform
    text = platform.connection_table()     # None: cannot read connections here
"""

from __future__ import annotations

import sys

if sys.platform == "darwin":
    from .macos import (code_signature, connection_table, listening_table, process_paths, process_table,
                        routing_table, tailscale_status, traffic_unavailable)
else:
    from .unsupported import (code_signature, connection_table, listening_table, process_paths, process_table,
                              routing_table, tailscale_status, traffic_unavailable)

__all__ = [
    "code_signature", "connection_table", "listening_table", "process_paths", "process_table", "routing_table",
    "tailscale_status", "traffic_unavailable",
]
