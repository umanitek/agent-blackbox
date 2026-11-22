"""The operating-system seam of the agent observer: the two programs it runs to see which agent
processes exist are run here, one module per operating system (per-OS structure, 2026-11-21).

Each function answers raw text, or ``""`` when this machine cannot be read that way, so a missing
tool degrades to "no process seen", never to an error. READ-ONLY by construction: nothing here
(or anywhere in ``observe``) signals, stops or changes a process.

Pattern: **Strategy** (one module per OS) behind a **Facade** (this module).

Usage::

    from . import platform
    platform.process_table()        # "pid ppid <start> command…" lines, "" when unreadable
    platform.process_environment(1234)
"""

from __future__ import annotations

import sys

if sys.platform == "darwin":
    from .macos import process_environment, process_table
else:
    from .unsupported import process_environment, process_table

__all__ = ["process_environment", "process_table"]
