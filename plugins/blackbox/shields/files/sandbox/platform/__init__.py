"""The operating-system seam of the agent sandbox: one module per OS (per-OS structure, Amos
2026-11-21) — ``macos.py`` (Seatbelt) today, ``unsupported.py`` elsewhere (with the Linux and
Windows ports described). Only this machine's module is imported or copied (``kernel.os_layout``).

Pattern: **Strategy** (one module per OS) behind a **Facade** (this module).

Usage::

    from . import platform
    platform.unavailable()          # None when agents can be sandboxed here
    platform.render(places)         # the profile text
"""

from __future__ import annotations

import sys

if sys.platform == "darwin":
    from .macos import APPS, PROFILE_SUFFIX, launcher_script, open_app, render, unavailable
else:
    from .unsupported import APPS, PROFILE_SUFFIX, launcher_script, open_app, render, unavailable

__all__ = ["APPS", "PROFILE_SUFFIX", "launcher_script", "open_app", "render", "unavailable"]
