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
    from .macos import (APPS, ONCE_MINUTES, ProcessFacts, describe, is_system, terminate, ONCE_SUFFIX, PROFILE_SUFFIX, PROJECT_INDEX, RUN_INFIX, SETUID_NOTE, TOOLS_FOLDER, brew_shim, command_shim, find_app, is_driver,
                        launcher_script, manager_shims, open_app, open_shim, open_url, open_with, osascript_shim, refresh_tools, render, run_script,
                        shell_shim, spawn_brew, startup_places, stop_group, unavailable)
else:
    from .unsupported import (APPS, ONCE_MINUTES, ProcessFacts, describe, is_system, terminate, ONCE_SUFFIX, PROFILE_SUFFIX, PROJECT_INDEX, RUN_INFIX, SETUID_NOTE, TOOLS_FOLDER, brew_shim, command_shim, find_app, is_driver,
                        launcher_script, manager_shims, open_app, open_shim, open_url, open_with, osascript_shim, refresh_tools, render, run_script,
                              shell_shim, spawn_brew, startup_places, stop_group, unavailable)

__all__ = ["APPS", "ONCE_MINUTES", "ONCE_SUFFIX", "PROFILE_SUFFIX", "PROJECT_INDEX", "RUN_INFIX", "SETUID_NOTE",
           "TOOLS_FOLDER", "ProcessFacts", "brew_shim", "command_shim", "describe", "find_app", "is_driver",
           "is_system", "launcher_script", "manager_shims", "open_app", "open_shim", "open_url", "open_with",
           "refresh_tools", "render", "shell_shim", "spawn_brew", "startup_places", "stop_group", "terminate",
           "unavailable"]
