"""The operating-system seam of the agent sandbox: one module per OS (per-OS structure, Amos
2026-11-21) — ``macos/`` (Seatbelt), ``linux/`` (``blackbox-sandbox``: namespaces, seccomp,
Landlock scopes), ``unsupported.py`` elsewhere (with the Windows port described); the POSIX ports
share ``posix_scripts.py``. Only this machine's module is imported or copied (``kernel.os_layout``).

Pattern: **Strategy** (one module per OS) behind a **Facade** (this module).

Usage::

    from . import platform
    platform.unavailable()          # None when agents can be sandboxed here
    platform.render(places)         # the profile text
"""

from __future__ import annotations

import sys

if sys.platform == "darwin":
    from .macos import (APPS, BREW_PATHS, MANAGER_FOLDERS, ONCE_MINUTES, ProcessFacts, describe, is_system, terminate, ONCE_SUFFIX, PROFILE_SUFFIX,
            PROJECT_INDEX, RUN_INFIX, SETUID_NOTE, TOOLS_FOLDER, brew_shim, broker_shims, command_shim, find_app, is_driver,
            hides_socket, launcher_script, layers, manager_shims, network_rules, open_app, open_shim, open_url, open_with, osascript_shim, prepare,
            refresh_tools, render, run_script, shell_shim, spawn_brew, startup_places, stop_group, unavailable, unprepare)
elif sys.platform.startswith("linux"):
    from .linux import (APPS, BREW_PATHS, MANAGER_FOLDERS, ONCE_MINUTES, ProcessFacts, describe, is_system, terminate, ONCE_SUFFIX, PROFILE_SUFFIX,
            PROJECT_INDEX, RUN_INFIX, SETUID_NOTE, TOOLS_FOLDER, brew_shim, broker_shims, command_shim, find_app, is_driver,
            hides_socket, launcher_script, layers, manager_shims, network_rules, open_app, open_shim, open_url, open_with, osascript_shim, prepare,
            refresh_tools, render, run_script, shell_shim, spawn_brew, startup_places, stop_group, unavailable, unprepare)
else:
    from .unsupported import (APPS, BREW_PATHS, MANAGER_FOLDERS, ONCE_MINUTES, ProcessFacts, describe, is_system, terminate, ONCE_SUFFIX, PROFILE_SUFFIX,
            PROJECT_INDEX, RUN_INFIX, SETUID_NOTE, TOOLS_FOLDER, brew_shim, broker_shims, command_shim, find_app, is_driver,
            hides_socket, launcher_script, layers, manager_shims, network_rules, open_app, open_shim, open_url, open_with, osascript_shim, prepare,
            refresh_tools, render, run_script, shell_shim, spawn_brew, startup_places, stop_group, unavailable, unprepare)

__all__ = ["APPS", "BREW_PATHS", "MANAGER_FOLDERS", "ONCE_MINUTES", "ONCE_SUFFIX", "PROFILE_SUFFIX", "PROJECT_INDEX", "RUN_INFIX", "SETUID_NOTE",
           "TOOLS_FOLDER", "ProcessFacts", "brew_shim", "broker_shims", "command_shim", "describe", "find_app", "hides_socket", "is_driver",
           "is_system", "launcher_script", "layers", "manager_shims", "network_rules", "open_app", "open_shim", "open_url", "open_with",
           "prepare", "refresh_tools", "render", "shell_shim", "spawn_brew", "startup_places", "stop_group", "terminate",
           "unavailable", "unprepare"]
