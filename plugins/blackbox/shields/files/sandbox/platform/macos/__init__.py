"""Layer 2 on macOS: the agent sandbox is a Seatbelt profile, run with ``/usr/bin/sandbox-exec``.

Seatbelt is the kernel's own sandbox (the one App Store apps run in). A process started under a
profile keeps it for life, every process it starts inherits it, and nothing inside can lift it —
so a script, a compiled program or an interpreter an agent starts is refused the same as the
agent. Proven on this macOS (27.x, 2026-11-22): ``cat``, ``python3 open()``, grandchildren, a
symlink to a protected file, ``ln`` (hard link), ``mv``/``rm`` of a protected file and a rename of
a folder above one are all refused; a file next to it stays readable.

What it can not do, said plainly (proposal §04):

* driving ANOTHER app, which would do the work outside the sandbox: ``osascript`` (AppleScript
  and JavaScript), ``automator`` and ``shortcuts`` can not start inside (:data:`APP_DRIVERS`),
  and ``open`` / LaunchServices launches are refused (``lsopen``). Probed 2026-11-22: Seatbelt's
  ``appleevent-send`` rule does NOT stop a CLI's AppleEvents, and refusing the LaunchServices
  database lookup (``com.apple.lsd.mapdb``) stops them only by making every LaunchServices caller
  HANG (``open``, a browser login) — so it is not used. Left open: a program the agent compiles
  itself that sends AppleEvents through the system's own frameworks (``NSAppleScript``) — the
  OS's file checks (Layer 3) close that;
* setuid programs (``sudo``, ``su``, ``top``, ``crontab``, ``/bin/ps``) can not run inside any Seatbelt
  sandbox (the kernel's ``forbidden-exec-sugid``; no profile rule lifts it) — so Layer 2 is a per-agent
  choice of the person. ``ps`` works from a copy without the setuid bit, which :func:`refresh_tools`
  keeps in ``<launchers>/sandbox-tools`` (made again when macOS changes) and every launcher puts
  first on the sandboxed PATH (KI-589; an absolute ``/bin/ps`` still fails). The others need root to
  work at all, so a stand-in there says why (:data:`SETUID_NOTE`) instead of a bare
  "operation not permitted";
* ``sandbox-exec`` is marked deprecated by Apple but is what Apple's own tools still use; the
  long-term path is the OS's file checks (Endpoint Security, Layer 3);
* a GUI editor built on Electron/Chromium (Cursor, Windsurf) sandboxes its own helper processes
  with Seatbelt, and a second Seatbelt sandbox can not be started inside one ("sandbox
  initialization failed: Operation not permitted" — every helper exits, so the editor never
  appears; KI-534, probed 2026-11-22 with a Chromium app). Inside Blackbox's sandbox the editor
  therefore runs with its OWN sandbox off (:data:`ELECTRON_FLAGS`): Blackbox's sandbox then covers
  the whole editor, but its web pages lose Chromium's extra isolation — the page says so before the
  person chooses it. An app from the App Store (Apple's App Sandbox) can not be started inside at all.

Pattern: one **Strategy** of :mod:`.` (the platform facade).

Usage::

    text = render(places)                         # the profile
    launcher_script("claude", here, profile)      # the launcher Blackbox puts on PATH
    refresh_tools(here)                           # the setuid-free ps + stand-ins, first on the sandboxed PATH
"""

from __future__ import annotations


from __future__ import annotations

import os
from typing import Optional

from ......kernel.persistence_places import startup_places
from .apps import APPS, ELECTRON_FLAGS, open_app
from .launchers import ONCE_MINUTES, ONCE_SUFFIX, PROJECT_INDEX, RUN_INFIX, command_shim, launcher_script, shell_shim
from .applescript import run_script
from .opener import find_app, is_driver, open_url, open_with
from .processes import ProcessFacts, describe, is_system, terminate
from .profile import APP_DRIVERS, LOCAL_SSH, PROFILE_SUFFIX, SANDBOX_EXEC, render
from .shims import BREW_READ_ONLY, brew_shim, manager_shims, open_shim, osascript_shim, spawn_brew, stop_group
from .tools import PS, SETUID_NOTE, SETUID_TOOLS, TOOLS_FOLDER, refresh_tools


def unavailable() -> Optional[str]:
    """Why the sandbox can not run here, or None."""
    return None if os.access(SANDBOX_EXEC, os.X_OK) else "This Mac has no sandbox-exec, so agents can not be sandboxed."



__all__ = ["APPS", "APP_DRIVERS", "BREW_READ_ONLY", "ELECTRON_FLAGS", "LOCAL_SSH", "ONCE_MINUTES", "ONCE_SUFFIX",
           "PROFILE_SUFFIX", "PROJECT_INDEX", "PS", "RUN_INFIX", "SANDBOX_EXEC", "SETUID_NOTE", "SETUID_TOOLS",
           "TOOLS_FOLDER", "ProcessFacts", "brew_shim", "command_shim", "describe", "find_app", "is_driver",
           "is_system", "launcher_script", "manager_shims", "open_app", "open_shim", "open_url", "open_with",
           "osascript_shim", "refresh_tools", "render", "run_script", "shell_shim", "spawn_brew", "startup_places",
           "stop_group", "terminate", "unavailable"]
