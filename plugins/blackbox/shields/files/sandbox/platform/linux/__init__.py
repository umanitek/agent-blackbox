"""Layer 2 on Linux: the agent sandbox is ``blackbox-sandbox`` (the helper crate's second program,
installed root-owned with the system protection helper), started by the same POSIX launchers as on
macOS with the line-oriented policy this package renders (design "Linux deep layers" §1).

What it refuses, and how (the launcher's own doc, ``helper/src/platform/linux/sandbox/mod.rs``):
protected items under mode-0000 masks, Blackbox's own places and the startup places read-only,
the folders above an item pinned — in a private user + mount namespace locked by a nested one;
no new privileges; seccomp (terminal injection, the kernel keyrings, bpf, perf, userfaultfd);
Landlock's signal and abstract-socket scopes on kernel 6.12+; the session bus hidden (so the
keyring is out of reach, F4); local ports, ssh back into this machine and Docker's TCP port refused
per agent by the root helper, matching the agent's cgroup scope.

What it can not do, said plainly (§1.4): no unprivileged user namespaces (a hardened kernel, a
container; Ubuntu 23.10+ until Blackbox's AppArmor rule is installed) → hooks only; a startup FILE
that does not exist is not closed (``.bash_profile``: hooks and the real-time watch; F1); below
6.12 an X11 display stays reachable through its abstract socket; GUI editors on X11 can read and
drive every window (F11); Electron editors run with their own sandbox off; a policy change applies
at the agent's next start.

Pattern: one **Strategy** of :mod:`..` (the platform facade).

Usage::

    unavailable()                                 # None, or why not (from the launcher's probe)
    text = render(places, "sha256:…", allowances)
    launcher_script("claude", here, profile)
"""

from __future__ import annotations

from pathlib import Path

from ......kernel.persistence_places import startup_places
from ...places import Places
from . import placeholders
from .apps import APPS, ELECTRON_FLAGS, open_app
from .launchers import ONCE_MINUTES, ONCE_SUFFIX, PROJECT_INDEX, RUN_INFIX, command_shim, launcher_script, shell_shim
from .opener import find_app, is_driver, open_url, open_with
from .probe import layers, unavailable
from .processes import ProcessFacts, describe, is_system, terminate
from .profile import PROFILE_SUFFIX, SANDBOX, render
from .shims import BREW_READ_ONLY, brew_shim, broker_shims, manager_shims, open_shim, osascript_shim, spawn_brew, stop_group
from .tools import SETUID_NOTE, SETUID_TOOLS, TOOLS_FOLDER, refresh_tools


def run_script(_script: str) -> tuple[int, str]:
    raise OSError("AppleScript runs only on macOS")


def prepare(places: Places, home: str, state: Path) -> list[str]:
    """Creates the startup places' placeholders (:mod:`.placeholders`) and records them in *state*'s
    manifest; answers the ones made now."""
    return placeholders.ensure(places, home, state / placeholders.MANIFEST)


__all__ = [
    "APPS",
    "BREW_READ_ONLY",
    "ELECTRON_FLAGS",
    "ONCE_MINUTES",
    "ONCE_SUFFIX",
    "PROFILE_SUFFIX",
    "PROJECT_INDEX",
    "RUN_INFIX",
    "SANDBOX",
    "SETUID_NOTE",
    "SETUID_TOOLS",
    "TOOLS_FOLDER",
    "ProcessFacts",
    "brew_shim",
    "broker_shims",
    "command_shim",
    "describe",
    "find_app",
    "is_driver",
    "is_system",
    "launcher_script",
    "layers",
    "manager_shims",
    "open_app",
    "open_shim",
    "open_url",
    "open_with",
    "osascript_shim",
    "prepare",
    "refresh_tools",
    "render",
    "run_script",
    "shell_shim",
    "spawn_brew",
    "startup_places",
    "stop_group",
    "terminate",
    "unavailable",
]
