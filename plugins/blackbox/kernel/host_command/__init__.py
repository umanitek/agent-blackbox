"""The command that starts THIS Hermes again, for every child ``hermes …`` process.

WHY one place: a child must run the same Hermes that is running now — the same
code, version and profile rules. ``hermes`` looked up on PATH can be another
install on a machine that has two, so the command is always this process's own
Python running Hermes' entry module. A published Hermes install starts through
a launcher that hands its import path to child processes, so the module is
found there as well (checked on a real install, 2026-11-10).

Usage::

    subprocess.run(hermes_argv("blackbox", "sync", "--wait"))
    subprocess.Popen(hermes_argv("--profile", name, "serve"))

The one exception is ``blackbox chat``: it REPLACES the current process with
Hermes' interactive chat and uses Hermes' own relaunch resolver for that.
"""

from __future__ import annotations

import sys

#: Hermes' command-line entry module.
HERMES_ENTRY_MODULE = "hermes_cli.main"

__all__ = ["HERMES_ENTRY_MODULE", "hermes_argv"]


def hermes_argv(*args: str) -> list[str]:
    """``hermes <args…>`` as an argument list that runs the Hermes this process runs in."""
    return [sys.executable, "-m", HERMES_ENTRY_MODULE, *args]
