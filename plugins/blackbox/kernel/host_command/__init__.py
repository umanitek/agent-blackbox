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

``agent_model.py`` asks this same Hermes whether an agent has an AI model it can use
(``agent_model_state``: ready / missing / unknown) and holds the one message and fix
every surface shows when it has none. ``hermes_root.py`` asks Hermes for the machine's main home,
where the one Blackbox for every profile keeps its rules, logs and settings (re-exported as
``constants.hermes_root``).
"""

from __future__ import annotations

import sys

from .agent_model import (FIX_COMMAND, MISSING, NO_MODEL_EXIT, NO_MODEL_MESSAGE, READY, UNKNOWN,
                          agent_model_state)

#: Hermes' command-line entry module.
HERMES_ENTRY_MODULE = "hermes_cli.main"

__all__ = ["FIX_COMMAND", "HERMES_ENTRY_MODULE", "MISSING", "NO_MODEL_EXIT", "NO_MODEL_MESSAGE", "READY", "UNKNOWN",
           "agent_model_state", "hermes_argv"]


def hermes_argv(*args: str) -> list[str]:
    """``hermes <args…>`` as an argument list that runs the Hermes this process runs in."""
    return [sys.executable, "-m", HERMES_ENTRY_MODULE, *args]
