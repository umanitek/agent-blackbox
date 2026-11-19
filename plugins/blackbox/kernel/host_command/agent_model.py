"""Does a Hermes agent have an AI model it can use? Hermes answers; Blackbox only asks (2026-11-19).

WHY this exists: Blackbox checks a prompt at the moment the agent sends it to its model. A fresh
install leaves Hermes with no model (the installer has no key to give it), so nothing is ever
sent, nothing is ever checked, and the dashboard's test prompt "does nothing" — exactly what a
new user reported. Every surface that asks the user to try Blackbox (the installer's last step,
the dashboard's first-detection card, the assistant chat) first asks this question and, when the
answer is no, shows the one fix instead of a dead end.

How it asks: Hermes' own first-run check (``hermes_cli.main._has_any_provider_configured``, the
gate ``hermes chat`` runs before it refuses to start, asked the same unscoped way) in a CHILD
process of this same Hermes with ``HERMES_HOME`` set to the agent's home — the child is used
because Hermes binds a profile's home and secrets at start-up, and it inherits this process's
environment exactly as the agent's own chat would.

Three outcomes (LES-011): :data:`READY`, :data:`MISSING`, :data:`UNKNOWN`. A probe that failed,
timed out or printed something else is UNKNOWN, and callers act only on MISSING.

Usage::

    if agent_model_state() == MISSING:
        print(NO_MODEL_MESSAGE)
    agent_model_state(profile_home)   # a named profile's home
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import Callable, Optional

READY = "ready"
MISSING = "missing"
UNKNOWN = "unknown"

#: The fix, as the user types it: Hermes' one-step free Nous Portal sign-in (opens the browser,
#: no API key). ``hermes setup`` offers every other provider.
FIX_COMMAND = "hermes setup --portal"

#: Exit status of ``blackbox chat`` when the agent has no model (sysexits' EX_CONFIG); the
#: dashboard turns it into the "connect a model" card instead of an error.
NO_MODEL_EXIT = 78

NO_MODEL_MESSAGE = (
    "Your agent has no AI model connected yet, so it cannot chat — and Blackbox checks each prompt "
    "as the agent sends it to its model. Connect one (free, opens your browser, no API key) by "
    f"running this in a terminal:  {FIX_COMMAND}   (or `hermes setup` for any other provider). "
    "Threat-graph sync, the dashboard and the rules keep working without it."
)

#: Hermes imports its whole CLI here (about 1–2 s); a slow machine gets ten times that.
PROBE_TIMEOUT_SECONDS = 20.0

_PROBE = (
    "from hermes_cli.main import _has_any_provider_configured as configured\n"
    "print('ready' if configured() else 'missing')\n"
)

Runner = Callable[..., "subprocess.CompletedProcess[str]"]

__all__ = ["FIX_COMMAND", "MISSING", "NO_MODEL_EXIT", "NO_MODEL_MESSAGE", "READY", "UNKNOWN",
           "agent_model_state"]


def agent_model_state(hermes_home: Optional[Path] = None, *, run: Runner = subprocess.run) -> str:
    """READY, MISSING or UNKNOWN for the Hermes home *hermes_home* (``None``: this process's own).

    *run* is the test seam for :func:`subprocess.run`.
    """
    env = dict(os.environ)
    if hermes_home is not None:
        env["HERMES_HOME"] = str(hermes_home)
    argv = [sys.executable, "-c", _PROBE]
    try:
        proc = run(argv, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                   timeout=PROBE_TIMEOUT_SECONDS, check=False)
    except (OSError, subprocess.SubprocessError, ValueError):
        return UNKNOWN
    if proc.returncode != 0:
        return UNKNOWN
    lines = (proc.stdout or "").strip().splitlines()
    answer = lines[-1].strip() if lines else ""
    return answer if answer in (READY, MISSING) else UNKNOWN
