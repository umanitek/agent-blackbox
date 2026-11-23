"""The Hermes agent inside the agent sandbox: its terminal tool's shells and its ``execute_code``
interpreter run inside, while Hermes itself (and Blackbox in it) stays outside.

Blackbox writes sandboxed ``bash`` / ``sh`` / ``zsh`` shims and an interpreter launcher into
:func:`.layout.hermes_shell_dir`, puts that folder first on the Hermes process's OWN PATH and sets
Hermes's interpreter-launcher hook point (:data:`HERMES_LAUNCHER_ENV`, a carried patch in
``tools/code_kernel.py``) at each session start.

Usage::

    sync_shells(True)               # shims + launcher written (False: removed)
    enter_hermes_process(mode)      # HermesCover(shells=True, execute_code=True, note="")
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from ....kernel import agent_hosts
from ...contract import ShieldMode
from .. import mode as mode_module
from . import platform
from .layout import agent_profile, chosen, hermes_shell_dir, launcher_dir, write_if_changed

#: The shells the Hermes agent's terminal tool may start (it looks ``bash`` up on its own PATH).
HERMES_SHELLS = ("bash", "sh", "zsh")

#: Hermes's interpreter-launcher hook point (carried patch in ``tools/code_kernel.py``): a JSON
#: argv array put before the Python its ``execute_code`` tool starts, read from Hermes's own process.
HERMES_LAUNCHER_ENV = "HERMES_EXECUTE_CODE_LAUNCHER"
#: The launcher Blackbox writes beside the Hermes shells for ``execute_code``'s interpreter.
HERMES_CODE_LAUNCHER = "execute-code"


def sync_shells(wanted: bool) -> None:
    """Writes the sandboxed shells and the ``execute_code`` launcher when *wanted*; removes them otherwise."""
    folder, profile = hermes_shell_dir(), str(agent_profile(agent_hosts.HERMES_ID))   # the Hermes agent's own profile
    for shell in HERMES_SHELLS:
        if wanted:
            write_if_changed(folder / shell, platform.shell_shim(shell, str(folder), profile, str(launcher_dir())), 0o755)
        else:
            (folder / shell).unlink(missing_ok=True)
    if wanted:
        write_if_changed(code_launcher(), platform.command_shim(profile, str(launcher_dir())), 0o755)
    else:
        code_launcher().unlink(missing_ok=True)


def code_launcher() -> Path:
    return hermes_shell_dir() / HERMES_CODE_LAUNCHER


def _hermes_has_launcher_hook() -> bool:
    """True when the Hermes Blackbox runs in reads :data:`HERMES_LAUNCHER_ENV` (the carried patch);
    a Hermes without it starts execute_code's Python directly, whatever the setting says."""
    try:
        from tools import code_kernel   # the Hermes host's module, not Blackbox's
    except ImportError:
        return False
    return getattr(code_kernel, "INTERPRETER_LAUNCHER_ENV", None) == HERMES_LAUNCHER_ENV


@dataclass(frozen=True)
class HermesCover:
    """What of the Hermes agent runs inside the sandbox: its terminal tool's ``shells``, its
    ``execute_code`` interpreter, and ``note`` — why execute_code is not covered when it is not."""
    shells: bool = False
    execute_code: bool = False
    note: str = ""


def enter_hermes_process(mode: Optional[ShieldMode] = None, environ: Optional[dict[str, str]] = None) -> HermesCover:
    """Puts the sandboxed shells first on THIS (the Hermes agent's) process PATH and sets Hermes's
    interpreter-launcher hook point (:data:`HERMES_LAUNCHER_ENV`) to Blackbox's launcher when the
    person sandboxes the Hermes agent; takes both away when not. So every shell its terminal tool
    starts and every ``execute_code`` Python run inside the sandbox, while Hermes itself (and
    Blackbox inside it) do not. A launcher value someone else set is left alone. Answers what is
    covered (:class:`HermesCover`)."""
    mode = mode or mode_module.current()
    env = os.environ if environ is None else environ
    folder = str(hermes_shell_dir())
    parts = [part for part in env.get("PATH", "").split(os.pathsep) if part and part != folder]
    wanted = (agent_hosts.HERMES_ID in chosen(mode) and platform.unavailable() is None
              and all((hermes_shell_dir() / shell).is_file() for shell in HERMES_SHELLS))
    env["PATH"] = os.pathsep.join(([folder] if wanted else []) + parts)
    ours = json.dumps([str(code_launcher())])
    code, note = wanted and code_launcher().is_file(), code_note(wanted)
    if code:
        env[HERMES_LAUNCHER_ENV] = ours
    elif env.get(HERMES_LAUNCHER_ENV) == ours:
        del env[HERMES_LAUNCHER_ENV]
    return HermesCover(shells=wanted, execute_code=code and not note, note=note)


def code_note(shells: bool) -> str:
    """Why the Hermes agent's execute_code stays on hooks, or "" when it is covered."""
    if not shells:
        return "not picked for the sandbox"
    if not code_launcher().is_file():
        return f"Blackbox's execute_code launcher is missing ({code_launcher()})"
    if not _hermes_has_launcher_hook():
        return f"this Hermes has no {HERMES_LAUNCHER_ENV} hook point, so it starts execute_code's Python directly"
    return ""


__all__ = ["HERMES_CODE_LAUNCHER", "HERMES_LAUNCHER_ENV", "HERMES_SHELLS", "HermesCover", "code_launcher", "code_note",
           "enter_hermes_process", "sync_shells"]
