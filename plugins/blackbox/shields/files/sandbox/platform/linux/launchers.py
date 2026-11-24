"""The shell launchers on Linux: the POSIX ports' shared scripts (``platform/posix_scripts.py``) with
Linux's runner, ``blackbox-sandbox run --policy <profile> --``. A machine where the launcher is
not installed (no system protection helper yet) runs the agent with Blackbox's hooks only and says
so, the same line as a missing profile.

Usage::

    launcher_script("claude", here, profile)
    shell_shim("bash", here, profile, launchers)
    command_shim(profile, launchers)
"""

from __future__ import annotations

from .. import posix_scripts
from ..posix_scripts import ONCE_MINUTES, PROJECT_INDEX, RUN_INFIX, quote_shell
from .profile import PROFILE_SUFFIX, SANDBOX
from .tools import tools_dir

ONCE_SUFFIX = ".once" + PROFILE_SUFFIX
SUFFIXES = posix_scripts.Suffixes(PROFILE_SUFFIX, ONCE_SUFFIX)
#: How a launcher starts a program inside the policy.
RUNNER = f'{quote_shell(SANDBOX)} run --policy "$profile" --'
#: The launcher is there (else: hooks only).
READY = f"[ -x {quote_shell(SANDBOX)} ]"


def launcher_script(command: str, here: str, profile: str) -> str:
    """The launcher first on PATH for *command*, with ``<here>/sandbox-tools`` first on the sandboxed PATH."""
    return posix_scripts.launcher_script(command, here, profile, RUNNER, tools_dir(here), SUFFIXES, READY)


def shell_shim(shell: str, here: str, profile: str, launchers: str = "") -> str:
    """The Hermes agent's sandboxed *shell*."""
    return posix_scripts.shell_shim(shell, here, profile, RUNNER, tools_dir(launchers) if launchers else "", SUFFIXES, READY)


def command_shim(profile: str, launchers: str = "") -> str:
    """The Hermes agent's ``execute_code`` interpreter launcher."""
    return posix_scripts.command_shim(profile, RUNNER, tools_dir(launchers) if launchers else "", SUFFIXES, READY)


__all__ = ["ONCE_MINUTES", "ONCE_SUFFIX", "PROJECT_INDEX", "READY", "RUNNER", "RUN_INFIX", "SUFFIXES", "command_shim",
           "launcher_script", "shell_shim"]
