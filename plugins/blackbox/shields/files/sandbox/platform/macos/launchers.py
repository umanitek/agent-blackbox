"""The shell launchers that start a program inside the profile: one per command-line agent (first on
the person's PATH), the Hermes agent's sandboxed shells and its ``execute_code`` interpreter launcher.
The scripts are the POSIX ports' shared ones (``platform/posix_scripts.py``); macOS's runner is
``sandbox-exec -f <profile>``.

Usage::

    launcher_script("claude", here, profile, canary)
    shell_shim("bash", here, profile, canary, launchers)
    command_shim(profile, canary, launchers)
"""

from __future__ import annotations

from .. import posix_scripts
from ..posix_scripts import ONCE_MINUTES, PROJECT_INDEX, RUN_INFIX, quote_shell, with_tools
from .profile import PROFILE_SUFFIX, SANDBOX_EXEC
from .tools import tools_dir

#: Allow once for a profile's permission: ``<profile>.once.sb`` beside the profile the launch picks
#: (``posix_scripts.pick_profile``).
ONCE_SUFFIX = ".once" + PROFILE_SUFFIX
SUFFIXES = posix_scripts.Suffixes(PROFILE_SUFFIX, ONCE_SUFFIX)
#: How a launcher starts a program inside the profile.
RUNNER = f'{SANDBOX_EXEC} -f "$profile"'


def pick_profile() -> str:
    """The project-profile pick (``posix_scripts.pick_profile``) for Seatbelt profiles."""
    return posix_scripts.pick_profile(SUFFIXES)


def launcher_script(command: str, here: str, profile: str, canary: str) -> str:
    """The launcher first on PATH for *command* (``posix_scripts.launcher_script``), with the
    sandbox's tools (``<here>/sandbox-tools``) first on the sandboxed PATH."""
    return posix_scripts.launcher_script(command, here, profile, RUNNER, tools_dir(here), SUFFIXES, canary)


def shell_shim(shell: str, here: str, profile: str, canary: str, launchers: str = "") -> str:
    """The Hermes agent's sandboxed *shell* (``posix_scripts.shell_shim``); *launchers*: the folder
    whose ``sandbox-tools`` go first on the sandboxed shell's PATH."""
    return posix_scripts.shell_shim(shell, here, profile, RUNNER, tools_dir(launchers) if launchers else "", SUFFIXES, canary)


def command_shim(profile: str, canary: str, launchers: str = "") -> str:
    """The Hermes agent's ``execute_code`` interpreter launcher (``posix_scripts.command_shim``)."""
    return posix_scripts.command_shim(profile, RUNNER, tools_dir(launchers) if launchers else "", SUFFIXES, canary)


__all__ = [
    "ONCE_MINUTES",
    "ONCE_SUFFIX",
    "PROJECT_INDEX",
    "RUNNER",
    "RUN_INFIX",
    "SUFFIXES",
    "command_shim",
    "launcher_script",
    "pick_profile",
    "quote_shell",
    "shell_shim",
    "with_tools",
]
