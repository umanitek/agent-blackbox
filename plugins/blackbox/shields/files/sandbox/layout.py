"""Where the agent sandbox's files live, which agents it can start, and how its files are written.

Shared by the facade (``__init__``), :mod:`.hermes` and :mod:`.status`, so neither of those has to
import the facade (no cycle). No policy here: :mod:`.places` is the policy.

Usage::

    profile_path()          # <BLACKBOX_HOME>/sandbox/agents.sb
    chosen(mode)            # ("claude-code",) — the agents the person sandboxes
    write_if_changed(path, text, 0o755)
"""

from __future__ import annotations

import stat
from pathlib import Path

from ....kernel import agent_hosts, constants
from ....kernel.bounded_files import atomic_write
from ...contract import ShieldMode
from .. import mode as mode_module
from . import platform

#: GUI agents are relaunched, not given a command-line launcher.
_GUI_ONLY = frozenset({"windsurf"})
#: Command-line agents and the commands their launchers stand in for.
CLI_AGENTS: dict[str, tuple[str, ...]] = {host.id: tuple(host.commands) for host in agent_hosts.HOSTS
                                          if host.id not in _GUI_ONLY and host.commands}


def home() -> Path:
    return constants.blackbox_home() / "sandbox"


def profile_path() -> Path:
    return home() / f"agents{platform.PROFILE_SUFFIX}"


def canary_path() -> Path:
    return home() / "canary"


def launcher_dir() -> Path:
    return constants.blackbox_home() / "agent-bin"


def hermes_shell_dir() -> Path:
    """Where the Hermes agent's sandboxed shells live — put first on the Hermes process's OWN PATH
    (``hermes.enter_process``), never on the person's."""
    return home() / "hermes-shell"


def chosen(mode: ShieldMode) -> tuple[str, ...]:
    """The agents the person sandboxes (none while File Shield is off)."""
    return tuple(mode.options.get(mode_module.OPT_SANDBOXED, ())) if mode.enabled else ()


def write_if_changed(path: Path, text: str, mode: int) -> bool:
    """Writes *text* to *path* with permission *mode* unless both already match; True when written."""
    try:
        if path.read_text(encoding="utf-8-sig") == text and stat.S_IMODE(path.stat().st_mode) == mode:
            return False
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(path, text, mode=mode)
    return True


__all__ = ["CLI_AGENTS", "canary_path", "chosen", "hermes_shell_dir", "home", "launcher_dir", "profile_path", "write_if_changed"]
