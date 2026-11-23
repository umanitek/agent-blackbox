"""What the agent sandbox's card and a companion app show: whether agents can be sandboxed here,
which are, each one's protection level, and the GUI editors on offer.

Usage::

    status(mode)["agents"]          # [{"id": "claude-code", "sandboxed": True, ...}]
    offer("codex")                  # ("supported", "")
    protection("hermes", True)      # {"protection": "sandboxed", "protection_note": "..."}
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from ....kernel import agent_hosts, shell_path
from ...contract import OPTION_NOT_INSTALLED, OPTION_SUPPORTED, OPTION_UNAVAILABLE, ShieldMode
from . import platform
from .hermes import HERMES_SHELLS, code_note
from .layout import CLI_AGENTS, chosen, hermes_shell_dir, launcher_dir, profile_path

#: What the person is told before opening an editor protected (KI-534: its own sandbox can not
#: start inside Blackbox's, so it runs with that one off).
APP_NOTE = ("Quit the editor first. Inside Blackbox's sandbox the editor runs with its own web-page sandbox off "
            "(two sandboxes can not nest): Blackbox's covers the whole editor and your protected items instead.")

#: What each protection level means, in the words the dashboard shows.
SANDBOXED = agent_hosts.PROTECTION_SANDBOXED
HOOKS_ONLY = agent_hosts.PROTECTION_HOOKS
SHELLS_ONLY = agent_hosts.PROTECTION_SHELLS
_HERMES_NOTE = ("its terminal tool's shells and its execute_code Python run inside the sandbox; its file tools run in "
                "Hermes itself and stay on hooks")
_HERMES_SHELLS_NOTE = "its terminal tool's shells run inside the sandbox; its execute_code tool stays on hooks: "
_LAUNCH_NOTE = "when started from a shell that has Blackbox's launchers first on PATH (see coverage)"
NOT_INSTALLED_NOTE = "not installed on this machine yet — pick it now and it starts sandboxed once installed"


def status(mode: ShieldMode) -> dict[str, Any]:
    """What the shield's card and a companion app show: whether agents can be sandboxed here, which
    agents are (each with its protection level, :func:`protection`), whether their launcher is first
    on PATH, which ways of starting an agent reach it (``coverage``), and the GUI editors on offer."""
    picked = set(chosen(mode))
    folder = launcher_dir()
    return {
        "unavailable": platform.unavailable(),
        "profile": str(profile_path()) if profile_path().is_file() else "",
        "on_path": shell_path.present(),
        "restart_note": "An agent that is already running keeps the protection it started with — restart it after a change.",
        "agents": [{"id": agent, "name": agent_hosts.BY_ID[agent].name, "commands": list(commands),
                    "sandboxed": agent in picked,
                    "launcher": all((folder / command).is_file() for command in commands) if agent in picked else False,
                    **protection(agent, agent in picked)}
                   for agent, commands in CLI_AGENTS.items()]
                  + [{"id": agent_hosts.HERMES_ID, "name": agent_hosts.HERMES_NAME, "commands": ["hermes"],
                      "sandboxed": agent_hosts.HERMES_ID in picked,
                      "launcher": all((hermes_shell_dir() / shell).is_file() for shell in HERMES_SHELLS),
                      **protection(agent_hosts.HERMES_ID, agent_hosts.HERMES_ID in picked)}],
        "coverage": shell_path.coverage(folder),
        "apps": [{"id": app, "name": name, "installed": os.path.isdir(bundle), "note": APP_NOTE}
                 for app, (name, bundle) in platform.APPS.items()],
    }


def offer(agent: str) -> tuple[str, str]:
    """``(status, note)`` of *agent* as a sandbox choice on this machine: ``unavailable`` with
    the reason when this OS can not sandbox agents, ``not installed`` when its program is not
    here (still pickable), otherwise ``supported``. The Hermes agent is the program Blackbox
    runs in, so it is always installed."""
    reason = platform.unavailable()
    if reason:
        return OPTION_UNAVAILABLE, reason
    host = agent_hosts.BY_ID.get(agent)
    if host is not None and not host.installed(Path.home()):
        return OPTION_NOT_INSTALLED, NOT_INSTALLED_NOTE
    return OPTION_SUPPORTED, ""


def protection(agent: str, picked: bool) -> dict[str, str]:
    """``{"protection", "protection_note"}`` for *agent*: kernel-enforced only when it is picked
    and this OS can sandbox it; otherwise hooks only, said plainly."""
    if not picked or platform.unavailable() is not None:
        return {"protection": HOOKS_ONLY, "protection_note": platform.unavailable() or "not picked for the sandbox"}
    if agent == agent_hosts.HERMES_ID:
        note = code_note(True)
        return {"protection": SHELLS_ONLY, "protection_note": _HERMES_SHELLS_NOTE + note} if note else \
            {"protection": SANDBOXED, "protection_note": _HERMES_NOTE}
    return {"protection": SANDBOXED, "protection_note": _LAUNCH_NOTE}


__all__ = ["APP_NOTE", "HOOKS_ONLY", "NOT_INSTALLED_NOTE", "SANDBOXED", "SHELLS_ONLY", "offer", "protection", "status"]
