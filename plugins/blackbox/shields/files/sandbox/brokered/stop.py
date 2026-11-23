"""Stopping a program for a sandboxed agent (sandbox permission ``stop-processes``, ask by default).

Inside the sandbox an agent may signal only what it started itself (the profile's ``(deny
signal)`` + ``same-sandbox``, in the never-list). When it tries to stop a process outside — a dev
server left running from yesterday, a program holding the port it needs — the kill fails, the hook
reads the refusal with the process id (``agent_hooks`` SIGNAL), and this broker takes it from there:
on "allow" Blackbox stops it at once; on "ask" the person is asked, and Blackbox stops it when they
allow it (once, or always for this agent here).

NEVER stopped, whatever the permission says (:func:`never`): process 1 and below, Blackbox itself
(this process, its parent, anything running Blackbox's plugin or from its home), macOS's own
programs, another user's processes, and another AI agent. The check is made again right before
the signal: a process id can be reused.

Usage::

    on_refused(8240, "claude-code", "claude-code:ab12", "/Users/me/shop")
    act(request)      # the person allowed it: stop the process the request names
"""

from __future__ import annotations

import logging
import os

from ..... import audit
from .....kernel import constants
from .. import permissions, platform
from ..layout import CLI_AGENTS

PERMISSION = "stop-processes"
_PLUGIN = os.path.realpath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".."))
logger = logging.getLogger(__name__)


def never(pid: int) -> str:
    """Why *pid* is never stopped for an agent ("" when it may be)."""
    if pid <= 1 or pid in (os.getpid(), os.getppid()):
        return "it is part of macOS or of Blackbox"
    facts = platform.describe(pid)
    if facts is None:
        return "it is not running"
    if facts.uid != getattr(os, "getuid", lambda: -1)():
        return "it belongs to another user"
    if platform.is_system(facts.path):
        return "it is part of macOS"
    own = (_PLUGIN, os.path.realpath(str(constants.blackbox_home())))
    if any(place in facts.args or facts.path.startswith(place) for place in own) or "blackbox" in os.path.basename(facts.path).lower():
        return "it is part of Blackbox"
    commands = {command for each in CLI_AGENTS.values() for command in each} | {"hermes"}
    words = facts.args.split()
    if os.path.basename(facts.path) in commands or (words and os.path.basename(words[0]) in commands):
        return "it is another AI agent"
    return ""


def _name(pid: int) -> str:
    facts = platform.describe(pid)
    return os.path.basename(facts.path) if facts is not None else "a program"


def _stop(pid: int, agent: str, folder: str) -> bool:
    if never(pid):
        return False
    stopped = platform.terminate(pid)
    audit.record_for(audit.SANDBOX_RECORDER, event="brokered_stop", workspace=folder,
                     detail={"pid": pid, "program": _name(pid), "agent": agent, "stopped": stopped})
    return stopped


def on_refused(pid: int, agent: str, instance: str, folder: str) -> str:
    """The agent's kill of *pid* was refused: stop it now (allow), ask the person (ask), or nothing
    (block, or a process that is never stopped). Answers what happened: ``stopped`` / ``asked`` /
    ``refused``."""
    if pid <= 0 or never(pid):
        return "refused"
    mode = permissions.decide(PERMISSION, agent, folder)
    if mode is permissions.Mode.ALLOW:
        return "stopped" if _stop(pid, agent, folder) else "refused"
    if mode is permissions.Mode.ASK and permissions.ask(PERMISSION, agent, instance, folder, f"stop {_name(pid)} (process {pid})", pid):
        return "asked"
    return "refused"


def act(request: permissions.PermissionRequest) -> None:
    """The person allowed stopping the process *request* names: stop it (checked again first)."""
    _stop(request.pid, request.agent, request.project)


__all__ = ["PERMISSION", "act", "never", "on_refused"]
