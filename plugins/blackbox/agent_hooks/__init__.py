"""Agent Hooks: Blackbox protects the coding agents on this machine through their own hooks.

Claude Code, Codex, Cursor, Gemini CLI, GitHub Copilot CLI, Windsurf, Cline and OpenCode each run
a command (or plugin) before and after every tool call. Blackbox installs ONE small runner there
(:mod:`.runner`) that asks the local dashboard, which judges the call with the same guard a Hermes
agent gets (``guard.tool_call_verdict``) and records the event under the agent's name
(:mod:`.events`). Adapter pattern: each agent is a data record (:mod:`.hosts`) plus a payload and
answer mapping in the runner; the judgement exists once.

Honest states (:func:`rows`): ``available`` (the agent is here, not hooked), ``hooked`` (Blackbox's
hooks are in its config), ``trust-required`` (hooked, but the agent asks its user to trust new
hooks and none has run yet), ``connected`` (a hook event arrived lately — the only state that
proves protection), ``degraded`` (the hook cannot run, or its events fail), ``off`` (the user
stopped protecting it). Fail-open everywhere: an agent is never made unusable.

Usage::

    from plugins.blackbox import agent_hooks
    agent_hooks.rows()                           # what /api/agent-hooks lists
    agent_hooks.set_protection("cursor", True)   # install (False: remove and keep it off)
    agent_hooks.sweep()                          # hook every agent found, unless switched off
    agent_hooks.record_event(body)               # one event from the runner
"""

from __future__ import annotations

import shlex
import shutil
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from ..kernel import constants
from ..kernel.config import load_blackbox_config
from .protect import config_edit, own_files
from .protect.events import note_error, read_state, record_event, write_state
from .hosts import BY_ID, HOSTS, Host

__all__ = ["KINDS", "AgentRow", "note_error", "record_event", "rows", "set_protection", "sweep"]

#: The agent ids this module answers for (``/api/agent-hooks/protection`` accepts these).
KINDS = tuple(BY_ID)
#: A hook event this recent makes the agent "connected".
CONNECTED_SECONDS = 15 * 60
_OWN_FILE_STYLES = ("own-json", "scripts", "plugin")


@dataclass(frozen=True)
class AgentRow:
    """One agent as the Agents page shows it."""

    id: str
    name: str
    state: str
    detail: str
    config: str
    last_event: Optional[float]
    events: int
    sessions: list[dict[str, Any]] = field(default_factory=list)
    trust_note: str = ""


def _home() -> Path:
    return Path.home()


def _runner() -> Path:
    """The runner every hook names: a copy in Blackbox's data folder, refreshed when it changes,
    so a moved plugin folder never breaks an agent's hook."""
    source = Path(__file__).with_name("protect") / "runner.py"
    target = constants.blackbox_home() / "agent-hooks" / "runner.py"
    text = source.read_text(encoding="utf-8-sig")
    if not target.exists() or target.read_text(encoding="utf-8-sig") != text:
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    return target


def _invocations(host: Host) -> dict[str, tuple[list[str], str]]:
    url = f"http://127.0.0.1:{load_blackbox_config().dashboard_port}"
    runner = str(_runner())
    out = {}
    for agent_event, kind in host.events.items():
        argv = [sys.executable, runner, host.id, kind, url]
        out[agent_event] = (argv, " ".join(shlex.quote(part) for part in argv))
    return out


def _editor(host: Host):
    return own_files if host.style in _OWN_FILE_STYLES else config_edit


def install(host: Host) -> config_edit.EditResult:
    invocations = _invocations(host)
    if host.style in _OWN_FILE_STYLES:
        return own_files.install(host, _home(), invocations)
    return config_edit.install(host, _home(), {event: command for event, (_argv, command) in invocations.items()})


def _runnable(host: Host, commands: list[str]) -> bool:
    if host.style in _OWN_FILE_STYLES:
        return own_files.runnable(commands)
    paths = [part for command in commands for part in shlex.split(command)[:2]]
    return own_files.runnable(paths)


def _state_of(host: Host, hooked: bool, runnable: bool, record: dict[str, Any]) -> tuple[str, str]:
    last, last_error = record.get("last_event") or 0, record.get("last_error") or 0
    if record.get("disabled"):
        return "off", "You stopped protecting it."
    if not hooked:
        return "available", "Found on this Mac; Blackbox's hooks are not installed."
    if not runnable:
        return "degraded", "The hook cannot run: the Python or the runner it names is gone. Protect it again."
    if last_error > last:
        return "degraded", "Its latest hook event could not be checked."
    if last and time.time() - last < CONNECTED_SECONDS:
        return "connected", "Blackbox checked its actions in the last 15 minutes."
    if not last and host.trust_note:
        return "trust-required", host.trust_note
    return "hooked", "Hooks installed; protection is proven by its first checked action."


def rows() -> list[AgentRow]:
    """Every agent found on this machine or hooked by Blackbox, with its honest state."""
    state = read_state()["agents"]
    out = []
    for host in HOSTS:
        commands = _editor(host).installed_commands(host, _home())
        record = state.get(host.id, {})
        if not host.installed(_home()) and not commands and not record:
            continue
        name, detail = _state_of(host, bool(commands), _runnable(host, commands), record)
        sessions = sorted(({"id": key, **value} for key, value in (record.get("sessions") or {}).items()),
                          key=lambda row: row.get("last", 0), reverse=True)
        out.append(AgentRow(host.id, host.name, name, detail, str(host.config_path(_home())), record.get("last_event"),
                            int(record.get("events", 0)), sessions[:20], host.trust_note))
    return out


def set_protection(agent_id: str, enabled: bool) -> dict[str, Any]:
    """Protect *agent_id* (install its hooks) or stop (remove them and keep them off)."""
    host = BY_ID.get(agent_id)
    if host is None:
        return {"ok": False, "kind": agent_id, "error": "unknown agent"}
    result = install(host) if enabled else _editor(host).uninstall(host, _home())
    if result.ok:
        state = read_state()
        state["agents"].setdefault(agent_id, {})["disabled"] = not enabled
        write_state(state)
    return {"ok": result.ok, "kind": agent_id, "target": result.path, "enabled": enabled, "note": result.error}


def sweep() -> list[dict[str, Any]]:
    """Hook every agent found that is not switched off, and repair hooks whose paths moved.
    Runs only while "Protect new agents automatically" is on (the same opt-in as ``attach``)."""
    if not load_blackbox_config().auto_attach:
        return []
    state = read_state()["agents"]
    done = []
    for host in HOSTS:
        if state.get(host.id, {}).get("disabled") or not host.installed(_home()):
            continue
        current = _editor(host).installed_commands(host, _home())
        wanted = [command for _argv, command in _invocations(host).values()]
        if host.style in _OWN_FILE_STYLES or sorted(current) != sorted(wanted):
            done.append(asdict(install(host)) | {"kind": host.id})
    return done
