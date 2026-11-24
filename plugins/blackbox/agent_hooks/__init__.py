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
    agent_hooks.answer_event(body)               # one event from the runner: answered now, recorded after
    agent_hooks.record_event(body)               # …or answered and recorded before returning
"""

from __future__ import annotations

import json
import shlex
import shutil
import sys
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Optional

from ..kernel import constants
from ..kernel.bounded_files import atomic_write
from .. import audit
from ..kernel.config import load_blackbox_config
from . import owners, process_facts, profiles, prompt_text, tracking, versions
from .protect import config_edit, hook_watch, own_files
from .protect import recorder
from .protect.judge_here import JUDGE_HERE_FILE
from .protect.sandbox_errors import RefusalSeen, on_sandbox_refusal
from .protect.sandbox_run import answer_hidden_sockets_with
from .protect.events import answer_event, note_error, read_state, record_event, write_state
from ..kernel.agent_hosts import BY_ID, HOSTS, Host

__all__ = ["KINDS", "AgentRow", "RefusalSeen", "answer_event", "answer_hidden_sockets_with", "hooked_agents", "keep_hooks", "note_error", "on_sandbox_refusal",
           "owners", "present", "process_facts", "prompt_text", "record_event", "remove_all", "rows", "set_protection",
           "settle", "sweep", "tracking", "versions"]

def settle(timeout: float = 5.0) -> bool:
    """Wait until every answered hook event is recorded (tests; the dashboard before it stops)."""
    return recorder.settle(timeout)


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


#: The runner and the modules it imports, copied together.
RUNNER_FILES = ("runner.py", "answers.py", "identity.py", "judge_here.py", "tool_shapes.py")


def _runner() -> Path:
    """The runner every hook names: a copy in Blackbox's data folder (with its sibling module),
    refreshed when it changes, so a moved plugin folder never breaks an agent's hook."""
    for name in RUNNER_FILES:
        source = Path(__file__).with_name("protect") / name
        target = constants.blackbox_home() / "agent-hooks" / name
        text = source.read_text(encoding="utf-8-sig")
        if not target.exists() or target.read_text(encoding="utf-8-sig") != text:
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(source, target)
    _write_judge_here()
    return constants.blackbox_home() / "agent-hooks" / RUNNER_FILES[0]


def _write_judge_here() -> None:
    """Tell the runner where this plugin and its homes are, so it can judge a call itself while
    the dashboard does not answer (``protect.runner.judge_here``)."""
    target = constants.blackbox_home() / "agent-hooks" / JUDGE_HERE_FILE
    text = json.dumps({"plugin": str(Path(__file__).resolve().parent.parent), "hermes_home": str(constants.hermes_root()),
                       "blackbox_home": str(constants.blackbox_home())}, indent=1) + "\n"
    if not target.exists() or target.read_text(encoding="utf-8-sig") != text:
        atomic_write(target, text)


#: The launcher every hook names instead of a Python path (:func:`_python`).
LAUNCHER_NAME = "python"


def _python() -> Path:
    """A launcher in Blackbox's data folder that runs the runner with a Python that exists.

    WHY: hooks named ``sys.executable`` — Hermes's VERSIONED environment
    (``~/.hermes/installs/<id>/environments/<id>/venv/bin/python3``). An update that prunes that
    environment would leave every agent's hook pointing at a missing Python (fail-open: the agents
    run unprotected) until the next sweep (E2E 2026-11-21). The runner needs only the standard
    library, so ANY Python of this Hermes will do: the launcher tries the current one, then the
    newest Hermes environment still there, and lets the agent go on (exit 0) when none is."""
    target = constants.blackbox_home() / "agent-hooks" / LAUNCHER_NAME
    hermes_envs = shlex.quote(str(constants.hermes_root())) + "/installs/*/environments/*/venv/bin/python3"
    text = (
        "#!/bin/sh\n"
        "# Blackbox: the Python that runs coding agents' hooks. Rewritten by Blackbox; safe to delete.\n"
        f"for py in {shlex.quote(sys.executable)} $(ls -t {hermes_envs} 2>/dev/null); do\n"
        '    [ -x "$py" ] && exec "$py" "$@"\n'
        "done\n"
        "exit 0   # no Python left: the agent goes on (fail-open)\n"
    )
    if not target.exists() or target.read_text(encoding="utf-8-sig") != text:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        target.chmod(0o755)
    return target


def _invocations(host: Host) -> dict[str, tuple[list[str], str]]:
    url = f"http://127.0.0.1:{load_blackbox_config().dashboard_port}"
    runner = str(_runner())
    python = str(_python())
    out = {}
    for agent_event, kind in host.events.items():
        argv = [python, runner, host.id, kind, url]
        out[agent_event] = (argv, " ".join(shlex.quote(part) for part in argv))
    return out


def _editor(host: Host):
    return own_files if host.style in _OWN_FILE_STYLES else config_edit


def _variants(host: Host) -> list[Host]:
    """*host* once per config home it has on this machine: the default one first, then every
    other PROFILE Blackbox learned of (``profiles.homes``) — each must carry the hooks."""
    return [profiles.variant(host, folder, default=default) for folder, default in profiles.homes(host, _home())]


def install(host: Host) -> config_edit.EditResult:
    """Install Blackbox's hooks for *host* (one config home) and remember what was written, so the
    hook watch (:func:`keep_hooks`) tells Blackbox's own install from a change made outside it."""
    invocations = _invocations(host)
    if host.style in _OWN_FILE_STYLES:
        result = own_files.install(host, _home(), invocations)
    else:
        result = config_edit.install(host, _home(), {event: command for event, (_argv, command) in invocations.items()})
    _remember(host)
    return result


def _watch_key(host: Host) -> str:
    return f"{host.id}:{host.config_path(_home())}"


def _remember(host: Host) -> None:
    hook_watch.remember(_watch_key(host), hook_watch.fingerprint(host, _home(), _editor(host).installed_commands(host, _home())))


def keep_hooks() -> list[dict[str, Any]]:
    """The hook watch, one look (cheap: a few small files per agent): for every agent the person
    protects, Blackbox's hook that is gone or changed since Blackbox installed it is recorded as a
    HIGH finding and put back where the path is safe (``protect.hook_watch``; a file that is not
    Blackbox's in its place is moved aside, kept). A hook installed before this watch existed is
    adopted as it is; an agent the person removed from this machine (no folder, no command) is
    forgotten, never re-created. Answers one ``{kind, restored, lost}`` per change found."""
    state = read_state()["agents"]
    done = []
    for host in HOSTS:
        if state.get(host.id, {}).get("disabled"):
            continue
        if not host.installed(_home()):
            for variant in _variants(host):
                if hook_watch.known(_watch_key(variant)):
                    hook_watch.remember(_watch_key(variant), {})
            continue
        for variant in _variants(host):
            key = _watch_key(variant)
            now = hook_watch.fingerprint(variant, _home(), _editor(variant).installed_commands(variant, _home()))
            if not hook_watch.known(key):
                if now:
                    hook_watch.remember(key, now)   # adopted: installed by a Blackbox before this watch
                continue
            lost = hook_watch.changed(key, now)
            if not lost:
                continue
            restored, moved = False, []
            if hook_watch.safe(_home(), lost):
                moved = hook_watch.quarantine(lost)
                restored = install(variant).ok and not hook_watch.changed(key, hook_watch.fingerprint(
                    variant, _home(), _editor(variant).installed_commands(variant, _home())))
            if not restored:
                hook_watch.remember(key, now)   # said once; the next change is new again
            audit.record_for(host.id, event="agent_hook_changed", findings=[hook_watch.finding(host.name, lost, restored, moved)],
                             detail={"restored": restored, "moved_aside": moved, "decision": "flag"})
            done.append({"kind": host.id, "restored": restored, "lost": lost})
    return done


def _runnable(host: Host, commands: list[str]) -> bool:
    if host.style in _OWN_FILE_STYLES:
        return own_files.runnable(commands)
    paths = [part for command in commands for part in shlex.split(command)[:2]]
    return own_files.runnable(paths)


def _invalid(host: Host) -> list[str]:
    """Why the agent's own loader would not run Blackbox's entries (own-file styles: never)."""
    return [] if host.style in _OWN_FILE_STYLES else config_edit.invalid_entries(host, _home())


def _state_of(host: Host, hooked: bool, runnable: bool, record: dict[str, Any], invalid: tuple[str, ...] = ()) -> tuple[str, str]:
    last, last_error = record.get("last_event") or 0, record.get("last_error") or 0
    if record.get("disabled"):
        return "off", "You stopped protecting it."
    if not hooked:
        return "available", "Found on this Mac; Blackbox's hooks are not installed."
    if not runnable:
        return "degraded", "The hook cannot run: the Python or the runner it names is gone. Protect it again."
    if invalid:
        return "degraded", f"{host.name} would not run Blackbox's hook as written ({invalid[0]}). Protect it again."
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
        name, detail = _state_of(host, bool(commands), _runnable(host, commands), record, tuple(_invalid(host)))
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
    results = [install(variant) if enabled else _uninstall(variant) for variant in _variants(host)]
    result = next((item for item in results if not item.ok), results[0])   # the default home's, or the first failure
    if result.ok:
        state = read_state()
        state["agents"].setdefault(agent_id, {})["disabled"] = not enabled
        write_state(state)
    return {"ok": result.ok, "kind": agent_id, "target": result.path, "enabled": enabled, "note": result.error}


def _uninstall(host: Host) -> config_edit.EditResult:
    """Remove Blackbox's hooks for *host* and forget them (the hook watch no longer expects them)."""
    result = _editor(host).uninstall(host, _home())
    hook_watch.remember(_watch_key(host), {})
    return result


def present() -> frozenset[str]:
    """The ids of the coding agents on this machine now (cheap: a few file checks and PATH
    lookups) — what tells the dashboard's sweep that a new agent appeared."""
    return frozenset(host.id for host in HOSTS if host.installed(_home()))


def sweep() -> list[dict[str, Any]]:
    """Hook every agent found that is not switched off, and repair hooks whose paths moved or that
    the agent's own loader would not run as written (a time limit in the wrong unit — KI-570).
    Runs only while "Protect new agents automatically" is on (the same opt-in as ``attach``)."""
    if not load_blackbox_config().auto_attach:
        return []
    state = read_state()["agents"]
    done = []
    for host in HOSTS:
        if state.get(host.id, {}).get("disabled") or not host.installed(_home()):
            continue
        wanted = [command for _argv, command in _invocations(host).values()]
        for variant in _variants(host):
            current = _editor(variant).installed_commands(variant, _home())
            if variant.style in _OWN_FILE_STYLES or sorted(current) != sorted(wanted) or _invalid(variant):
                done.append(asdict(install(variant)) | {"kind": host.id})
    return done


def hooked_agents() -> list[str]:
    """The names of the coding agents whose config holds Blackbox's hooks now."""
    return [host.name for host in HOSTS if any(_editor(variant).installed_commands(variant, _home()) for variant in _variants(host))]


def remove_all() -> list[dict[str, Any]]:
    """Take Blackbox's hooks out of every coding agent's config (the person's own hooks stay) —
    what ``blackbox uninstall`` does, so no agent is left running a hook whose runner is deleted.
    Returns one ``{kind, ok, target, note}`` per agent that had Blackbox's hooks."""
    done = []
    for host in HOSTS:
        for variant in _variants(host):
            if not _editor(variant).installed_commands(variant, _home()):
                continue
            result = _uninstall(variant)
            done.append({"kind": host.id, "name": host.name, "ok": result.ok, "target": result.path, "note": result.error})
    return done
