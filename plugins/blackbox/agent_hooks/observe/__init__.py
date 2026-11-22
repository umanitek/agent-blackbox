"""Which coding-agent processes run on this machine right now — whether or not Blackbox has a
hook in them. READ-ONLY: the observer lists and classifies; it never signals or stops a process.

WHY: a hook only reports the instances that run it. An agent started in a way that skips hooks
(Claude Code ``--bare``), from a config home Blackbox has not hooked yet (``CLAUDE_CONFIG_DIR``,
``CODEX_HOME``…), or before its hooks were trusted would otherwise be invisible. The observer
shows it as "running, not protected" and tells :mod:`..profiles` about the config home it uses.

Usage::

    from . import observe
    table = observe.read_table()            # {pid: Proc}
    observe.running(table)                  # [Running] — one per agent process tree root
    observe.agent_of(table, hook_parent_pid)  # the agent process a hook was run by
    observe.read_users()                    # {pid: (real uid, effective uid)}
    observe.descendants(table, pid)         # every process started (at any depth) by *pid*
"""

from __future__ import annotations

import re
import shlex
import time
from dataclasses import dataclass
from pathlib import PurePath
from typing import Mapping, Optional

from ...kernel.agent_hosts import HOSTS, Host
from ..instances.model import Running
from . import platform

__all__ = ["Proc", "agent_of", "classify", "descendants", "read_table", "read_users", "running"]

_LINE = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\w{3} +\w{3} +\d+ +[\d:]+ +\d{4})\s+(.*)$")
#: argv words that say an agent runs without a person at the keyboard, per agent.
_HEADLESS = {"claude-code": ("-p", "--print"), "gemini-cli": ("-p", "--prompt"), "codex": ("exec", "e"),
             "copilot-cli": ("-p", "--prompt"), "cursor": ("-p", "--print"), "opencode": ("run",), "devin": ("-p",)}
_SERVER = {"codex": ("app-server", "mcp-server", "mcp"), "opencode": ("serve",), "claude-code": ("mcp",)}
#: Runs whose hooks the agent itself skips (documented): the reason shown to the person.
_SKIPS = {("claude-code", "--bare"): "started with --bare, which skips every hook"}
#: Runtimes that run an agent's script: the SECOND word is then the program.
_RUNTIMES = ("node", "bun", "deno", "python", "python3", "tsx")
MAX_ANCESTORS = 12


@dataclass(frozen=True)
class Proc:
    pid: int
    ppid: int
    started: float
    command: str


def read_table() -> dict[int, Proc]:
    """Every process on this machine, by pid ({} when the list cannot be read)."""
    table = {}
    for line in platform.process_table().splitlines():
        match = _LINE.match(line)
        if not match:
            continue
        try:
            started = time.mktime(time.strptime(" ".join(match.group(3).split()), "%a %b %d %H:%M:%S %Y"))
        except ValueError:
            started = 0.0
        table[int(match.group(1))] = Proc(int(match.group(1)), int(match.group(2)), started, match.group(4)[:4000])
    return table


def _words(command: str) -> list[str]:
    try:
        return shlex.split(command)[:40]
    except ValueError:
        return command.split()[:40]


def classify(command: str) -> Optional[Host]:
    """The agent a command line is, judged by its program (or the script a runtime runs): the
    first two words' file names against each agent's ``programs`` — never a substring match, so
    ``vim claude.md`` is not Claude Code."""
    words = _words(command)
    if not words:
        return None
    names = {PurePath(words[0]).name}
    if names & set(_RUNTIMES) and len(words) > 1:
        names = {PurePath(words[1]).name}
    for host in HOSTS:
        if names & set(host.programs):
            return host
    return None


def _launch(host: Host, words: list[str]) -> str:
    rest = words[1:]
    if any(word in _SERVER.get(host.id, ()) for word in rest[:2]):
        return "sdk"
    if any(word in _HEADLESS.get(host.id, ()) for word in rest):
        return "headless"
    return "ide" if PurePath(words[0]).name in ("Cursor", "Windsurf") else "interactive"


def _profile(host: Host, pid: int) -> str:
    """The config home *pid* was started with (``Host.home_env``), "" for the default one. The
    kernel's own record is asked first (a path with a space stays whole); ``ps``'s words are the
    fallback."""
    if not host.home_env:
        return ""
    exact = platform.process_variable(pid, host.home_env)
    if exact:
        return exact[:500]
    match = re.search(rf"(?:^|\s){re.escape(host.home_env)}=(\S+)", platform.process_environment(pid))
    return match.group(1)[:500] if match else ""


def running(table: Mapping[int, Proc]) -> list[Running]:
    """One :class:`Running` per agent process whose parent is not the same agent (an agent's own
    helper processes are part of it, not more instances)."""
    out = []
    for proc in table.values():
        host = classify(proc.command)
        if host is None:
            continue
        parent = table.get(proc.ppid)
        if parent is not None and classify(parent.command) is host:
            continue
        words = _words(proc.command)
        skipped = next((reason for (agent, flag), reason in _SKIPS.items() if agent == host.id and flag in words), "")
        out.append(Running(proc.pid, proc.ppid, host.id, _launch(host, words), _profile(host, proc.pid), skipped, proc.started))
    return out


def agent_of(table: Mapping[int, Proc], pid: int, agent: str) -> int:
    """The pid of the *agent* process that *pid* (a hook's parent) belongs to: the nearest
    ancestor (or *pid* itself) that is that agent, climbing on only while the parent is the same
    agent too (an agent's launcher and its program are ONE instance, as in :func:`running`); 0
    when none is (the hook then has no process to follow).

    WHY the climb stops at the first other process: an agent started by another run of the same
    agent (a ``claude -p`` that a Claude Code session runs as a tool) is its OWN instance — the
    outermost one would give two sessions one process (found in the KI-548 process-tree test)."""
    current, top = table.get(pid), 0
    for _ in range(MAX_ANCESTORS):
        if current is None:
            break
        host = classify(current.command)
        if host is not None and host.id == agent:
            top = current.pid
        elif top:
            break   # the chain of this agent's processes ended
        current = table.get(current.ppid)
    return top


MAX_DESCENDANTS = 2000


def read_users() -> dict[int, tuple[int, int]]:
    """``{pid: (real uid, effective uid)}`` for every process ({} when it cannot be read)."""
    users = {}
    for line in platform.process_users().splitlines():
        words = line.split()
        if len(words) == 3 and all(word.lstrip("-").isdigit() for word in words):
            users[int(words[0])] = (int(words[1]), int(words[2]))
    return users


def descendants(table: Mapping[int, Proc], pid: int) -> list[Proc]:
    """Every process *pid* started, at any depth (bounded), nearest first; *pid* itself is not in it."""
    children: dict[int, list[Proc]] = {}
    for proc in table.values():
        children.setdefault(proc.ppid, []).append(proc)
    found, queue, seen = [], [pid], {pid}
    while queue and len(found) < MAX_DESCENDANTS:
        for child in children.get(queue.pop(0), []):
            if child.pid not in seen:
                seen.add(child.pid)
                found.append(child)
                queue.append(child.pid)
    return found
