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
    observe.launch_of(table, agent_pid)     # "headless" / "interactive" / "ide" / "sdk"
    observe.read_users()                    # {pid: (real uid, effective uid)}
    observe.descendants(table, pid)         # every process started (at any depth) by *pid*
"""

from __future__ import annotations

import re
import shlex
import time
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path, PurePath
from typing import Mapping, Optional

from ...kernel.agent_hosts import HOSTS, Host
from .. import permission_risks
from ..instances.model import Running
from . import platform

__all__ = ["Proc", "agent_of", "classify", "descendants", "launch_of", "read_table", "read_users", "running"]

_LINE = re.compile(r"^\s*(\d+)\s+(\d+)\s+(\w{3} +\w{3} +\d+ +[\d:]+ +\d{4})\s+(.*)$")
#: argv words that say an agent runs without a person at the keyboard, per agent.
_HEADLESS = {"claude-code": ("-p", "--print"), "gemini-cli": ("-p", "--prompt"), "codex": ("exec", "e"),
             "copilot-cli": ("-p", "--prompt"), "cursor": ("-p", "--print"), "opencode": ("run",), "devin": ("-p",)}
_SERVER = {"codex": ("app-server", "mcp-server", "mcp"), "opencode": ("serve",), "claude-code": ("mcp",)}
#: Runs whose hooks the agent itself skips (documented): the reason shown to the person.
_SKIPS = {("claude-code", "--bare"): "started with --bare, which skips every hook"}
#: Runtimes that run an agent's script — the script (or ``-m`` module) is then the program. Any
#: spelling a runtime is installed under: ``python3.14``, macOS's framework ``Python``, ``nodejs``.
_RUNTIME = re.compile(r"^(?:node(?:js)?|bun|deno|tsx|pypy3?|[Pp]ython(?:\d+(?:\.\d+)*)?)$")
#: A runtime's options that run inline code (no program), and those that take a value.
_INLINE = frozenset({"-c", "-e", "--eval", "-p", "--print"})
_VALUED = frozenset({"-X", "-W", "-r", "--require", "--import", "--loader", "--env-file", "--config"})
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


def _split(words: list[str]) -> tuple[str, list[str]]:
    """``(program, its arguments)`` of a command line: argv[0], or — for a runtime — the script
    it runs (past the runtime's own options) or the module after ``-m``. ``("", [])`` when a
    runtime runs inline code (``-c`` / ``-e``) or nothing."""
    if not words or not _RUNTIME.match(PurePath(words[0]).name):
        return (words[0], words[1:]) if words else ("", [])
    skip = False
    for position, word in enumerate(words[1:], start=1):
        if skip:
            skip = False
        elif word == "-m" and position + 1 < len(words):
            return words[position + 1], words[position + 2:]
        elif word in _INLINE:
            return "", []
        elif word in _VALUED:
            skip = True   # the option's value is not the script
        elif not word.startswith("-"):
            return word, words[position + 1:]
    return "", []


@lru_cache(maxsize=2048)
def _real_path(program: str) -> str:
    """*program*'s real file (links followed); "" when it is not a path to a file."""
    if "/" not in program:
        return ""
    try:
        return str(Path(program).resolve())
    except (OSError, RuntimeError):
        return ""


def classify(command: str) -> Optional[Host]:
    """The agent a command line is, judged by its PROGRAM (:func:`_split`: argv[0], or the script
    or module a runtime runs): its file name — as run and as its real file — against each
    agent's ``programs``, and its real path against each agent's ``packages`` (an npm-installed
    agent's ``…/node_modules/@openai/codex/bin/codex.js``). Never a substring of the line, so
    ``vim claude.md`` is not Claude Code."""
    program, _args = _split(_words(command))
    if not program:
        return None
    real = _real_path(program)
    names = {PurePath(program).name, PurePath(real).name if real else ""} - {""}
    for host in HOSTS:
        if names & set(host.programs) or any(f"/node_modules/{package}/" in real for package in host.packages):
            return host
    return None


def _launch(host: Host, words: list[str]) -> str:
    program, rest = _split(words)
    if any(word in _SERVER.get(host.id, ()) for word in rest[:2]):
        return "sdk"
    if any(word in _HEADLESS.get(host.id, ()) for word in rest):
        return "headless"
    return "ide" if PurePath(program).name in ("Cursor", "Windsurf") else "interactive"


def launch_of(table: Mapping[int, Proc], pid: int) -> str:
    """How the agent process *pid* was started, read from its command line: ``headless``
    (``claude -p``, ``codex exec``, ``gemini -p``, ``opencode run``…), ``sdk`` (``codex
    app-server``, ``opencode serve``), ``ide`` (the Cursor / Windsurf app) or ``interactive``;
    "" when *pid* is not an agent process in *table*."""
    proc = table.get(pid)
    host = classify(proc.command) if proc is not None else None
    return _launch(host, _words(proc.command)) if host is not None and proc is not None else ""


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
        out.append(Running(proc.pid, proc.ppid, host.id, _launch(host, words), _profile(host, proc.pid), skipped, proc.started,
                           tuple(permission_risks.from_command(host.id, _split(words)[1]))))
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
