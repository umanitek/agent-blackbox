"""Every file an agent reads a hooks-off switch from — the ONE list every layer reads (LES-137).

Private security finding ``2026-11-25-hooks-only-an-agent-may-write-a-project-`` (macOS round R8,
High): a hooks-only agent wrote ``{"disableAllHooks": true}`` into a project's
``.claude/settings.json`` (and a sibling project's, and ``settings.local.json``), Codex's
``[features] codex_hooks = false`` into a project ``.codex/config.toml`` and Gemini CLI's hooks
switch into a project ``.gemini/settings.json``. Every write was allowed; the next Claude Code
session started there ran with no hook at all, so Blackbox saw nothing and recorded no session.

A :class:`SwitchFile` is one such file: whose it is, where it lives — under the person's home
(:data:`USER`) or under ANY project folder (:data:`PROJECT`) —, and the settings in it that turn
the agent's hooks off (:attr:`~.Host.switches`, the same data ``agent_hooks.profiles`` reports).
Each layer reads this list for its own part:

* the hook judgement (``detection.hook_switches``) refuses an agent's write, by any route, that
  turns one of these switches OFF in any of these files — and nothing else there (a permission
  rule, a model choice stay the agent's to edit);
* the agent sandbox (``shields.files.sandbox.own_places.hook_configs``) keeps the USER-level files
  closed to writes (:func:`sandbox_closed`). The kernel can not read what a write says, so a file
  the agent itself writes in normal work stays open (:attr:`SwitchFile.agent_writes`), and so do
  the PROJECT-level files: closing them would refuse every harmless edit of a project's settings.
  Those rest on the hook judgement and the back-stop below;
* the hook watch (``agent_hooks.profiles`` and ``agent_hooks.observe.hooks_off``) reports a switch
  found off in any of them, and an agent process that runs with no Blackbox session is a HIGH
  finding naming the agent and its folder (``agent_hooks.tracking``).

Usage::

    for entry in switch_files():                    # SwitchFile("claude-code", ".claude/settings.json", "project", …)
        ...
    matching("/work/app/.claude/settings.local.json")   # the entries that file is
    turned_off(matching(path), {"disableAllHooks": True})   # "disableAllHooks = true"
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Iterable, Mapping

#: Where a switch file lives: under the person's home, or under any project folder.
USER, PROJECT = "user", "project"


@dataclass(frozen=True)
class SwitchFile:
    """One file *agent* reads a hooks-off switch from.

    *path* is relative to the home folder (:data:`USER`) or to a project folder (:data:`PROJECT`);
    *switches* are ``(dotted key, the value that means OFF)``; *agent_writes* is True for a file
    the agent writes itself in its everyday work (a remembered permission, a trusted folder), which
    the kernel sandbox therefore can not close."""

    agent: str
    path: str
    level: str
    switches: tuple[tuple[str, object], ...]
    agent_writes: bool = False


#: The files an agent writes itself. WHY: Claude Code saves "Yes, and don't ask again" into the
#: project's ``.claude/settings.local.json``; Codex records a trusted folder and the chosen model in
#: ``~/.codex/config.toml``. Closing them in the sandbox would break that; the hook judgement still
#: refuses a write that turns their switch off.
_AGENT_WRITES = frozenset({("claude-code", PROJECT, ".claude/settings.local.json"), ("codex", USER, ".codex/config.toml")})


def _entries() -> tuple[SwitchFile, ...]:
    from .. import agent_hosts   # late: this module is imported by the package's own __init__
    out: list[SwitchFile] = []
    for host in agent_hosts.HOSTS:
        if not host.switches:
            continue
        folder = os.path.dirname(host.config)
        by_file: dict[str, list[tuple[str, object]]] = {}
        for name, key, off in host.switches:
            by_file.setdefault(name, []).append((key, off))
        for name, switches in by_file.items():
            path = os.path.join(folder, name)
            out.append(SwitchFile(host.id, path, USER, tuple(switches), (host.id, USER, path) in _AGENT_WRITES))
        for relative in host.project_files:
            switches = tuple(dict.fromkeys(pair for pairs in by_file.values() for pair in pairs))
            out.append(SwitchFile(host.id, relative, PROJECT, switches, (host.id, PROJECT, relative) in _AGENT_WRITES))
    return tuple(out)


_ALL: tuple[SwitchFile, ...] = ()


def switch_files() -> tuple[SwitchFile, ...]:
    """Every switch file of every agent (user-level and project-level), worked out once."""
    global _ALL
    if not _ALL:
        _ALL = _entries()
    return _ALL


def user_paths(home: str) -> list[str]:
    """The user-level switch files under *home*, absolute."""
    return [os.path.join(home, entry.path) for entry in switch_files() if entry.level == USER]


def project_patterns() -> list[str]:
    """The project-level switch files in ANY folder, as absolute ``fnmatch`` patterns
    (``/*/.claude/settings.json``: an ``fnmatch`` ``*`` crosses ``/``)."""
    return [os.sep + "*" + os.sep + entry.path for entry in switch_files() if entry.level == PROJECT]


def sandbox_closed(home: str) -> list[str]:
    """The switch files the kernel sandbox keeps closed to writes: user-level, not written by the
    agent itself (see the module doc for why the others stay open)."""
    return [os.path.join(home, entry.path) for entry in switch_files() if entry.level == USER and not entry.agent_writes]


def matching(path: str, home: str = "") -> tuple[SwitchFile, ...]:
    """The entries the file at absolute *path* is: a user-level one under *home* (default the
    person's), or a project-level one in any folder."""
    home = (home or os.path.expanduser("~")).rstrip(os.sep)
    path = os.path.normpath(path)
    return tuple(entry for entry in switch_files()
                 if (entry.level == USER and path == os.path.join(home, entry.path))
                 or (entry.level == PROJECT and path.endswith(os.sep + entry.path)))


def lookup(data: Any, dotted: str) -> Any:
    """The value at a dotted key of a settings dict (None when any part is missing)."""
    for part in dotted.split("."):
        data = data.get(part) if isinstance(data, Mapping) else None
    return data


def turned_off(entries: Iterable[SwitchFile], data: Any) -> str:
    """The first switch of *entries* that settings *data* (a parsed file) sets OFF, as
    ``key = value``; "" when none is."""
    for entry in entries:
        for key, off in entry.switches:
            value = lookup(data, key)
            if value == off and type(value) is type(off):
                return f"{key} = {json.dumps(off)}"
    return ""


__all__ = ["PROJECT", "USER", "SwitchFile", "lookup", "matching", "project_patterns", "sandbox_closed", "switch_files",
           "turned_off", "user_paths"]
