"""One Seatbelt profile per sandboxed agent, and one per project that has its own rules: the shared
policy (the person's items, Blackbox's own places, the startup places) with that agent's
permissions on top, the never-list last.

Each agent's launcher (and the Hermes agent's shells) start it in ITS profile, so allowing Docker
for Claude Code leaves Codex refused. ``agents.sb`` stays the everywhere profile (no agent rules):
what the card names and what an editor opened without its own rules runs in.

Projects: for every project folder a rule names (for this agent or for every agent), the agent
gets ``profiles/<agent>/<key>.sb`` and a line ``<canonical folder>\t<key>.sb`` in
``profiles/<agent>/projects.idx``. The launcher picks the LONGEST folder that holds the working
folder (``pwd -P``: the kernel's spelling, LES-105); no index or no match → the agent's own
profile. Everything here is in Blackbox's home, closed to writes inside the sandbox.

Usage::

    sync(places, ("claude-code", "hermes"), settings)   # profiles/claude-code.sb, profiles/claude-code/…
    render_signed(places, allowances)                   # profile text with its digest line
"""

from __future__ import annotations

import hashlib
import os
import shutil
from pathlib import Path

from . import platform
from .layout import agent_profile, profiles_dir, write_if_changed
from .permissions import Allowances, Settings, allowances
from .places import Places

#: How many hex digits of the profile's sha256 its digest line carries.
DIGEST_CHARS = 16
#: The index of an agent's project profiles: ``<canonical folder>\t<file>`` per line.
INDEX = platform.PROJECT_INDEX


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:DIGEST_CHARS]


def render_signed(places: Places, allowed: Allowances = Allowances()) -> str:
    """The profile text for *places* and *allowed*, its digest line naming the text without it."""
    text = platform.render(places, allowances=allowed)
    return platform.render(places, f"sha256:{digest(text)}", allowed)


def projects_dir(agent: str) -> Path:
    """Where *agent*'s project profiles and their index live (the profile's name without suffix)."""
    return profiles_dir() / agent


def projects_for(settings: Settings, agent: str) -> tuple[str, ...]:
    """The canonical project folders a rule names for *agent* (or for every agent)."""
    named = [each.scope for each in (*settings.rules, *settings.folders) if each.scope.project and each.scope.agent in ("", agent)]
    return tuple(dict.fromkeys(os.path.realpath(scope.project_path()) for scope in named))


def project_file(folder: str) -> str:
    """The file name of the project profile for canonical *folder*."""
    return f"{digest(folder)}{platform.PROFILE_SUFFIX}"


def _sync_projects(places: Places, agent: str, settings: Settings) -> None:
    folder, projects = projects_dir(agent), projects_for(settings, agent)
    if not projects:
        shutil.rmtree(folder, ignore_errors=True)
        return
    wanted = {project_file(project) for project in projects} | {INDEX}
    for project in projects:
        write_if_changed(folder / project_file(project), render_signed(places, allowances(settings, agent, project)), 0o644)
    write_if_changed(folder / INDEX, "".join(f"{project}\t{project_file(project)}\n" for project in projects), 0o644)
    for entry in folder.iterdir():
        if entry.is_file() and entry.name not in wanted:
            entry.unlink()


def sync(places: Places, agents: tuple[str, ...], settings: Settings) -> None:
    """Writes each of *agents*' own profile and project profiles (only what changed) and removes
    every other agent's."""
    for agent in agents:
        write_if_changed(agent_profile(agent), render_signed(places, allowances(settings, agent)), 0o644)
        _sync_projects(places, agent, settings)
    folder = profiles_dir()
    if not folder.is_dir():
        return
    keep = {agent_profile(agent).name for agent in agents} | set(agents)
    for entry in folder.iterdir():
        if entry.name in keep:
            continue
        if entry.is_dir():
            shutil.rmtree(entry, ignore_errors=True)
        elif entry.suffix == platform.PROFILE_SUFFIX:
            entry.unlink()


def clear() -> None:
    """Removes every agent's own profile (no agent is sandboxed)."""
    sync(Places((), (), (), (), (), ""), (), Settings())


__all__ = ["DIGEST_CHARS", "INDEX", "clear", "digest", "project_file", "projects_dir", "projects_for",
           "render_signed", "sync"]
