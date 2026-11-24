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
import time
import shutil
from pathlib import Path

from ....kernel.bounded_files import read_small_text
from . import platform
from .layout import agent_profile, profile_path, profiles_dir, write_if_changed
from .permissions import Allowances, Mode, PermissionRequest, Rule, Scope, Settings, allowances
from .places import Places

#: How many hex digits of the profile's sha256 its digest line carries.
DIGEST_CHARS = 16
#: The most of a profile read back (its digest line).
MAX_PROFILE_BYTES = 1024 * 1024
#: The index of an agent's project profiles: ``<canonical folder>\t<file>`` per line.
INDEX = platform.PROJECT_INDEX


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:DIGEST_CHARS]


def digest_of(path: str) -> str:
    """The digest a rendered profile's second line carries ("" when unreadable or none)."""
    text = read_small_text(path, MAX_PROFILE_BYTES) or ""
    lines = text.splitlines()
    marker = lines[1].rsplit("sha256:", 1) if len(lines) > 1 else []
    return marker[1].strip() if len(marker) == 2 else ""


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


def _transient(entry: Path, now: float) -> bool:
    """True for an allow-once profile still waiting (younger than ``ONCE_MINUTES``) or one a running
    launch took (its pid alive): kept by sync; an expired or orphaned one is not."""
    name = entry.name
    if name.endswith(platform.ONCE_SUFFIX):
        return now - entry.stat().st_mtime < platform.ONCE_MINUTES * 60
    if platform.RUN_INFIX in name:
        pid = name.rsplit(platform.RUN_INFIX, 1)[1][: -len(platform.PROFILE_SUFFIX)]
        return pid.isdigit() and _alive(int(pid))
    return False


def _alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)   # windows-footgun: ok (signal 0 only asks whether the process exists)
    except PermissionError:
        return True
    except OSError:
        return False
    return True


def write_once(places: Places, request: PermissionRequest, settings: Settings) -> Path:
    """Allow once, for a profile's permission: the profile the agent's next launch in the request's
    project would pick, with that permission allowed, written beside it as ``…once.sb``. The
    launch that takes it runs in it; every later one is back to the rule (``launchers.pick_profile``)."""
    scope = Scope(agent=request.agent, project=request.project)
    granted = Settings(settings.rules + (Rule(request.permission, Mode.ALLOW, scope),), settings.folders)
    folder = os.path.realpath(scope.project_path()) if request.project else ""
    if folder and folder in projects_for(settings, request.agent):
        target = projects_dir(request.agent) / project_file(folder)
    else:
        target = agent_profile(request.agent)   # no profile of its own for that project: the agent's next launch
    once = target.with_name(target.name[: -len(platform.PROFILE_SUFFIX)] + platform.ONCE_SUFFIX)
    write_if_changed(once, render_signed(places, allowances(granted, request.agent, folder)), 0o644)
    return once


def _sync_projects(places: Places, agent: str, settings: Settings) -> None:
    folder, projects = projects_dir(agent), projects_for(settings, agent)
    if not projects:
        shutil.rmtree(folder, ignore_errors=True)
        return
    wanted = {project_file(project) for project in projects} | {INDEX}
    for project in projects:
        write_if_changed(folder / project_file(project), render_signed(places, allowances(settings, agent, project)), 0o644)
    write_if_changed(folder / INDEX, "".join(f"{project}\t{project_file(project)}\n" for project in projects), 0o644)
    now = time.time()
    for entry in folder.iterdir():
        if entry.is_file() and entry.name not in wanted and not _transient(entry, now):
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
    keep, now = {agent_profile(agent).name for agent in agents} | set(agents), time.time()
    for entry in folder.iterdir():
        if entry.name in keep or (entry.is_file() and _transient(entry, now)):
            continue
        if entry.is_dir():
            shutil.rmtree(entry, ignore_errors=True)
        elif entry.suffix == platform.PROFILE_SUFFIX:
            entry.unlink()


#: The most profiles whose network rules one watch plan carries.
MAX_NETWORK_RULES = 256


def network_rules() -> list[dict[str, object]]:
    """Every rendered profile's per-agent network rules for the root helper (the watch plan's
    ``agents``; Linux only — ``platform.network_rules`` answers None where the sandbox refuses
    them itself), one per digest, at most :data:`MAX_NETWORK_RULES`."""
    folder = profiles_dir()
    paths = [profile_path(), *(sorted(folder.rglob("*" + platform.PROFILE_SUFFIX)) if folder.is_dir() else [])]
    found: dict[str, dict[str, object]] = {}
    for path in paths[:MAX_NETWORK_RULES]:
        rules = platform.network_rules(read_small_text(str(path), MAX_PROFILE_BYTES) or "")
        if rules is not None:
            found.setdefault(rules.digest, rules.plan())
    return list(found.values())


def clear() -> None:
    """Removes every agent's own profile (no agent is sandboxed)."""
    sync(Places((), (), (), (), (), ""), (), Settings())


__all__ = [
    "DIGEST_CHARS",
    "INDEX",
    "clear",
    "digest",
    "digest_of",
    "network_rules",
    "project_file",
    "projects_dir",
    "projects_for",
    "render_signed",
    "sync",
    "write_once",
]
