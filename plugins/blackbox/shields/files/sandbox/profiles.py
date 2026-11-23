"""One Seatbelt profile per sandboxed agent: the shared policy (the person's items, Blackbox's own
places, the startup places) with that agent's permissions on top, the never-list last.

Each agent's launcher (and the Hermes agent's shells) start it in ITS profile, so allowing Docker
for Claude Code leaves Codex refused. ``agents.sb`` stays the everywhere profile (no agent rules):
what the card names and what an editor opened without its own rules runs in.

Usage::

    sync(places, ("claude-code", "hermes"), settings)   # <sandbox>/profiles/claude-code.sb, hermes.sb
    render_signed(places, allowances)                   # profile text with its digest line
"""

from __future__ import annotations

import hashlib

from . import platform
from .layout import agent_profile, profiles_dir, write_if_changed
from .permissions import Allowances, Settings, allowances
from .places import Places

#: How many hex digits of the profile's sha256 its digest line carries.
DIGEST_CHARS = 16


def digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:DIGEST_CHARS]


def render_signed(places: Places, allowed: Allowances = Allowances()) -> str:
    """The profile text for *places* and *allowed*, its digest line naming the text without it."""
    text = platform.render(places, allowances=allowed)
    return platform.render(places, f"sha256:{digest(text)}", allowed)


def sync(places: Places, agents: tuple[str, ...], settings: Settings) -> None:
    """Writes each of *agents*' own profile (only what changed) and removes every other one."""
    wanted = {agent_profile(agent).name for agent in agents}
    for agent in agents:
        write_if_changed(agent_profile(agent), render_signed(places, allowances(settings, agent)), 0o644)
    folder = profiles_dir()
    if folder.is_dir():
        for entry in folder.iterdir():
            if entry.is_file() and entry.suffix == platform.PROFILE_SUFFIX and entry.name not in wanted:
                entry.unlink()


def clear() -> None:
    """Removes every agent's own profile (no agent is sandboxed)."""
    sync(Places((), (), (), (), (), ""), (), Settings())


__all__ = ["DIGEST_CHARS", "clear", "digest", "render_signed", "sync"]
