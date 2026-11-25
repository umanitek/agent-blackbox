"""Blackbox's own files the agent sandbox keeps closed to writes, worked out from the agent catalogue
(no OS calls here).

* :func:`hook_configs` — every coding agent's hook config and Blackbox's own hook files in the
  person's home: closed to writes inside the sandbox, so a program an agent starts can not take
  Blackbox's hook out of its own agent's config.
* :func:`settings_files` / :func:`settings_globs` — Hermes' ``config.yaml`` and ``.env`` (main home
  and every profile), which hold EVERY Blackbox setting (design review 2026-11-23, P0: a
  sandboxed script the hook can not read could have written ``file-shield: enabled: false``,
  emptied the sandboxed list or switched Block mode off). Never written, renamed or removed.
* :func:`holders` — every folder above Blackbox's own places, those files and every hook config:
  never renamed or removed (``mv ~/.hermes ~/.h2`` would walk Blackbox's home out from under the
  profile, and the launcher would fall back to hooks only; ``mv ~/Documents/Cline`` would walk
  Blackbox's Cline hooks away and let a planted one take their place — Linux round L4).

Usage::

    hook_configs()          # ["/Users/me/.claude/settings.json", …]
    settings_files()        # ["/Users/me/.hermes/config.yaml", "/Users/me/.hermes/.env"]
    holders(["/Users/me/.hermes/blackbox"])   # ["/Users/me/.hermes", "/Users/me", "/Users"]
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterable

from ....kernel import agent_hosts, constants

#: Hermes' files that hold Blackbox's settings (its entry in config.yaml) or its environment.
SETTINGS_NAMES = ("config.yaml", ".env")


def hook_configs() -> list[str]:
    """Every coding agent's hook config and Blackbox's own hook files in the default home: closed
    to writes inside the sandbox, so a program an agent starts can not take Blackbox's hook out of
    its own agent's config (hook-layer refusals stop the agent's own tools; this stops a script)."""
    user = Path.home()
    out = []
    for host in agent_hosts.HOSTS:
        target = host.config_path(user)
        out += [str(target / event) for event in host.events] if host.style == "scripts" else [str(target)]
        out += [str(path) for path in host.companion_paths(user)]
    # The user-level files that switch an agent's hooks off (security finding 2026-11-25, R8): the
    # ONE list the hook judgement and the hook watch read too (LES-137).
    out += agent_hosts.hook_switches.sandbox_closed(str(user))
    return list(dict.fromkeys(out))


def settings_files() -> list[str]:
    """Hermes' own settings files in its main home (:data:`SETTINGS_NAMES`)."""
    root = constants.hermes_root()
    return [str(root / name) for name in SETTINGS_NAMES]


def settings_globs() -> list[str]:
    """The same files in every Hermes profile, existing or not (``<root>/profiles/*/config.yaml``)."""
    root = constants.hermes_root()
    return [str(root / "profiles" / "*" / name) for name in SETTINGS_NAMES]


def holders(places: Iterable[str]) -> list[str]:
    """Every folder above each of *places* (the root folder aside), nearest first, without repeats."""
    out: list[str] = []
    for place in places:
        parent = os.path.dirname(os.path.normpath(os.path.expanduser(place)))
        while parent and parent != os.sep:
            out.append(parent)
            parent = os.path.dirname(parent)
    return list(dict.fromkeys(out))


__all__ = ["SETTINGS_NAMES", "holders", "hook_configs", "settings_files", "settings_globs"]
