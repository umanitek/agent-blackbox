"""Every PROFILE of every coding agent — each config home Blackbox must have its hooks in — and
what would keep those hooks from running there.

An agent's hooks live in a config home. The documented default is one folder under the person's
home, but each agent can be pointed at another (``CLAUDE_CONFIG_DIR``, ``CODEX_HOME``,
``GEMINI_CLI_HOME``, ``COPILOT_HOME``): a second account, a work profile, a tool that wraps the
agent. A hook in the default home protects none of those. Blackbox learns of a home three ways —
a hook event names it (the runner reads the variable), a running agent process carries it
(:mod:`.observe`), or the dashboard's own environment does — remembers it, and hooks it.

It also reads the SWITCHES that turn hooks off (``Host.switches``: Claude Code's
``disableAllHooks``, Gemini CLI's ``hooksConfig.enabled``, Codex's ``[features].hooks``) in each
profile and in the projects agents have worked in, and the managed policies that allow only an
organisation's hooks. A switch is REPORTED, with what to change; Blackbox does not flip a
person's own setting by itself.

Usage::

    from . import profiles
    profiles.remember("claude-code", "/Users/me/.claude-work")
    profiles.homes(host)                      # [(folder, default?)…]
    profiles.variant(host, folder)            # a Host whose config is in that folder
    profiles.problems(host, folder, projects) # [Problem…]
"""

from __future__ import annotations

import dataclasses
import json
import os
import threading
import tomllib
from pathlib import Path
from typing import Any, Iterable, Optional

from ..kernel import constants
from ..kernel.agent_hosts import Host
from ..kernel.bounded_files import read_json_object, read_small_text, write_json_object
from .instances.model import Problem

__all__ = ["homes", "lookup", "problems", "remember", "variant"]

MAX_CONFIG_BYTES = 2 * 1024 * 1024
MAX_HOMES_PER_AGENT = 12
MAX_PROJECTS = 40
#: Managed-policy files that can restrict hooks to an organisation's own (read-only for Blackbox).
MANAGED = {
    "claude-code": (("/Library/Application Support/ClaudeCode/managed-settings.json", "allowManagedHooksOnly", True),
                    ("/etc/claude-code/managed-settings.json", "allowManagedHooksOnly", True)),
    "codex": (("/etc/codex/requirements.toml", "allow_managed_hooks_only", True),),
}
_lock = threading.Lock()


def _path() -> Path:
    return constants.blackbox_home() / "agent-hooks" / "profiles.json"


def _default_home(host: Host, home: Path) -> Path:
    """The folder the default config lives in (for ``home_config`` ``settings.json`` under
    ``~/.claude``: ``~/.claude``; for Gemini's ``.gemini/settings.json``: the home itself)."""
    config = host.config_path(home)
    return Path(str(config)[: -len(host.home_config)].rstrip("/")) if host.home_config and str(config).endswith(host.home_config) else config.parent


def remember(agent: str, folder: str) -> bool:
    """Note that *agent* uses the config home *folder* (an absolute, existing folder). True when
    it is new — the caller then hooks it."""
    try:
        resolved = Path(folder).expanduser().resolve()
    except (OSError, RuntimeError):
        return False
    if not folder or not resolved.is_absolute() or not resolved.is_dir():
        return False
    with _lock:
        data = read_json_object(_path()) or {}
        known = [item for item in data.get(agent, []) if isinstance(item, str)]
        if str(resolved) in known:
            return False
        data[agent] = (known + [str(resolved)])[-MAX_HOMES_PER_AGENT:]
        write_json_object(_path(), data, what="the agent profiles list")
    return True


def homes(host: Host, home: Optional[Path] = None) -> list[tuple[Path, bool]]:
    """Every config home of *host*: the default first, then each remembered or environment-named
    one that still exists (``(folder, is_default)``)."""
    home = home or Path.home()
    default = _default_home(host, home)
    found = [(default, True)]
    if not host.home_env:
        return found
    named = [os.environ.get(host.home_env, "")] + [item for item in (read_json_object(_path()) or {}).get(host.id, [])
                                                   if isinstance(item, str)]
    for folder in named:
        path = Path(folder) if folder else None
        if path and path.is_absolute() and path.is_dir() and path.resolve() != default.resolve() and all(path != seen for seen, _ in found):
            found.append((path, False))
    return found


def variant(host: Host, folder: Path, *, default: bool) -> Host:
    """*host* as it is configured in the config home *folder* (the default home: unchanged)."""
    if default or not host.home_config:
        return host
    return dataclasses.replace(host, config=str(folder / host.home_config))


def lookup(data: Any, dotted: str) -> Any:
    """The value at a dotted key of a settings dict (None when any part is missing)."""
    for part in dotted.split("."):
        data = data.get(part) if isinstance(data, dict) else None
    return data


def _read(path: Path) -> Optional[dict[str, Any]]:
    """A JSON or TOML settings file as a dict; None when it is missing, too large or malformed."""
    text = read_small_text(str(path), MAX_CONFIG_BYTES)
    if text is None:
        return None
    try:
        data = tomllib.loads(text) if path.suffix == ".toml" else json.loads(text or "{}")
    except (ValueError, tomllib.TOMLDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _switch_problems(host: Host, folder: Path, where: str) -> list[Problem]:
    out = []
    for name, key, off in host.switches:
        path = folder / name
        data = _read(path)
        if data is not None and lookup(data, key) == off:
            out.append(Problem(host.id, "hooks-off", str(path),
                               f"{key} is {json.dumps(off)} in {where}: {host.name} runs no hooks there, Blackbox's included.",
                               fixable=True))
    return out


def problems(host: Host, folder: Path, projects: Iterable[str] = ()) -> list[Problem]:
    """What keeps Blackbox's hooks from running for *host* in the config home *folder* and in the
    *projects* (folders) its sessions worked in."""
    settings_folder = folder / ".gemini" if host.id == "gemini-cli" else folder
    out = _switch_problems(host, settings_folder, "this profile")
    for path, key, value in MANAGED.get(host.id, ()):
        data = _read(Path(path))
        if data is not None and lookup(data, key) == value:
            out.append(Problem(host.id, "managed-only", path,
                               f"Your organisation's policy ({key}) lets {host.name} run only its own hooks; Blackbox's are skipped."))
    seen = set()
    for project in list(projects)[:MAX_PROJECTS]:
        for relative in host.project_files:
            path = Path(project) / relative
            if path in seen or host.id == "devin":
                continue
            seen.add(path)
            data = _read(path)
            for key, off in dict.fromkeys((key, off) for _name, key, off in host.switches):
                if data is not None and lookup(data, key) == off:
                    out.append(Problem(host.id, "hooks-off", str(path),
                                       f"{key} is {json.dumps(off)} in this project: {host.name} runs no hooks there."))
    return out
