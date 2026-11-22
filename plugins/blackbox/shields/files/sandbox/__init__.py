"""File Shield, Layer 2: AI agents run inside an operating-system sandbox built from the person's
protected list — so a script, a compiled program or an interpreter an agent starts is refused the
same as the agent, with no hook involved (proposal "Process-level file protection", §03).

How an agent gets into it: Blackbox writes a LAUNCHER for each command-line agent the person
chooses (``claude``, ``codex``, ``cursor-agent``, ``gemini``, ``copilot``, ``cline``, ``opencode``)
into ``<BLACKBOX_HOME>/agent-bin`` and puts that folder first on PATH (``kernel.shell_path``); the
launcher starts the real program inside the profile. GUI editors (Cursor, Windsurf) are relaunched
inside it on request (:func:`open_app`, decision D10). An agent started any other way keeps
Layer 1 only (the hooks) — and the dashboard shows which sessions are sandboxed (:func:`proven`).

Choice per agent (decision D7, Amos 2026-11-21: agents keep ``sudo``): a sandbox can not run
setuid programs, so sandboxing is OFF until the person picks agents (``shields.file-shield.
sandboxed``). Adding an agent applies at once; removing one turns protection down and waits for
the person (it is a protecting list).

The profile follows the list: :func:`sync` rewrites it (and the launchers) when the items or the
chosen agents change. A running agent keeps the profile it started with until it is restarted.

The PATH block is watched too (KI-535): when the block Blackbox put in the person's startup files is
gone or changed, :func:`sync` puts it back at once (it only protects more) and records it, so File
Shield alerts the person (:func:`restorations`). Inside the sandbox no startup file can be written
at all; outside, the guard refuses an agent's edit of the block (``detection`` guarded places).

Pattern: **Facade** over :mod:`.places` (the policy) and :mod:`.platform` (one Strategy per OS).

Usage::

    state = sync(mode)          # profile + launchers made to match the setting; answers status()
    status(mode)["agents"]      # [{"id": "claude-code", "sandboxed": True, ...}]
    open_app("cursor")          # "Cursor is starting inside Blackbox's sandbox."
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Any, Optional

from ....detection import blackbox_key_patterns
from ....kernel import agent_hosts, constants, shell_path
from ....kernel.bounded_files import atomic_write
from ...contract import ShieldMode
from .. import mode as mode_module
from ..protect import is_folder
from . import platform
from .places import Places, build

__all__ = ["CLI_AGENTS", "Places", "launcher_dir", "open_app", "policy", "profile_path", "proven", "restorations",
           "status", "sync"]

#: GUI agents are relaunched, not given a command-line launcher.
_GUI_ONLY = frozenset({"windsurf"})
#: Command-line agents and the commands their launchers stand in for.
CLI_AGENTS: dict[str, tuple[str, ...]] = {host.id: tuple(host.commands) for host in agent_hosts.HOSTS
                                          if host.id not in _GUI_ONLY and host.commands}
CANARY_TEXT = "Blackbox agent sandbox canary — a sandboxed agent can not read this file.\n"
#: How many PATH-block restorations are kept for File Shield's alerts.
MAX_RESTORATIONS = 20
_PLUGIN = Path(__file__).resolve().parents[3]


def home() -> Path:
    return constants.blackbox_home() / "sandbox"


def profile_path() -> Path:
    return home() / f"agents{platform.PROFILE_SUFFIX}"


def canary_path() -> Path:
    return home() / "canary"


def launcher_dir() -> Path:
    return constants.blackbox_home() / "agent-bin"


def _on_path_marker() -> Path:
    """Written once Blackbox has put its block on PATH: a block missing AFTER that was removed."""
    return home() / "on-path"


def _restorations_path() -> Path:
    return home() / "path-restored.json"


def chosen(mode: ShieldMode) -> tuple[str, ...]:
    """The agents the person sandboxes (none while File Shield is off)."""
    return tuple(mode.options.get(mode_module.OPT_SANDBOXED, ())) if mode.enabled else ()


def policy(mode: ShieldMode) -> Places:
    """The sandbox's policy for *mode*: the person's items, Blackbox's keys and own places."""
    own = (str(constants.blackbox_home()), str(_PLUGIN))
    startup = [str(Path.home() / name) for name in shell_path.STARTUP_FILES]
    return build(mode_module.protected(mode), blackbox_key_patterns(), own, str(canary_path()), is_folder=is_folder,
                 startup_files=startup)


def _write_if_changed(path: Path, text: str, mode: int) -> bool:
    try:
        if path.read_text(encoding="utf-8-sig") == text and stat.S_IMODE(path.stat().st_mode) == mode:
            return False
    except OSError:
        pass
    path.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(path, text, mode=mode)
    return True


def _sync_launchers(commands: set[str]) -> None:
    folder = launcher_dir()
    if commands:
        for command in sorted(commands):
            _write_if_changed(folder / command, platform.launcher_script(command, str(folder), str(profile_path())), 0o755)
        _keep_on_path(folder)
    else:
        shell_path.remove()
        _on_path_marker().unlink(missing_ok=True)
    if folder.is_dir():
        for entry in folder.iterdir():
            if entry.name not in commands and entry.is_file():
                entry.unlink()


def _keep_on_path(folder: Path) -> None:
    """Puts the block on PATH; when Blackbox had put it there before and it is gone or changed, the
    restoration is recorded for File Shield's alerts (an agent or a program undid it)."""
    marker = _on_path_marker()
    was_on, whole = marker.is_file(), shell_path.intact(folder)
    changed = shell_path.add(folder)
    if changed and was_on and not whole:
        _record_restoration([str(path) for path in changed])
    if not was_on:
        marker.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(marker, "1\n", mode=0o644)


def _record_restoration(files: list[str]) -> None:
    rows = [{"ts": time.time(), "files": files}] + restorations()
    atomic_write(_restorations_path(), json.dumps(rows[:MAX_RESTORATIONS]), mode=0o644)


def restorations() -> list[dict[str, Any]]:
    """The times File Shield put the PATH block back, newest first: ``[{"ts", "files"}]``."""
    try:
        rows = json.loads(_restorations_path().read_text(encoding="utf-8-sig"))
    except (OSError, ValueError):
        return []
    return [row for row in rows if isinstance(row, dict) and isinstance(row.get("files"), list)] if isinstance(rows, list) else []


def sync(mode: Optional[ShieldMode] = None) -> dict[str, Any]:
    """Makes the profile, the canary and the launchers match *mode* (the current setting when
    None); writes only what changed. Answers :func:`status`. Fail-open: nothing here may stop an
    agent or the dashboard."""
    mode = mode or mode_module.current()
    if platform.unavailable() is None and mode.enabled:
        rules = policy(mode)
        text = platform.render(rules)
        _write_if_changed(profile_path(), platform.render(rules, f"sha256:{_digest(text)}"), 0o644)
        _write_if_changed(canary_path(), CANARY_TEXT, 0o644)
        _sync_launchers({command for agent in chosen(mode) for command in CLI_AGENTS.get(agent, ())})
    else:
        _sync_launchers(set())
    return status(mode)


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def status(mode: ShieldMode) -> dict[str, Any]:
    """What the shield's card and Blackbox Desktop show: whether agents can be sandboxed here, which
    agents are, whether their launcher is first on PATH, and the GUI editors on offer."""
    picked = set(chosen(mode))
    folder = launcher_dir()
    return {
        "unavailable": platform.unavailable(),
        "profile": str(profile_path()) if profile_path().is_file() else "",
        "on_path": shell_path.present(),
        "restart_note": "An agent that is already running keeps the protection it started with — restart it after a change.",
        "agents": [{"id": agent, "name": agent_hosts.BY_ID[agent].name, "commands": list(commands),
                    "sandboxed": agent in picked,
                    "launcher": all((folder / command).is_file() for command in commands) if agent in picked else False}
                   for agent, commands in CLI_AGENTS.items()],
        "apps": [{"id": app, "name": name, "installed": os.path.isdir(bundle)} for app, (name, bundle) in platform.APPS.items()],
    }


def open_app(app: str) -> str:
    """Relaunches GUI agent *app* inside the sandbox (D10); raises with a sentence when it can not."""
    if platform.unavailable():
        raise RuntimeError(platform.unavailable())
    current = mode_module.current()
    if not current.enabled:
        raise RuntimeError("Engage File Shield first: the sandbox protects its list.")
    sync(current)
    return platform.open_app(app, str(profile_path()))


def proven(canary: Optional[Path] = None) -> bool:
    """True when THIS process is inside the sandbox: only a sandboxed process is refused the canary
    (unforgeable from inside — an environment variable is not). The hook runner asks the same."""
    try:
        with open(canary or canary_path(), encoding="utf-8-sig") as handle:
            handle.read(1)
        return False
    except PermissionError:
        return True
    except OSError:
        return False
