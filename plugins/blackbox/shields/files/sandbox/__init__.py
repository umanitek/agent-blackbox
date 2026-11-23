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
    open_app("cursor")          # "Cursor is running inside Blackbox's sandbox."
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional

from ....detection import blackbox_key_patterns
from ....kernel import addons, agent_hosts, constants, persistence_places, shell_path
from ....kernel.bounded_files import atomic_write
from ...contract import OPTION_NOT_INSTALLED, OPTION_SUPPORTED, OPTION_UNAVAILABLE, ShieldMode
from .. import mode as mode_module
from ..protect import is_folder
from . import addon_places, defaults, own_places, packages, platform
from .places import Places, build, canonical

__all__ = ["CLI_AGENTS", "HERMES_LAUNCHER_ENV", "HERMES_SHELLS", "HermesCover", "Places", "enter_hermes_process", "enter_hermes_session", "hermes_shell_dir", "launcher_dir", "offer",
           "open_app", "policy", "profile_path", "protection", "proven", "restorations", "self_protected_files", "status", "sync"]

#: GUI agents are relaunched, not given a command-line launcher.
_GUI_ONLY = frozenset({"windsurf"})
#: Command-line agents and the commands their launchers stand in for.
CLI_AGENTS: dict[str, tuple[str, ...]] = {host.id: tuple(host.commands) for host in agent_hosts.HOSTS
                                          if host.id not in _GUI_ONLY and host.commands}
CANARY_TEXT = "Blackbox agent sandbox canary — a sandboxed agent can not read this file.\n"
#: What the person is told before opening an editor protected (KI-534: its own sandbox can not
#: start inside Blackbox's, so it runs with that one off).
APP_NOTE = ("Quit the editor first. Inside Blackbox's sandbox the editor runs with its own web-page sandbox off "
            "(two sandboxes can not nest): Blackbox's covers the whole editor and your protected items instead.")
#: How many PATH-block restorations are kept for File Shield's alerts.
MAX_RESTORATIONS = 20
_PLUGIN = Path(__file__).resolve().parents[3]
logger = logging.getLogger(__name__)


def home() -> Path:
    return constants.blackbox_home() / "sandbox"


def profile_path() -> Path:
    return home() / f"agents{platform.PROFILE_SUFFIX}"


def canary_path() -> Path:
    return home() / "canary"


def launcher_dir() -> Path:
    return constants.blackbox_home() / "agent-bin"


#: The shells the Hermes agent's terminal tool may start (it looks ``bash`` up on its own PATH).
HERMES_SHELLS = ("bash", "sh", "zsh")

#: Hermes's interpreter-launcher hook point (carried patch in ``tools/code_kernel.py``): a JSON
#: argv array put before the Python its ``execute_code`` tool starts, read from Hermes's own process.
HERMES_LAUNCHER_ENV = "HERMES_EXECUTE_CODE_LAUNCHER"
#: The launcher Blackbox writes beside the Hermes shells for ``execute_code``'s interpreter.
HERMES_CODE_LAUNCHER = "execute-code"


def hermes_shell_dir() -> Path:
    """Where the Hermes agent's sandboxed shells live — put first on the Hermes process's OWN PATH
    (:func:`enter_hermes_process`), never on the person's."""
    return home() / "hermes-shell"


def _on_path_marker() -> Path:
    """Written once Blackbox has put its block on PATH: a block missing AFTER that was removed."""
    return home() / "on-path"


def _restorations_path() -> Path:
    return home() / "path-restored.json"


def chosen(mode: ShieldMode) -> tuple[str, ...]:
    """The agents the person sandboxes (none while File Shield is off)."""
    return tuple(mode.options.get(mode_module.OPT_SANDBOXED, ())) if mode.enabled else ()


def policy(mode: ShieldMode) -> Places:
    """The policy for *mode*: the person's items, Blackbox's keys, own and add-on places, the OS's startup places."""
    own = (str(constants.blackbox_home()), str(_PLUGIN), *addon_places.of(_PLUGIN.parent))
    hooks = own_places.hook_configs()
    startup = persistence_places.shell_startup_files(str(Path.home())) + hooks   # the hook judgement reads the same list
    holders = sorted({os.path.dirname(path) for path in hooks} - {str(Path.home())})
    return build(mode_module.protected(mode), blackbox_key_patterns(), own, str(canary_path()), is_folder=is_folder,
                 startup_files=startup, keep_in_place=holders, no_write_globs=[addons.manifest_pattern(str(_PLUGIN.parent))],
                 startup=platform.startup_places(str(Path.home())))


def self_protected_files(mode: ShieldMode) -> tuple[str, ...]:
    """The files the sandbox keeps closed to writes for Blackbox's sake — every agent's hook config
    and the shell startup files (canonical paths) — while any agent is sandboxed; () otherwise. The
    helper watches them for the kernel's refusals too, so a refusal of an agent rewriting its OWN
    hook config is recorded as self-protection (KI-581); every add-on folder too, anything in it (KI-600)."""
    if not chosen(mode) or platform.unavailable() is not None:
        return ()
    return policy(mode).no_write_files + tuple(canonical(place) for place in addon_places.of(_PLUGIN.parent))


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
    # Only a block that is gone or changed is a restoration: lines the person adds around a whole
    # block change nothing (add() leaves the file alone), and Blackbox's own older block is an upgrade.
    was_on, whole, upgrade = marker.is_file(), shell_path.intact(folder), shell_path.upgradable(folder)
    changed = shell_path.add(folder)
    if changed and was_on and not whole and not upgrade:
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
        platform.refresh_tools(str(launcher_dir()), bool(chosen(mode)))   # the setuid-free ps for the sandboxed PATH (KI-589)
        packages.install_shim(launcher_dir() / platform.TOOLS_FOLDER)        # brew installs through Blackbox (KI-593)
        _sync_launchers({command for agent in chosen(mode) for command in CLI_AGENTS.get(agent, ())})
        _sync_hermes_shells(agent_hosts.HERMES_ID in chosen(mode))
    else:
        _sync_launchers(set())
        _sync_hermes_shells(False)
        platform.refresh_tools(str(launcher_dir()), False)
    return status(mode)


def _sync_hermes_shells(wanted: bool) -> None:
    folder = hermes_shell_dir()
    for shell in HERMES_SHELLS:
        if wanted:
            _write_if_changed(folder / shell, platform.shell_shim(shell, str(folder), str(profile_path()), str(launcher_dir())), 0o755)
        else:
            (folder / shell).unlink(missing_ok=True)
    if wanted:
        _write_if_changed(_hermes_code_launcher(), platform.command_shim(str(profile_path()), str(launcher_dir())), 0o755)
    else:
        _hermes_code_launcher().unlink(missing_ok=True)


def _hermes_code_launcher() -> Path:
    return hermes_shell_dir() / HERMES_CODE_LAUNCHER


def _hermes_has_launcher_hook() -> bool:
    """True when the Hermes Blackbox runs in reads :data:`HERMES_LAUNCHER_ENV` (the carried patch);
    a Hermes without it starts execute_code's Python directly, whatever the setting says."""
    try:
        from tools import code_kernel   # the Hermes host's module, not Blackbox's
    except ImportError:
        return False
    return getattr(code_kernel, "INTERPRETER_LAUNCHER_ENV", None) == HERMES_LAUNCHER_ENV


@dataclass(frozen=True)
class HermesCover:
    """What of the Hermes agent runs inside the sandbox: its terminal tool's ``shells``, its
    ``execute_code`` interpreter, and ``note`` — why execute_code is not covered when it is not."""
    shells: bool = False
    execute_code: bool = False
    note: str = ""


def enter_hermes_process(mode: Optional[ShieldMode] = None, environ: Optional[dict[str, str]] = None) -> HermesCover:
    """Puts the sandboxed shells first on THIS (the Hermes agent's) process PATH and sets Hermes's
    interpreter-launcher hook point (:data:`HERMES_LAUNCHER_ENV`) to Blackbox's launcher when the
    person sandboxes the Hermes agent; takes both away when not. So every shell its terminal tool
    starts and every ``execute_code`` Python run inside the sandbox, while Hermes itself (and
    Blackbox inside it) do not. A launcher value someone else set is left alone. Answers what is
    covered (:class:`HermesCover`)."""
    mode = mode or mode_module.current()
    env = os.environ if environ is None else environ
    folder = str(hermes_shell_dir())
    parts = [part for part in env.get("PATH", "").split(os.pathsep) if part and part != folder]
    wanted = (agent_hosts.HERMES_ID in chosen(mode) and platform.unavailable() is None
              and all((hermes_shell_dir() / shell).is_file() for shell in HERMES_SHELLS))
    env["PATH"] = os.pathsep.join(([folder] if wanted else []) + parts)
    ours = json.dumps([str(_hermes_code_launcher())])
    code, note = wanted and _hermes_code_launcher().is_file(), _code_note(wanted)
    if code:
        env[HERMES_LAUNCHER_ENV] = ours
    elif env.get(HERMES_LAUNCHER_ENV) == ours:
        del env[HERMES_LAUNCHER_ENV]
    return HermesCover(shells=wanted, execute_code=code and not note, note=note)


def _code_note(shells: bool) -> str:
    """Why the Hermes agent's execute_code stays on hooks, or "" when it is covered."""
    if not shells:
        return "not picked for the sandbox"
    if not _hermes_code_launcher().is_file():
        return f"Blackbox's execute_code launcher is missing ({_hermes_code_launcher()})"
    if not _hermes_has_launcher_hook():
        return f"this Hermes has no {HERMES_LAUNCHER_ENV} hook point, so it starts execute_code's Python directly"
    return ""


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


def status(mode: ShieldMode) -> dict[str, Any]:
    """What the shield's card and a companion app show: whether agents can be sandboxed here, which
    agents are (each with its protection level, :func:`protection`), whether their launcher is first
    on PATH, which ways of starting an agent reach it (``coverage``), and the GUI editors on offer."""
    picked = set(chosen(mode))
    folder = launcher_dir()
    return {
        "unavailable": platform.unavailable(),
        "profile": str(profile_path()) if profile_path().is_file() else "",
        "on_path": shell_path.present(),
        "restart_note": "An agent that is already running keeps the protection it started with — restart it after a change.",
        "agents": [{"id": agent, "name": agent_hosts.BY_ID[agent].name, "commands": list(commands),
                    "sandboxed": agent in picked,
                    "launcher": all((folder / command).is_file() for command in commands) if agent in picked else False,
                    **protection(agent, agent in picked)}
                   for agent, commands in CLI_AGENTS.items()]
                  + [{"id": agent_hosts.HERMES_ID, "name": agent_hosts.HERMES_NAME, "commands": ["hermes"],
                      "sandboxed": agent_hosts.HERMES_ID in picked,
                      "launcher": all((hermes_shell_dir() / shell).is_file() for shell in HERMES_SHELLS),
                      **protection(agent_hosts.HERMES_ID, agent_hosts.HERMES_ID in picked)}],
        "coverage": shell_path.coverage(folder),
        "apps": [{"id": app, "name": name, "installed": os.path.isdir(bundle), "note": APP_NOTE}
                 for app, (name, bundle) in platform.APPS.items()],
    }


def enter_hermes_session() -> HermesCover:
    """At a Hermes session start: the profile, shells and launcher made current (:func:`sync`), then
    the Hermes process's PATH and launcher set (:func:`enter_hermes_process`). Fail-open: nothing
    covered on any error, logged."""
    try:
        sync()
        return enter_hermes_process()
    except Exception:   # the agent always runs; the reason is logged
        logger.warning("blackbox: could not put the Hermes agent's shells in the sandbox", exc_info=True)
        return HermesCover(note="Blackbox could not set up the sandbox for this session (see the log)")


#: What each protection level means, in the words the dashboard shows.
SANDBOXED = agent_hosts.PROTECTION_SANDBOXED
HOOKS_ONLY = agent_hosts.PROTECTION_HOOKS
SHELLS_ONLY = agent_hosts.PROTECTION_SHELLS
_HERMES_NOTE = ("its terminal tool's shells and its execute_code Python run inside the sandbox; its file tools run in "
                "Hermes itself and stay on hooks")
_HERMES_SHELLS_NOTE = "its terminal tool's shells run inside the sandbox; its execute_code tool stays on hooks: "
_LAUNCH_NOTE = "when started from a shell that has Blackbox's launchers first on PATH (see coverage)"
NOT_INSTALLED_NOTE = "not installed on this machine yet — pick it now and it starts sandboxed once installed"


def offer(agent: str) -> tuple[str, str]:
    """``(status, note)`` of *agent* as a sandbox choice on this machine: ``unavailable`` with
    the reason when this OS can not sandbox agents, ``not installed`` when its program is not
    here (still pickable), otherwise ``supported``. The Hermes agent is the program Blackbox
    runs in, so it is always installed."""
    reason = platform.unavailable()
    if reason:
        return OPTION_UNAVAILABLE, reason
    host = agent_hosts.BY_ID.get(agent)
    if host is not None and not host.installed(Path.home()):
        return OPTION_NOT_INSTALLED, NOT_INSTALLED_NOTE
    return OPTION_SUPPORTED, ""


def protection(agent: str, picked: bool) -> dict[str, str]:
    """``{"protection", "protection_note"}`` for *agent*: kernel-enforced only when it is picked
    and this OS can sandbox it; otherwise hooks only, said plainly."""
    if not picked or platform.unavailable() is not None:
        return {"protection": HOOKS_ONLY, "protection_note": platform.unavailable() or "not picked for the sandbox"}
    if agent == agent_hosts.HERMES_ID:
        note = _code_note(True)
        return {"protection": SHELLS_ONLY, "protection_note": _HERMES_SHELLS_NOTE + note} if note else \
            {"protection": SANDBOXED, "protection_note": _HERMES_NOTE}
    return {"protection": SANDBOXED, "protection_note": _LAUNCH_NOTE}


def open_app(app: str) -> str:
    """Relaunches GUI agent *app* inside the sandbox (D10); raises with a sentence when it can not."""
    if platform.unavailable():
        raise RuntimeError(platform.unavailable())
    current = mode_module.current()
    if not current.enabled:
        raise RuntimeError("Engage File Shield first: the sandbox protects its list.")
    sync(current)
    return platform.open_app(app, str(profile_path()), log=str(home() / f"{app}.log"))


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
