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

import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Optional

from ....detection import blackbox_key_patterns
from ....kernel import addons, agent_hosts, constants, persistence_places, shell_path
from ....kernel.bounded_files import atomic_write
from ...contract import ShieldMode
from ...shield_api import RunningAgent
from .. import mode as mode_module
from ..protect import is_folder
from . import addon_places, brokered, defaults, layout, own_places, packages, permissions, platform, profiles
from .hermes import HERMES_CODE_LAUNCHER, HERMES_LAUNCHER_ENV, HERMES_SHELLS, HermesCover, enter_hermes_process, sync_shells
from .layout import CLI_AGENTS, agent_profile, canary_path, chosen, hermes_shell_dir, home, launcher_dir, profile_path, write_if_changed
from .places import Places, build, canonical
from .status import HOOKS_ONLY, NOT_INSTALLED_NOTE, SANDBOXED, SHELLS_ONLY, offer, protection, status

__all__ = ["CLI_AGENTS", "HELPER_REPORTS_REFUSALS", "HERMES_CODE_LAUNCHER", "HERMES_LAUNCHER_ENV", "HERMES_SHELLS", "HOOKS_ONLY",
           "NOT_INSTALLED_NOTE", "SANDBOXED", "SHELLS_ONLY", "HermesCover", "Places", "act_on", "brokered",
           "canary_path", "chosen", "enter_hermes_process", "enter_hermes_session", "hermes_shell_dir", "home",
           "launcher_dir", "network_rules", "offer", "on_refusal", "open_app", "policy", "profile_path", "protection", "proven",
           "remove_placeholders", "restorations", "run_hides_socket", "self_protected_files", "status", "sync", "unavailable"]


def unavailable() -> Optional[str]:
    """Why agents can not be sandboxed on this machine (the platform's reason), or None."""
    return platform.unavailable()


CANARY_TEXT = "Blackbox agent sandbox canary — a sandboxed agent can not read this file.\n"
#: How many PATH-block restorations are kept for File Shield's alerts.
MAX_RESTORATIONS = 20
_PLUGIN = Path(__file__).resolve().parents[3]
logger = logging.getLogger(__name__)


def _on_path_marker() -> Path:
    """Written once Blackbox has put its block on PATH: a block missing AFTER that was removed."""
    return home() / "on-path"


def _restorations_path() -> Path:
    return home() / "path-restored.json"


def policy(mode: ShieldMode) -> Places:
    """The policy for *mode*: the person's items, Blackbox's keys, own and add-on places, the OS's startup places."""
    own = (str(constants.blackbox_home()), str(_PLUGIN), *addon_places.of(_PLUGIN.parent))
    hooks, settings = own_places.hook_configs(), own_places.settings_files()   # Blackbox's settings live in Hermes' config (P0)
    startup = persistence_places.shell_startup_files(str(Path.home())) + hooks + settings   # the hook judgement reads the same list
    # Every folder above every hook place, not only the one holding it (security finding
    # 2026-11-24, Linux round L4: with only ~/Documents/Cline/Hooks pinned, ``mv ~/Documents/Cline``
    # walked Blackbox's Cline hooks away and a planted TaskStart took their place; ``mv
    # ~/.config/opencode`` did the same to the OpenCode plugin). The ONE list every layer reads (LES-137).
    holders = own_places.holders([*hooks, *own, *settings])
    return build(mode_module.protected(mode), blackbox_key_patterns(), own, str(canary_path()), is_folder=is_folder,
                 startup_files=startup, keep_in_place=holders,
                 no_write_globs=[addons.manifest_pattern(str(_PLUGIN.parent)), *own_places.settings_globs()],
                 startup=platform.startup_places(str(Path.home())))


def self_protected_files(mode: ShieldMode) -> tuple[str, ...]:
    """The files the sandbox keeps closed to writes for Blackbox's sake — every agent's hook config
    and the shell startup files (canonical paths) — while any agent is sandboxed; () otherwise. The
    helper watches them for the kernel's refusals too, so a refusal of an agent rewriting its OWN
    hook config is recorded as self-protection (KI-581); every add-on folder too, anything in it (KI-600)."""
    if not chosen(mode) or platform.unavailable() is not None:
        return ()
    return policy(mode).no_write_files + tuple(canonical(place) for place in addon_places.of(_PLUGIN.parent))


def _sync_launchers(commands: dict[str, str]) -> None:
    """One launcher per command in *commands* (``{command: agent}``), each starting its agent in
    the agent's own profile; every other launcher removed."""
    folder = launcher_dir()
    if commands:
        for command, agent in sorted(commands.items()):
            write_if_changed(folder / command, platform.launcher_script(command, str(folder), str(agent_profile(agent))), 0o755)
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


def remove_placeholders() -> list[str]:
    """Uninstall: the empty startup-place placeholders the sandbox made (Linux, F1) taken back —
    only those still empty; answers what went (KI-677)."""
    return platform.unprepare(home())


def sync(mode: Optional[ShieldMode] = None) -> dict[str, Any]:
    """Makes the profile, the canary and the launchers match *mode* (the current setting when
    None); writes only what changed. Answers :func:`status`. Fail-open: nothing here may stop an
    agent or the dashboard."""
    mode = mode or mode_module.current()
    if platform.unavailable() is None and mode.enabled:
        rules = policy(mode)
        settings = permissions.current()
        write_if_changed(profile_path(), profiles.render_signed(rules, permissions.allowances(settings)), 0o644)
        profiles.sync(rules, chosen(mode), settings)   # each agent's own permissions on top (sandbox permissions)
        write_if_changed(canary_path(), CANARY_TEXT, 0o644)
        platform.prepare(rules, str(Path.home()), home())   # Linux: placeholders for missing startup places (F1)
        platform.refresh_tools(str(launcher_dir()), bool(chosen(mode)))   # the setuid-free ps for the sandboxed PATH (KI-589)
        packages.install_shim(launcher_dir() / platform.TOOLS_FOLDER)        # brew installs through Blackbox (KI-593)
        brokered.install_shims(launcher_dir() / platform.TOOLS_FOLDER)       # open links / apps through Blackbox
        _sync_launchers({command: agent for agent in chosen(mode) for command in CLI_AGENTS.get(agent, ())})
        sync_shells(agent_hosts.HERMES_ID in chosen(mode))
    else:
        _sync_launchers({})
        profiles.clear()
        sync_shells(False)
        platform.refresh_tools(str(launcher_dir()), False)
    return status(mode)


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


def network_rules() -> list[dict[str, Any]]:
    """The per-agent network rules the root helper enforces for sandboxed agents (Linux), for the
    watch plan (``profiles.network_rules``)."""
    return profiles.network_rules()


def act_on(request: permissions.PermissionRequest) -> None:
    """The person allowed *request* and Blackbox must act: stop the process it names
    (``stop-processes``), or write the one-launch profile the agent's next start takes
    (``profiles.write_once``; its own rules apply again after that launch)."""
    if request.permission == brokered.stop.PERMISSION:
        brokered.stop.act(request)
    else:
        profiles.write_once(policy(mode_module.current()), request, permissions.current())


#: What the person is told about a running agent whose permissions changed since it started.
RESTART_NOTE = "still runs with the permissions it started with; restart it (or stop it) to use the new ones"


def stale_runs(runs: list[RunningAgent]) -> list[RunningAgent]:
    """The *runs* whose profile changed since they started: the file they name — only one inside
    Blackbox's profiles folder is read (the name came from the agent's own hook) — now carries
    another digest, or is gone."""
    root = os.path.realpath(str(layout.profiles_dir()))
    stale = []
    for run in runs:
        path, _, started = run.profile.rpartition("#")
        real = os.path.realpath(path) if path.startswith("/") else ""
        if not real.startswith(root + "/") or not started:
            continue
        if profiles.digest_of(real) != started:
            stale.append(run)
    return stale


def run_hides_socket(profile_ref: str, socket: str) -> bool:
    """True when the profile a sandboxed run STARTED with hides *socket* (an engine's socket on
    "ask" or "block"). *profile_ref* is the run's ``<file>#<digest>`` from its own hook; only a file
    inside Blackbox's profiles folder that still carries that digest is read — the launcher applied
    exactly that text. WHY (KI-685, Linux round L4): the dashboard judged the socket by lstat()
    OUTSIDE the sandbox, where it is the live socket, so Docker on "ask" never asked."""
    path, _, started = profile_ref.rpartition("#")
    real = os.path.realpath(path) if path.startswith("/") else ""
    if not started or not real.startswith(os.path.realpath(str(layout.profiles_dir())) + "/") or profiles.digest_of(real) != started:
        return False
    return platform.hides_socket(profiles.read_profile(real), socket)


def stop_run(run: RunningAgent) -> bool:
    """Stops a sandboxed agent the person chose to restart (its own process, checked first: a live
    process of this user, not macOS's)."""
    facts = platform.describe(run.pid) if run.pid > 1 else None
    if facts is None or facts.uid != getattr(os, "getuid", lambda: -1)() or platform.is_system(facts.path):
        return False
    return platform.terminate(run.pid)


#: Whether this machine's helper reports the sandbox's refusals itself (macOS: its denial log; KI-693).
HELPER_REPORTS_REFUSALS = platform.HELPER_REPORTS_REFUSALS


def on_refusal(kind: str, name: str, agent: str, instance: str, folder: str, pid: int = 0) -> None:
    """A sandbox refusal an agent's hook saw (``agent_hooks.RefusalSeen``): a refused signal goes
    to the stop broker with the process it named; any other kind may ask the person (its permission
    on "ask"). A kill of a process the agent could not see (``signal-unseen``: Linux below 6.12,
    where the sandbox is its own PID namespace) goes to the broker too, which only ever ASKS for it."""
    if kind in (permissions.catalogue.KIND_SIGNAL, brokered.stop.UNSEEN_KIND):
        brokered.stop.on_refused(int(name) if name.isdigit() else 0, agent, instance, folder,
                                 unseen=kind == brokered.stop.UNSEEN_KIND)
    else:
        permissions.refused(kind, agent, instance, folder, pid)


def open_app(app: str) -> str:
    """Relaunches GUI agent *app* inside the sandbox (D10); raises with a sentence when it can not."""
    if platform.unavailable():
        raise RuntimeError(platform.unavailable())
    current = mode_module.current()
    if not current.enabled:
        raise RuntimeError("Engage File Shield first: the sandbox protects its list.")
    sync(current)
    own = agent_profile(app)   # the editor's own permissions when it is sandboxed, else the everywhere profile
    return platform.open_app(app, str(own if own.is_file() else profile_path()), log=str(home() / f"{app}.log"))


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
