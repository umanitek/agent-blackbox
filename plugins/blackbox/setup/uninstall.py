"""``blackbox uninstall`` — remove Blackbox from this machine, and nothing else.

What a Blackbox install added, taken away in reverse order:

1. the login services, through their own supervisor (launchd on macOS, systemd on Linux,
   scheduled tasks on Windows) — never by killing a process under them;
2. a node or dashboard Blackbox started without its service (``daemon.pid`` in Blackbox's own
   DKG home only);
3. Blackbox in every agent: ``plugins.enabled`` and ``plugins.entries.blackbox`` leave each
   Hermes home's config.yaml (comments kept — kernel/yaml_files.py), OpenClaw workspaces are
   detached, and plugin copies ``blackbox attach`` placed are deleted;
4. Blackbox's data: ``$BLACKBOX_HOME`` (audit logs, findings, the node and its synced graph)
   and a DKG home Blackbox's config names elsewhere, but only one carrying Blackbox's marker
   (``blackbox-process-limits.json``), so another DKG node on the machine is never touched;
5. the ``blackbox`` command (only the launcher our installer wrote, which carries its marker);
6. last, the plugin itself: ``hermes plugins remove blackbox`` in each Hermes home where
   Hermes installed it (Hermes keeps the record), so the code running this goes last.

Keys are never lost by surprise: by default the node's wallet and identity files and the
reporter key are MOVED to ``~/blackbox-backup-<time>/`` (owner-only, with a README saying what
each file is and how to restore it), and ``--purge`` deletes them with everything else for a
clean uninstall. ``--keep-logs`` moves the local audit record into the same backup instead of
deleting it. The user's Hermes (Hermes Desktop or any other), other DKG nodes and Docker are
left alone. Linux system units (/etc/systemd/system) need root: they are named, with the
commands to run, rather than half-removed.

Pattern: a Plan built first (pure, shown to the user, testable) and then executed step by
step (Command). Every step reports and continues; a failed step never hides the others.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import os
import platform
import shutil
import signal
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Sequence

from .. import sync   # sync's public entry: the service names, which process is our node
from ..kernel import addons, constants, system_helper, terminal_question, yaml_files
from ..kernel.host_command import hermes_argv
from . import addon_cleanup, install_manifest, platform as os_platform
from .uninstall_data import _back_up, _delete_data
from .uninstall_outside import Runner, _remove_agent_hooks, _remove_from_agents, _remove_system_helper, _run_at_terminal

#: Files a node needs to keep its identity and wallet (DKG home), and Blackbox's own reporter
#: identity and sharing consent ($BLACKBOX_HOME). Moved to the backup unless --purge.
NODE_KEY_FILES = ("agent-keystore.json", "wallets.json", "wallets.key", "auth.token", "config.json")
BLACKBOX_KEY_FILES = ("reporter_key.pem", "sharing_consent.json")
#: A file only Blackbox's installer writes into the DKG home it manages: proof the folder is ours.
DKG_HOME_MARKER = "blackbox-process-limits.json"
SHIM_MARKER = "managed-by: agent-blackbox-installer"
# The services to remove: the names the installers register, owned by sync (one place to rename).
LAUNCHD_LABELS, SYSTEMD_UNITS, WINDOWS_TASKS = sync.LAUNCHD_LABELS, sync.SYSTEMD_UNITS, sync.WINDOWS_TASKS
SERVICE_NAMES = os_platform.ServiceNames(LAUNCHD_LABELS, SYSTEMD_UNITS, WINDOWS_TASKS)



def _run(command: Sequence[str]) -> int:
    """Run *command* quietly; 127 when the tool is not installed here."""
    try:
        return subprocess.run(list(command), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              stdin=subprocess.DEVNULL, check=False, timeout=60).returncode
    except (OSError, subprocess.TimeoutExpired):
        return 127


@dataclass(frozen=True)
class UninstallPlan:
    """Everything an uninstall will touch, worked out before anything changes.

    Build it with :func:`build_plan`; :func:`describe` turns it into the lines shown to the user
    and :func:`execute` carries it out. ``backup_dir`` is None under ``--purge``.
    """

    system: str                        # platform.system(): Darwin, Linux, Windows
    hermes_homes: tuple[Path, ...]     # Hermes homes whose config names Blackbox
    blackbox_home: Path
    dkg_home: Optional[Path]           # Blackbox's own node home (marker checked)
    key_files: tuple[Path, ...]        # identity/wallet files that exist
    backup_dir: Optional[Path]
    keep_logs: bool
    shim: Optional[Path]               # our `blackbox` launcher, if this machine has it
    system_units: tuple[Path, ...]     # Linux /etc/systemd/system units (need root)
    dashboard_port: int = constants.DEFAULT_DASHBOARD_PORT   # where a directly started dashboard would be listening
    notes: tuple[str, ...] = field(default_factory=tuple)
    system_helper: Optional[Path] = None   # the system protection helper (macOS), when installed
    agent_hooks: tuple[str, ...] = ()      # coding agents whose config holds Blackbox's hooks
    addons: tuple[Path, ...] = ()          # add-on folders beside the plugin (kernel.addons)
    #: What the installer made besides Blackbox (the Hermes host on a clean machine, KI-610).
    manifest: install_manifest.InstallManifest = field(default_factory=install_manifest.InstallManifest)
    #: What the add-ons' manifests ask to have removed (read before their folders go), checked.
    addon_cleanup: addon_cleanup.CleanupPlan = field(default_factory=addon_cleanup.CleanupPlan)


def _configured_dkg_home(home: Path) -> Optional[Path]:
    raw = yaml_files.blackbox_entry(yaml_files.load_yaml(home / "config.yaml")).get("dkg_home")
    return Path(str(raw)).expanduser() if raw else None


def _names_blackbox(home: Path) -> bool:
    plugins = yaml_files.load_yaml(home / "config.yaml").get("plugins")
    plugins = plugins if isinstance(plugins, dict) else {}   # a hand-edited string or list names nothing
    enabled = plugins.get("enabled") if isinstance(plugins.get("enabled"), list) else []
    entries = plugins.get("entries") or {}
    return "blackbox" in enabled or (isinstance(entries, dict) and "blackbox" in entries) \
        or (home / "plugins" / "blackbox").exists()


def build_plan(*, purge: bool, keep_logs: bool, now: Optional[_dt.datetime] = None,
               homes: Optional[Sequence[Path]] = None) -> UninstallPlan:
    """Work out what this machine's Blackbox consists of. Reads only; changes nothing."""
    from ..attach import discover_hermes_homes   # attach's public entry
    candidates = list(homes) if homes is not None else discover_hermes_homes(include_managed=True)   # its chat profile too
    hermes_homes = tuple(h for h in dict.fromkeys(Path(h).expanduser() for h in candidates) if _names_blackbox(h))
    blackbox_home = constants.blackbox_home()
    notes: list[str] = []
    dkg_home: Optional[Path] = None
    dashboard_port = constants.DEFAULT_DASHBOARD_PORT
    for home in hermes_homes:
        entry = yaml_files.blackbox_entry(yaml_files.load_yaml(home / "config.yaml"))
        if str(entry.get("dashboard_port", "")).isdigit():
            dashboard_port = int(entry["dashboard_port"])
            break
    for home in hermes_homes or (constants.hermes_home(),):
        configured = _configured_dkg_home(home)
        if configured and (configured / DKG_HOME_MARKER).exists():
            dkg_home = configured
            break
        if configured and configured.exists():
            notes.append(f"Left alone: {configured} has no Blackbox marker, so it may be another DKG node.")
    if dkg_home is None and (constants.blackbox_dkg_home() / DKG_HOME_MARKER).exists():
        dkg_home = constants.blackbox_dkg_home()
    keys = [dkg_home / name for name in NODE_KEY_FILES] if dkg_home else []
    keys += [blackbox_home / name for name in BLACKBOX_KEY_FILES]
    stamp = (now or _dt.datetime.now()).strftime("%Y%m%d-%H%M%S")
    shim_dir = Path.home() / ".local" / "bin"
    shim = next((p for p in (shim_dir / "blackbox", shim_dir / "blackbox.cmd")
                 if p.is_file() and SHIM_MARKER in p.read_text(encoding="utf-8-sig", errors="ignore")), None)
    system_units = tuple(p for p in (sync.SYSTEM_UNIT_DIR / u for u in SYSTEMD_UNITS) if p.exists())
    system = platform.system()
    manifest = install_manifest.read(blackbox_home)
    # The helper as found, or as the install manifest names it (KI-629: one list of what was added).
    helper = system_helper.BINARY if system == "Darwin" and (
        system_helper.BINARY.exists() or system_helper.LAUNCH_DAEMON.exists() or manifest.system_helper) else None
    from .. import agent_hooks   # agent_hooks' public entry
    addon_folders = tuple(home / "plugins" / name for home in hermes_homes for name in addons.found(home / "plugins"))
    return UninstallPlan(
        system_helper=helper, agent_hooks=tuple(agent_hooks.hooked_agents()), addons=addon_folders,
        system=system, hermes_homes=hermes_homes, blackbox_home=blackbox_home, dkg_home=dkg_home,
        key_files=tuple(p for p in keys if p.is_file()),
        backup_dir=None if purge else Path.home() / f"blackbox-backup-{stamp}",
        keep_logs=keep_logs, shim=shim, system_units=system_units, dashboard_port=dashboard_port,
        notes=tuple(notes), manifest=manifest, addon_cleanup=addon_cleanup.cleanup_for(addon_folders))


def installed(plan: UninstallPlan) -> bool:
    """True when *plan* finds any of Blackbox on this machine (KI-611: a second uninstall must
    change nothing and say so)."""
    return bool(plan.hermes_homes or plan.blackbox_home.exists() or plan.dkg_home or plan.shim or plan.system_helper
                or plan.agent_hooks or plan.addons or plan.system_units
                or any((Path.home() / "Library" / "LaunchAgents" / f"{label}.plist").exists() for label in LAUNCHD_LABELS))


def describe(plan: UninstallPlan) -> list[str]:
    """The lines shown before anything changes."""
    lines = ["Blackbox uninstall will:"]
    if plan.system_helper:
        lines.append("  - remove the system protection helper and put DNS and the firewall back "
                     "(macOS asks for your admin password)")
    lines.append("  - stop and remove Blackbox's login services (node, dashboard)")
    if plan.agent_hooks:
        lines.append(f"  - take Blackbox's hooks out of {', '.join(plan.agent_hooks)} (their other settings stay)")
    for folder in plan.addons:
        lines.append(f"  - remove the add-on {folder}")
    lines += addon_cleanup.describe(plan.addon_cleanup)
    for home in plan.hermes_homes:
        lines.append(f"  - remove Blackbox from the Hermes in {home} (its other settings and comments stay)")
    if plan.dkg_home:
        lines.append(f"  - delete Blackbox's DKG node and its synced graph: {plan.dkg_home}")
    lines.append(f"  - delete Blackbox's data: {plan.blackbox_home}")
    if plan.shim:
        lines.append(f"  - remove the blackbox command: {plan.shim}")
    if plan.manifest.linger_user:
        lines.append(f"  - turn systemd lingering off for {plan.manifest.linger_user} again (the installer turned it on)")
    for folder in plan.manifest.user_path:
        lines.append(f"  - take {folder} off your PATH again (the installer added it)")
    if plan.backup_dir is None:
        lines.append("  - DELETE the node's wallet and identity keys and the reporter key (--purge)")
    elif plan.key_files or plan.keep_logs:
        what = "keys" + (" and the local audit record" if plan.keep_logs else "")
        lines.append(f"  - keep the {what} in {plan.backup_dir}")
    if plan.manifest.has_host:
        lines.append("Blackbox's installer also set up the Hermes host it runs in: you are asked whether to remove it too.")
        for folder, added in install_manifest.host_removal(plan.manifest).kept:   # KI-654
            names = ", ".join(entry.name for entry in added[:install_manifest.MAX_NAMED])
            lines.append(f"  - {folder} stays either way: you added to it since the install ({names})")
    else:
        lines.append("Your Hermes itself, other DKG nodes and Docker are not touched.")
    return lines + [f"Note: {n}" for n in plan.notes]


def host_question(plan: UninstallPlan) -> str:
    """The question asked when the installer set up the Hermes host (KI-610)."""
    size = install_manifest.human_size(install_manifest.host_size(plan.manifest))
    return f"Blackbox also set up the Hermes host it runs in ({size}). Remove it too? [y/N] "


def host_kept_note(plan: UninstallPlan) -> list[str]:
    """The lines said when the host stays (KI-630): what was kept, and the exact commands that
    remove it later — the ``blackbox`` command and the install manifest go with Blackbox, so
    ``--remove-host`` can not run again. Worked out after the uninstall ran (Hermes may have
    rewritten one of its own commands meanwhile). Printing beats leaving a remover behind: an
    uninstall leaves nothing of Blackbox's, and the commands are the manifest itself, spelled out."""
    home = str(Path.home())
    listed = ", ".join(str(path).replace(home, "~", 1) for path in plan.manifest.host)
    kept = install_manifest.kept_host(plan.manifest)
    lines = [f"Kept the Hermes host Blackbox's installer set up ({listed})."]
    commands = os_platform.manual_removal(kept.paths, kept.empty_dirs)
    if commands:
        lines.append("To remove it later (the blackbox command is gone with Blackbox), run:")
        lines += [f"    {command}" for command in commands]
    for target, block in kept.appended:
        empty = install_manifest.empty_lines_above(target, block)
        above = "" if not empty else " and the empty line just above them" if empty == 1 else f" and the {empty} empty lines just above them"
        lines.append(f"and delete these lines the installer added to {target}{above} (your own lines there stay):")
        lines += [f"    {line}" for line in block.strip("\n").splitlines()]
    return lines


def _stop_services(plan: UninstallPlan, run: Runner, report: list[str]) -> None:
    """Blackbox's login services, through this system's own tools (``setup/platform/<os>``)."""
    os_platform.stop_login_services(SERVICE_NAMES, plan.system_units, run, report)


def _stop_notifier(plan: UninstallPlan, report: list[str]) -> None:
    """Blackbox's own notifier ended and removed before its folder goes (KI-635: a ``request``
    instance and its launchd job kept running from the deleted folder)."""
    from .. import notify   # late, as setup/notifier.py: the notifier's packages load only for this step
    had = (plan.blackbox_home / "notifier").exists()
    notify.remove_notifier()
    if had:
        report.append("stopped and removed Blackbox's notifier")


def _supervised(plan: UninstallPlan) -> bool:
    """True while a root unit still supervises the dashboard and the node (KI-507): stopping them
    by pid would only see systemd start them again, so they are left to the unit's own stop."""
    return plan.system == "Linux" and any(unit.exists() for unit in plan.system_units)


def _stop_dashboard_on(port: int) -> list[int]:
    from ..dashboard import stop_running_dashboard   # dashboard's public entry
    return stop_running_dashboard(port)


def _stop_running_dashboard(plan: UninstallPlan, stop: Callable[[int], list[int]], report: list[str]) -> None:
    """A dashboard setup started directly (its service takes over at the next login): stopped
    before the data goes, or it re-creates $BLACKBOX_HOME (seen live 2026-11-03)."""
    if _supervised(plan):
        report.append("left running: Blackbox's dashboard and node run under the root units above; they stop with them")
        return
    for pid in stop(plan.dashboard_port):
        report.append(f"stopped Blackbox's dashboard (pid {pid})")


def _stop_unsupervised_node(plan: UninstallPlan, report: list[str]) -> None:
    """A node Blackbox started without its service: only the pid in Blackbox's own DKG home."""
    pid_file = plan.dkg_home / "daemon.pid" if plan.dkg_home else None
    if not pid_file or not pid_file.is_file() or _supervised(plan):
        return
    from ..kernel.config import load_blackbox_config
    try:
        pid = int(pid_file.read_text(encoding="utf-8-sig").strip())
        # The file can name a pid the system has since given to another program (KI-496):
        # never signal a process that is not this installation's node.
        if not sync.is_node_process(load_blackbox_config(), pid):
            return
        os.kill(pid, signal.SIGTERM)
        report.append(f"stopped Blackbox's DKG node (pid {pid})")
    except (ValueError, OSError):
        pass


def execute(plan: UninstallPlan, *, run: Runner = _run,
            stop_dashboard: Callable[[int], list[int]] = _stop_dashboard_on,
            run_as_admin: Runner = _run_at_terminal, remove_host: bool = False) -> list[str]:
    """Carry out *plan*; returns what was done (and what needs root), in order. *run*,
    *stop_dashboard* and *run_as_admin* (sudo, at the terminal) are the ways it reaches running
    processes (tests pass fakes). *remove_host*: also remove the Hermes host the installer set up
    (exactly what its manifest lists), last."""
    remove_plugin = hermes_argv("plugins", "remove", "blackbox")   # the Hermes running this, never another on PATH
    report: list[str] = []
    _remove_system_helper(plan, run_as_admin, report)   # first: DNS back before anything else stops
    _stop_services(plan, run, report)
    _stop_running_dashboard(plan, stop_dashboard, report)
    _stop_unsupervised_node(plan, report)
    _stop_notifier(plan, report)
    _back_up(plan, report)
    hermes_installed = _remove_from_agents(plan, report)
    _remove_agent_hooks(plan, report)
    addon_cleanup.remove(plan.addon_cleanup, run, report)   # what a companion app left (its manifest, read above)
    _delete_data(plan, report)
    install_manifest.remove_components(plan.manifest, report)   # the notifier it added (KI-629)
    install_manifest.remove_own_dirs(plan.manifest, report)   # e.g. an empty ~/Library/LaunchAgents it made (KI-611)
    install_manifest.restore_system_settings(plan.manifest, run, report)   # lingering (Linux), user PATH (Windows)
    if remove_host and plan.manifest.has_host:   # the host goes as a whole: no plugin to remove from it first
        install_manifest.remove_host(plan.manifest, report)
        return report
    for home in hermes_installed:   # last: this removes the code that is running
        env_home = str(home)
        code = run(["env", f"HERMES_HOME={env_home}", *remove_plugin]) \
            if plan.system != "Windows" else run(remove_plugin)
        report.append(f"removed the Blackbox plugin from {home}" if code == 0
                      else f"run to finish: hermes plugins remove blackbox   (Hermes home {home})")
    return report


def cmd_uninstall(args: argparse.Namespace) -> int:
    plan = build_plan(purge=args.purge, keep_logs=args.keep_logs)
    if not installed(plan):
        print("Blackbox is not installed here: nothing to remove.")
        return 0
    for line in describe(plan):
        print(line)
    if args.dry_run:
        return 0
    if not args.yes:
        answer = terminal_question.ask("Remove Blackbox? [y/N] ")   # the terminal, even under curl | bash
        if answer is None:
            print("Not removing anything without a yes: run with --yes, or at a terminal.")
            return 1
        if answer.strip().lower() not in ("y", "yes"):
            print("Nothing removed.")
            return 0
    remove_host = bool(getattr(args, "remove_host", False))
    if plan.manifest.has_host and not remove_host and not args.yes:
        answer = terminal_question.ask(host_question(plan))
        remove_host = (answer or "").strip().lower() in ("y", "yes")
    for line in execute(plan, remove_host=remove_host):
        print(f"  {line}")
    if plan.manifest.has_host and not remove_host:
        print("\n".join(host_kept_note(plan)))
    print("Blackbox is uninstalled." + (f" Your keys are in {plan.backup_dir}" if plan.backup_dir and plan.key_files else ""))
    return 0


def add_uninstall_parser(sub: argparse._SubParsersAction) -> None:
    """Register ``blackbox uninstall`` on the `blackbox` command's sub-parsers."""
    parser = sub.add_parser("uninstall", help="Remove Blackbox from this machine (keeps your keys unless --purge)")
    parser.add_argument("--purge", action="store_true", help="Also delete the node's keys and the reporter key: a clean uninstall")
    parser.add_argument("--keep-logs", action="store_true", help="Keep the local audit record in the backup folder")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be removed; change nothing")
    parser.add_argument("--yes", "-y", action="store_true", help="Do not ask (the Hermes host stays unless --remove-host)")
    parser.add_argument("--remove-host", action="store_true",
                        help="Also remove the Hermes host Blackbox's installer set up (only what it installed)")
    parser.set_defaults(func=cmd_uninstall)
