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
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional, Sequence

from ..kernel import constants, yaml_files

#: Files a node needs to keep its identity and wallet (DKG home), and Blackbox's own reporter
#: identity and sharing consent ($BLACKBOX_HOME). Moved to the backup unless --purge.
NODE_KEY_FILES = ("agent-keystore.json", "wallets.json", "wallets.key", "auth.token", "config.json")
BLACKBOX_KEY_FILES = ("reporter_key.pem", "sharing_consent.json")
#: A file only Blackbox's installer writes into the DKG home it manages: proof the folder is ours.
DKG_HOME_MARKER = "blackbox-process-limits.json"
SHIM_MARKER = "managed-by: agent-blackbox-installer"
LAUNCHD_LABELS = ("ai.umanitek.blackbox-dashboard", "ai.umanitek.blackbox-dkg")
SYSTEMD_UNITS = ("blackbox-dashboard.service", "blackbox-dkg.service")
WINDOWS_TASKS = ("Agent Blackbox dashboard", "Agent Blackbox DKG node")

Runner = Callable[[Sequence[str]], int]


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
    notes: tuple[str, ...] = field(default_factory=tuple)


def _configured_dkg_home(home: Path) -> Optional[Path]:
    entry = (((yaml_files.load_yaml(home / "config.yaml").get("plugins") or {}).get("entries") or {})
             .get("blackbox") or {})
    raw = entry.get("dkg_home") if isinstance(entry, dict) else None
    return Path(str(raw)).expanduser() if raw else None


def _names_blackbox(home: Path) -> bool:
    plugins = yaml_files.load_yaml(home / "config.yaml").get("plugins") or {}
    enabled = plugins.get("enabled") or []
    entries = plugins.get("entries") or {}
    return "blackbox" in enabled or (isinstance(entries, dict) and "blackbox" in entries) \
        or (home / "plugins" / "blackbox").exists()


def build_plan(*, purge: bool, keep_logs: bool, now: Optional[_dt.datetime] = None,
               homes: Optional[Sequence[Path]] = None) -> UninstallPlan:
    """Work out what this machine's Blackbox consists of. Reads only; changes nothing."""
    from ..attach import discover_hermes_homes   # attach's public entry
    candidates = list(homes) if homes is not None else discover_hermes_homes()
    hermes_homes = tuple(h for h in dict.fromkeys(Path(h).expanduser() for h in candidates) if _names_blackbox(h))
    blackbox_home = constants.blackbox_home()
    notes: list[str] = []
    dkg_home: Optional[Path] = None
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
                 if p.is_file() and SHIM_MARKER in p.read_text(encoding="utf-8", errors="ignore")), None)
    system_units = tuple(p for p in (Path("/etc/systemd/system") / u for u in SYSTEMD_UNITS) if p.exists())
    return UninstallPlan(
        system=platform.system(), hermes_homes=hermes_homes, blackbox_home=blackbox_home, dkg_home=dkg_home,
        key_files=tuple(p for p in keys if p.is_file()),
        backup_dir=None if purge else Path.home() / f"blackbox-backup-{stamp}",
        keep_logs=keep_logs, shim=shim, system_units=system_units, notes=tuple(notes))


def describe(plan: UninstallPlan) -> list[str]:
    """The lines shown before anything changes."""
    lines = ["Blackbox uninstall will:",
             "  - stop and remove Blackbox's login services (node, dashboard)"]
    for home in plan.hermes_homes:
        lines.append(f"  - remove Blackbox from the Hermes in {home} (its other settings and comments stay)")
    if plan.dkg_home:
        lines.append(f"  - delete Blackbox's DKG node and its synced graph: {plan.dkg_home}")
    lines.append(f"  - delete Blackbox's data: {plan.blackbox_home}")
    if plan.shim:
        lines.append(f"  - remove the blackbox command: {plan.shim}")
    if plan.backup_dir is None:
        lines.append("  - DELETE the node's wallet and identity keys and the reporter key (--purge)")
    elif plan.key_files or plan.keep_logs:
        what = "keys" + (" and the local audit record" if plan.keep_logs else "")
        lines.append(f"  - keep the {what} in {plan.backup_dir}")
    lines.append("Your Hermes itself, other DKG nodes and Docker are not touched.")
    return lines + [f"Note: {n}" for n in plan.notes]


def _stop_services(plan: UninstallPlan, run: Runner, report: list[str]) -> None:
    if plan.system == "Darwin":
        uid = os.getuid()
        for label in LAUNCHD_LABELS:
            run(["launchctl", "bootout", f"gui/{uid}/{label}"])
            plist = Path.home() / "Library" / "LaunchAgents" / f"{label}.plist"
            if plist.exists():
                plist.unlink()
                report.append(f"removed login service {label}")
    elif plan.system == "Linux":
        user_dir = Path.home() / ".config" / "systemd" / "user"
        removed = False
        for unit in SYSTEMD_UNITS:
            if (user_dir / unit).exists():
                run(["systemctl", "--user", "disable", "--now", unit])
                (user_dir / unit).unlink()
                removed = True
                report.append(f"removed login service {unit}")
        if removed:
            run(["systemctl", "--user", "daemon-reload"])
        for unit in plan.system_units:
            report.append(f"needs root: sudo systemctl disable --now {unit.name} && sudo rm {unit} "
                          "&& sudo systemctl daemon-reload")
    elif plan.system == "Windows":
        for task in WINDOWS_TASKS:
            run(["schtasks", "/End", "/TN", task])
            if run(["schtasks", "/Delete", "/TN", task, "/F"]) == 0:
                report.append(f"removed scheduled task {task}")


def _stop_unsupervised_node(plan: UninstallPlan, report: list[str]) -> None:
    """A node Blackbox started without its service: only the pid in Blackbox's own DKG home."""
    pid_file = plan.dkg_home / "daemon.pid" if plan.dkg_home else None
    if not pid_file or not pid_file.is_file():
        return
    try:
        pid = int(pid_file.read_text(encoding="utf-8").strip())
        os.kill(pid, signal.SIGTERM)
        report.append(f"stopped Blackbox's DKG node (pid {pid})")
    except (ValueError, OSError):
        pass


def _back_up(plan: UninstallPlan, report: list[str]) -> None:
    if plan.backup_dir is None:
        return
    keys = plan.backup_dir / "keys"
    keys.mkdir(parents=True, exist_ok=True)
    os.chmod(plan.backup_dir, 0o700)
    for src in plan.key_files:
        dest = keys / ("node-" + src.name if plan.dkg_home and src.parent == plan.dkg_home else src.name)
        shutil.copy2(src, dest)
        os.chmod(dest, 0o600)
    if plan.keep_logs and plan.blackbox_home.is_dir():
        logs = plan.backup_dir / "audit-record"
        logs.mkdir(exist_ok=True)
        for item in plan.blackbox_home.iterdir():
            if item.suffix == ".jsonl" or item.name == "sandbox":
                (shutil.copytree if item.is_dir() else shutil.copy2)(item, logs / item.name)
    (plan.backup_dir / "README.txt").write_text(_BACKUP_README, encoding="utf-8")
    report.append(f"kept your keys in {plan.backup_dir}")


_BACKUP_README = """\
Kept by `blackbox uninstall` (delete this folder when you no longer need it).

keys/node-*               your Blackbox DKG node's identity and operational wallet
                          (agent-keystore.json, wallets.json, wallets.key, auth.token, config.json)
keys/reporter_key.pem     the key that signed your community threat reports
keys/sharing_consent.json your community-sharing consent record
audit-record/             your local audit record, if you ran uninstall with --keep-logs

To use the same node identity again after reinstalling Blackbox: stop the Blackbox DKG node,
copy keys/node-<name> back into its DKG home (dropping the "node-" prefix), copy
reporter_key.pem and sharing_consent.json into ~/.hermes/blackbox, then start the node.
These files are secrets: keep this folder private.
"""


def _remove_from_agents(plan: UninstallPlan, report: list[str]) -> list[Path]:
    """Detach every agent; returns the Hermes homes where Hermes itself installed the plugin."""
    from ..attach import detach_all   # attach's public entry
    detach_all(hermes=True, openclaw=True, remove_files=False, dry_run=False)
    hermes_installed: list[Path] = []
    for home in plan.hermes_homes:
        config = home / "config.yaml"
        data = yaml_files.load_yaml(config)
        entries = (data.get("plugins") or {}).get("entries")
        if isinstance(entries, dict) and "blackbox" in entries:
            del entries["blackbox"]
            yaml_files.dump_yaml(config, data)
        metadata = home / "plugins" / ".install-metadata.json"
        if metadata.is_file() and '"blackbox"' in metadata.read_text(encoding="utf-8", errors="ignore"):
            hermes_installed.append(home)
        elif (home / "plugins" / "blackbox").is_dir():
            shutil.rmtree(home / "plugins" / "blackbox", ignore_errors=True)
        report.append(f"removed Blackbox from the Hermes in {home}")
    return hermes_installed


def _delete_data(plan: UninstallPlan, report: list[str]) -> None:
    targets = [plan.blackbox_home]
    if plan.dkg_home and plan.blackbox_home not in plan.dkg_home.parents:
        targets.append(plan.dkg_home)
    for target in targets:
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
            report.append(f"deleted {target}")
    if plan.shim:
        plan.shim.unlink(missing_ok=True)
        report.append(f"removed {plan.shim}")


def execute(plan: UninstallPlan, *, run: Runner = _run, hermes: str = "hermes") -> list[str]:
    """Carry out *plan*; returns what was done (and what needs root), in order."""
    report: list[str] = []
    _stop_services(plan, run, report)
    _stop_unsupervised_node(plan, report)
    _back_up(plan, report)
    hermes_installed = _remove_from_agents(plan, report)
    _delete_data(plan, report)
    for home in hermes_installed:   # last: this removes the code that is running
        env_home = str(home)
        code = run(["env", f"HERMES_HOME={env_home}", hermes, "plugins", "remove", "blackbox"]) \
            if plan.system != "Windows" else run([hermes, "plugins", "remove", "blackbox"])
        report.append(f"removed the Blackbox plugin from {home}" if code == 0
                      else f"run to finish: hermes plugins remove blackbox   (Hermes home {home})")
    return report


def cmd_uninstall(args: argparse.Namespace) -> int:
    plan = build_plan(purge=args.purge, keep_logs=args.keep_logs)
    for line in describe(plan):
        print(line)
    if args.dry_run:
        return 0
    if not args.yes:
        if not sys.stdin.isatty():
            print("Not removing anything without a yes: run with --yes, or at a terminal.")
            return 1
        if input("Remove Blackbox? [y/N] ").strip().lower() not in ("y", "yes"):
            print("Nothing removed.")
            return 0
    for line in execute(plan):
        print(f"  {line}")
    print("Blackbox is uninstalled." + (f" Your keys are in {plan.backup_dir}" if plan.backup_dir and plan.key_files else ""))
    return 0


def add_uninstall_parser(sub: argparse._SubParsersAction) -> None:
    """Register ``blackbox uninstall`` on the `blackbox` command's sub-parsers."""
    parser = sub.add_parser("uninstall", help="Remove Blackbox from this machine (keeps your keys unless --purge)")
    parser.add_argument("--purge", action="store_true", help="Also delete the node's keys and the reporter key: a clean uninstall")
    parser.add_argument("--keep-logs", action="store_true", help="Keep the local audit record in the backup folder")
    parser.add_argument("--dry-run", action="store_true", help="Show what would be removed; change nothing")
    parser.add_argument("--yes", "-y", action="store_true", help="Do not ask")
    parser.set_defaults(func=cmd_uninstall)
