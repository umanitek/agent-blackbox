"""What ``blackbox uninstall`` removes OUTSIDE Blackbox's own folders: the system protection helper
(macOS, through its own uninstall, which puts DNS and the firewall back), Blackbox's place in
each agent (Hermes homes' config entries and plugin folders, through ``attach``), its hooks in
coding agents' configs (through ``agent_hooks``) and the add-on folders beside the plugin.

Split out of :mod:`.uninstall` (size guard); :func:`.uninstall.execute` calls these in order.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from typing import TYPE_CHECKING, Callable, Sequence

from ..kernel import system_helper, yaml_files

if TYPE_CHECKING:   # the plan type, for the annotations only (uninstall imports this module)
    from .uninstall import UninstallPlan

Runner = Callable[[Sequence[str]], int]
#: The plugin folder this code runs from, and the file an installed copy keeps naming its checkout.
_PLUGIN_DIR = Path(__file__).resolve().parents[1]
_SOURCE_ROOT_MARKER = ".blackbox-source-root"


def bundled_in_hermes() -> bool:
    """True when the Hermes Blackbox runs in carries Blackbox as one of its OWN (bundled) plugins:
    the checkout this plugin came from is a Hermes checkout (``hermes_cli/``) holding
    ``plugins/blackbox`` — what Blackbox's installer sets up on a clean machine. Hermes loads a
    bundled backend plugin unless ``plugins.disabled`` names it (KI-610: after uninstall
    ``hermes plugins list`` still said "blackbox enabled · bundled")."""
    roots = [_PLUGIN_DIR.parents[1]]
    try:
        marked = (_PLUGIN_DIR / _SOURCE_ROOT_MARKER).read_text(encoding="utf-8-sig").strip()
        roots += [Path(marked)] if marked else []
    except OSError:
        pass
    return any((root / "hermes_cli").is_dir() and (root / "plugins" / "blackbox" / "plugin.yaml").is_file() for root in roots)


def _disable_bundled(data: dict) -> bool:
    """``blackbox`` added to *data*'s ``plugins.disabled`` (a parsed config.yaml); True when changed."""
    plugins = data.setdefault("plugins", {})
    if not isinstance(plugins, dict):
        return False   # hand-edited into something else: never rewritten
    disabled = plugins.get("disabled") if isinstance(plugins.get("disabled"), list) else []
    if "blackbox" in disabled:
        return False
    plugins["disabled"] = [*disabled, "blackbox"]
    return True


def _run_at_terminal(command: Sequence[str]) -> int:
    """Run *command* with the person's terminal attached (sudo asks for the password there)."""
    try:
        return subprocess.run(list(command), check=False, timeout=300).returncode
    except (OSError, subprocess.TimeoutExpired):
        return 127


def _remove_system_helper(plan: UninstallPlan, run_as_admin: Runner, report: list[str]) -> None:
    """The helper puts DNS and the firewall back from its own saved state, then removes itself
    (its own `uninstall`, as the installer's --remove-system-protection does). Posture hardening
    it applied stays (the helper's rule: removing it never re-opens the Mac)."""
    # WHY no check that the program is there: its folder is root-only, so the person cannot see it
    # (E2E 2026-11-21 read a running helper as "gone" and left DNS and the firewall changed). The
    # plan found it by its LaunchDaemon; sudo can run what the person cannot see.
    if not plan.system_helper:
        _remove_helper_key(report)   # no helper left to pair with: its key is a leftover secret
        return
    if run_as_admin(["sudo", str(plan.system_helper), "uninstall"]) == 0:
        report.append("removed the system protection helper; DNS and the firewall are as they were")
        _remove_helper_key(report)
        return
    # Only the helper's own uninstall puts DNS back: stopping it by hand (bootout + rm) would leave
    # the Mac asking a resolver that no longer answers — no internet.
    report.append(f"needs root: sudo '{plan.system_helper}' uninstall   (puts DNS and the firewall back; "
                  f"if that program is missing, reinstall system protection first, then run it)")


def _remove_helper_key(report: list[str]) -> None:
    """Deletes the person's copy of the helper's pairing key, then its folder and the "Blackbox"
    folder above it only when each is left EMPTY (``rmdir`` refuses anything else — a companion
    app's files there are never touched). Only once the helper is gone: a helper that could not
    be removed still needs the key (E2E recheck 2026-11-21: empty folders were left behind)."""
    folder = system_helper.user_key_folder()
    key = folder / system_helper.KEY_FILE_NAME
    if key.is_file() and not key.is_symlink():
        key.unlink()
        report.append("deleted the system protection helper's pairing key")
    for empty in (folder, folder.parent):
        try:
            empty.rmdir()
        except OSError:   # missing, or not empty: left as it is
            return


@yaml_files.edits_config
def _remove_from_agents(plan: UninstallPlan, report: list[str]) -> list[Path]:
    """Detach every agent; returns the Hermes homes where Hermes itself installed the plugin."""
    from ..attach import detach_all, detach_hermes, is_managed_blackbox_chat_profile   # attach's public entry
    detach_all(hermes=True, openclaw=True, remove_files=False, dry_run=False)
    hermes_installed: list[Path] = []
    for home in plan.hermes_homes:
        if is_managed_blackbox_chat_profile(home):   # the sweep leaves Blackbox's own chat profile alone
            detach_hermes(home)
        config = home / "config.yaml"
        data = yaml_files.load_yaml(config)   # an unreadable config has no entry to remove: never written
        plugins = data.get("plugins")
        entries = plugins.get("entries") if isinstance(plugins, dict) else None   # hand-edited: nothing to remove
        changed = isinstance(entries, dict) and "blackbox" in entries
        if changed:
            del entries["blackbox"]
            if not entries:   # Blackbox's entry was the only one: no empty ``entries: {}`` is left behind
                del plugins["entries"]
        # Only a Hermes Blackbox's installer set up bundles Blackbox (its checkout is Blackbox's own);
        # a Hermes the person had before is never given a "disabled" entry.
        if config.is_file() and plan.manifest.has_host and bundled_in_hermes() and _disable_bundled(data):
            changed = True
            report.append(f"switched off the copy of Blackbox bundled with the Hermes in {home}")
        if changed:
            yaml_files.dump_yaml(config, data)
        metadata = home / "plugins" / ".install-metadata.json"
        if metadata.is_file() and '"blackbox"' in metadata.read_text(encoding="utf-8-sig", errors="ignore"):
            hermes_installed.append(home)
        elif (home / "plugins" / "blackbox").is_dir():
            shutil.rmtree(home / "plugins" / "blackbox", ignore_errors=True)
        report.append(f"removed Blackbox from the Hermes in {home}")
    return hermes_installed


def _remove_agent_hooks(plan: UninstallPlan, report: list[str]) -> None:
    """Coding agents' hooks and the add-on folders: left behind, every agent would run a hook whose
    runner is about to be deleted (E2E 2026-11-21), and the add-on would load into a Hermes
    without Blackbox."""
    if plan.agent_hooks:
        from .. import agent_hooks   # agent_hooks' public entry
        for row in agent_hooks.remove_all():
            report.append(f"took Blackbox's hooks out of {row['name']} ({row['target']})" if row["ok"]
                          else f"could not edit {row['target']}: {row['note']} — remove Blackbox's hooks there by hand")
    for folder in plan.addons:
        shutil.rmtree(folder, ignore_errors=True)
        report.append(f"removed the add-on {folder}")
    # File Shield's agent sandbox put its launcher folder first on PATH (kernel.shell_path); the
    # folder goes with Blackbox's home, so the PATH lines go too.
    from ..kernel import shell_path
    for changed in shell_path.remove():
        report.append(f"took Blackbox's agent launchers off PATH in {changed}")
