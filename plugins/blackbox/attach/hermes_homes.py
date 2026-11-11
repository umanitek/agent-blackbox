"""Protecting Hermes agents: discover homes, enable/disable Blackbox in each.

A Hermes home is protected when the plugin is copied into its
``plugins/blackbox/`` and ``blackbox`` is in ``plugins.enabled`` of its
``config.yaml``. Idempotent; fails open per home.
"""

from __future__ import annotations
from . import declined

import logging
import os
import shutil
from pathlib import Path
from typing import Any, Dict, List, Optional
from ..kernel import constants
from . import plugin_copy
from ..kernel import yaml_files

logger = logging.getLogger(__name__)



def discover_hermes_homes() -> list[Path]:
    """Return every local Hermes home directory to protect.

    Includes the resolved default home, ``~/.hermes``, every existing
    ``~/.hermes/profiles/*/`` directory, and (on Windows) ``%LOCALAPPDATA%/hermes``.
    The canonical default is always included even if not yet created; results are
    de-duplicated preserving order.
    """
    homes: list[Path] = []

    def _add(path: Optional[Path]) -> None:
        if path is None:
            return
        try:
            resolved = path.expanduser()
        except Exception:
            return
        if resolved not in homes:
            homes.append(resolved)

    # The canonical default (honours profile switching / $HERMES_HOME) — always
    # included even if the directory does not exist yet.
    try:
        _add(constants.hermes_home())
    except Exception:  # pragma: no cover - defensive
        pass

    default_dot = Path.home() / ".hermes"
    _add(default_dot)

    # Every existing profile directory under the default home.
    profiles_dir = default_dot / "profiles"
    try:
        if profiles_dir.is_dir():
            for child in sorted(profiles_dir.iterdir()):
                if child.is_dir() and not is_managed_blackbox_chat_profile(child):
                    _add(child)
    except Exception:
        pass

    # Windows: %LOCALAPPDATA%/hermes.
    if os.name == "nt":
        local_appdata = os.environ.get("LOCALAPPDATA")
        if local_appdata:
            _add(Path(local_appdata) / "hermes")

    return homes


def is_managed_blackbox_chat_profile(path: Path) -> bool:
    """Return True for the internal Blackbox control chat profile.

    The dashboard's attach/connected-agent surfaces list protected workloads.
    The managed ``agent-blackbox`` profile (``blackbox`` on older installs) is the operator/control profile launched by
    ``hermes blackbox chat``; showing it as a defended agent is misleading.
    """
    try:
        resolved = path.expanduser()
        names = (constants.BLACKBOX_CHAT_PROFILE, constants.LEGACY_BLACKBOX_CHAT_PROFILE)
        if resolved.name not in names or resolved.parent.name != "profiles":
            return False
        soul = resolved / "SOUL.md"
        return soul.exists() and constants.BLACKBOX_CHAT_SOUL_MARKER in soul.read_text(encoding="utf-8-sig")
    except Exception:
        return False


def enabled_list_has(data: dict[str, Any], name: str) -> bool:
    plugins = data.get("plugins")
    if not isinstance(plugins, dict):
        return False
    enabled = plugins.get("enabled")
    return isinstance(enabled, list) and name in enabled


# ---------------------------------------------------------------------------
# Hermes attach / detach
# ---------------------------------------------------------------------------



def _enable_in(data: dict[str, Any]) -> None:
    """Add ``blackbox`` to *data*'s ``plugins.enabled`` (a parsed config.yaml), creating the
    section or list where it is missing or not of the right kind; every other key is kept."""
    plugins = data.setdefault("plugins", {})
    if not isinstance(plugins, dict):
        plugins = {}
        data["plugins"] = plugins
    enabled = plugins.get("enabled")
    if not isinstance(enabled, list):
        enabled = []
        plugins["enabled"] = enabled
    if "blackbox" not in enabled:
        enabled.append("blackbox")

@declined.remembers("hermes", switched_off=False)
@yaml_files.edits_config
def attach_hermes(home: Path, *, dry_run: bool = False) -> dict[str, Any]:
    """Enable Blackbox in a single Hermes *home*.

    Copies the plugin into ``<home>/plugins/blackbox/`` (only when missing or a
    version mismatch) and adds ``blackbox`` to ``plugins.enabled`` in
    ``<home>/config.yaml`` idempotently, preserving every other key. Returns a
    per-target report dict; fails open (``ok=False`` + ``error`` on failure).
    """
    home = home.expanduser()
    report: dict[str, Any] = {
        "target": str(home),
        "kind": "hermes",
        "ok": False,
        "protected": False,
        "copied": False,
        "enabled": False,
        "already": False,
        "dry_run": dry_run,
    }
    try:
        src = plugin_copy._plugin_source_dir()
        dest = home / "plugins" / "blackbox"
        # Don't copy a home onto itself (e.g. running from inside a home).
        same_tree = src == dest or src == dest.resolve() if dest.exists() else False
        needs = (not same_tree) and plugin_copy._needs_copy(dest)
        files_ready = same_tree or not needs
        if needs and not dry_run:
            plugin_copy.copy_plugin_tree(src, dest)
        report["copied"] = needs

        config_path = home / "config.yaml"
        data = yaml_files.load_for_edit(config_path)   # unreadable: reported below, never rewritten
        config_enabled = enabled_list_has(data, "blackbox")
        if config_enabled and files_ready:
            report["already"] = True
        elif not config_enabled:
            if not dry_run:
                _enable_in(data)
                yaml_files.dump_yaml(config_path, data)
            report["enabled"] = True
        # A dry-run reports the protection that exists now, not the state an attach *could* create
        # (dashboard cards stay honest when config says enabled but the files are missing or stale).
        report["protected"] = (config_enabled and files_ready) if dry_run else True
        report["changed"] = not dry_run and bool(report["copied"] or report["enabled"])   # what auto-attach audits
        report["ok"] = True
    except Exception as exc:  # fail open per target
        logger.debug("blackbox.attach: attach_hermes(%s) failed: %s", home, exc)
        report["error"] = str(exc)
    return report


@declined.remembers("hermes", switched_off=True)
@yaml_files.edits_config
def detach_hermes(home: Path, *, remove_files: bool = False, dry_run: bool = False) -> dict[str, Any]:
    """Disable Blackbox in a single Hermes *home*.

    Removes ``blackbox`` from ``plugins.enabled`` (idempotent) and, when
    *remove_files* is set, deletes ``<home>/plugins/blackbox/``. Fails open.
    """
    home = home.expanduser()
    report: dict[str, Any] = {
        "target": str(home),
        "kind": "hermes",
        "ok": False,
        "disabled": False,
        "removed": False,
        "already": False,
        "dry_run": dry_run,
    }
    try:
        config_path = home / "config.yaml"
        data = yaml_files.load_yaml(config_path)
        if enabled_list_has(data, "blackbox"):
            if not dry_run:
                data["plugins"]["enabled"] = [p for p in data["plugins"]["enabled"] if p != "blackbox"]
                yaml_files.dump_yaml(config_path, data)
            report["disabled"] = True
        else:
            report["already"] = True

        dest = home / "plugins" / "blackbox"
        if remove_files and dest.exists():
            if not dry_run:
                shutil.rmtree(dest)
            report["removed"] = True
        report["ok"] = True
    except Exception as exc:
        logger.debug("blackbox.attach: detach_hermes(%s) failed: %s", home, exc)
        report["error"] = str(exc)
    return report
