"""Protecting Hermes agents: discover homes, enable/disable Blackbox in each.

A Hermes home is protected when the plugin is copied into its
``plugins/blackbox/`` and ``blackbox`` is in ``plugins.enabled`` of its
``config.yaml``. Idempotent; fails open per home.
"""

from __future__ import annotations
from . import declined, serial

import logging
import shutil
from pathlib import Path
from typing import Any, Optional
from ..kernel import constants
from . import plugin_copy
from .report import AttachReport
from ..kernel import yaml_files

logger = logging.getLogger(__name__)



def discover_hermes_homes(*, include_managed: bool = False) -> list[Path]:
    """Return every local Hermes home directory to protect.

    Blackbox's own chat profile (:func:`is_managed_blackbox_chat_profile`) is left out — it is
    not an agent to defend — unless *include_managed* (uninstall: Blackbox must leave it too).

    The resolved default home (``$HERMES_HOME``, else the platform default) even before it exists,
    then, only when they exist, each Hermes root (:func:`_hermes_roots`: the active home's root and
    the platform default) and every live profile under its ``profiles/``; de-duplicated, in order.
    WHY only existing ones: a missing home is not an agent — listing it made "protect every agent"
    create ~/.hermes on a Mac without Hermes. A profile Hermes deleted (its tombstone in
    ``profiles/.deleted/``) and dot-folders such as that tombstone folder are never listed.
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

    # The canonical default (honours profile switching / $HERMES_HOME).
    try:
        _add(constants.hermes_home())
    except Exception:  # pragma: no cover - defensive
        pass

    for root in _hermes_roots():
        if not root.is_dir():
            continue
        _add(root)
        profiles_dir = root / "profiles"
        try:
            children = sorted(profiles_dir.iterdir()) if profiles_dir.is_dir() else []
        except OSError:
            children = []
        for child in children:
            if (child.is_dir() and not child.name.startswith(".") and not _profile_deleted(child)
                    and (include_managed or not is_managed_blackbox_chat_profile(child))):
                _add(child)
    return homes


def _hermes_roots() -> list[Path]:
    """The Hermes roots on this machine, as Hermes itself resolves them: the active home's root
    (``constants.hermes_root``: a custom or Docker root's ``<root>/profiles/<name>`` → ``<root>``)
    and the platform default (``~/.hermes`` with ``HERMES_DATA_DIR_SUFFIX``, ``%LOCALAPPDATA%/hermes``
    on Windows). WHY not ``Path.home() / ".hermes"``: that missed every other layout (CLAUDE.md:
    never hardcode ``~/.hermes``)."""
    roots = [constants.hermes_root()]
    try:
        from hermes_constants import get_default_hermes_root

        roots.append(Path(get_default_hermes_root(home="")))   # "": no explicit home -> the platform default
    except (ImportError, AttributeError, OSError, ValueError, TypeError):   # an older Hermes: the active root is what we know
        pass
    return roots


def _profile_deleted(profile_home: Path) -> bool:
    """Whether Hermes deleted this named profile (``hermes_constants.named_profile_is_deleted``)."""
    try:
        from hermes_constants import named_profile_is_deleted
    except ImportError:   # an older Hermes without tombstones
        return False
    try:
        return bool(named_profile_is_deleted(profile_home))
    except OSError:
        return False


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
    disabled = plugins.get("disabled")
    if isinstance(disabled, list) and "blackbox" in disabled:   # an uninstall that kept a bundling Hermes (KI-610)
        plugins["disabled"] = [name for name in disabled if name != "blackbox"]

@serial.serialized
@declined.remembers("hermes", switched_off=False)
@yaml_files.edits_config
def attach_hermes(home: Path, *, dry_run: bool = False) -> AttachReport:
    """Enable Blackbox in a single Hermes *home*.

    Copies the plugin into ``<home>/plugins/blackbox/`` (only when missing or a
    version mismatch) and adds ``blackbox`` to ``plugins.enabled`` in
    ``<home>/config.yaml`` idempotently, preserving every other key. Returns a
    per-target report dict; fails open (``ok=False`` + ``error`` on failure).
    """
    home = home.expanduser()
    report: AttachReport = {
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


@serial.serialized
@declined.remembers("hermes", switched_off=True)
@yaml_files.edits_config
def detach_hermes(home: Path, *, remove_files: bool = False, dry_run: bool = False) -> AttachReport:
    """Disable Blackbox in a single Hermes *home*.

    Removes ``blackbox`` from ``plugins.enabled`` (idempotent) and, when
    *remove_files* is set, deletes ``<home>/plugins/blackbox/``. Fails open.
    """
    home = home.expanduser()
    report: AttachReport = {
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
