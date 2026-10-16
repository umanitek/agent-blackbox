"""Protecting OpenClaw workspaces through the bundled JS bridge plugin.

Wires the bridge into each workspace's plugin load paths (replacing stale
Blackbox entries, keeping everything else), and removes it on detach.
"""

from __future__ import annotations
from . import declined

import logging
import json
import os
import shutil
from pathlib import Path
from typing import Any, Dict, Optional
from ..kernel import constants
from . import openclaw_discovery
from . import plugin_copy
from ..kernel import yaml_files

logger = logging.getLogger(__name__)

def _openclaw_plugin_source() -> Optional[Path]:
    """Locate the OpenClaw JS plugin wherever this Blackbox copy runs from.

    An installed copy (``~/.hermes/plugins/blackbox``) has no sibling
    ``integrations/``, so the plugin is bundled into ``_openclaw`` at copy time
    and checked first; a repo checkout finds it via ``integrations/openclaw``.
    Returns ``None`` only when neither exists (e.g. a bare package with no repo),
    which the caller reports as an unprotected OpenClaw rather than a crash.
    """
    for candidate in (plugin_copy._bundled_openclaw_dir(), plugin_copy._repo_openclaw_dir()):
        if plugin_copy._is_openclaw_plugin_dir(candidate):
            return candidate
    return None


def _openclaw_load_paths_entry() -> Optional[str]:
    """Absolute path OpenClaw should load the Blackbox plugin from, or ``None``."""
    src = _openclaw_plugin_source()
    return str(src) if src is not None else None


def _same_openclaw_load_path(left: Any, right: Any) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    try:
        return Path(left).expanduser().resolve() == Path(right).expanduser().resolve()
    except Exception:
        return os.path.normcase(os.path.normpath(left)) == os.path.normcase(os.path.normpath(right))


def _is_blackbox_openclaw_load_path(value: Any) -> bool:
    """Recognize current or stale Blackbox OpenClaw plugin paths.

    Existing paths are identified by manifest id.  Known checkout/bundle path
    shapes cover stale directories that no longer exist, while deliberately not
    matching the pre-Blackbox ``plugins/guardian/_openclaw`` integration.
    """
    if not isinstance(value, str) or not value.strip():
        return False
    path = Path(value).expanduser()
    try:
        manifest = path / "openclaw.plugin.json"
        if manifest.is_file():
            data = json.loads(manifest.read_text(encoding="utf-8-sig"))
            if isinstance(data, dict) and data.get("id") == "blackbox":
                return True
    except Exception:
        pass
    normalized = value.replace("\\", "/").rstrip("/").lower()
    if normalized.endswith("/plugins/blackbox/_openclaw"):
        return True
    if normalized.endswith("/integrations/openclaw"):
        return any(
            marker in normalized
            for marker in ("/agent-blackbox/", "/blackbox-", "/blackbox/")
        )
    return False


def _is_missing_pre_blackbox_load_path(value: Any) -> bool:
    """True for a vanished pre-Blackbox OpenClaw bundle path."""
    if not isinstance(value, str) or not value.strip():
        return False
    normalized = value.replace("\\", "/").rstrip("/").lower()
    if not normalized.endswith("/plugins/guardian/_openclaw"):
        return False
    try:
        return not Path(value).expanduser().exists()
    except OSError:
        return True


@declined.remembers("openclaw", switched_off=False)
def attach_openclaw(workspace: Path, *, dry_run: bool = False) -> dict[str, Any]:
    """Enable Blackbox in a single OpenClaw *workspace*.

    Backs up ``openclaw.json``, then idempotently merges:

    * ``plugins.allow`` += ``"blackbox"``
    * ``plugins.load.paths`` += the absolute path to ``integrations/openclaw``
    * ``plugins.entries.blackbox`` = the Blackbox config + hook grants

    Preserves every other key. Fails open per target.
    """
    workspace = workspace.expanduser()
    config_path = openclaw_discovery._openclaw_config_path(workspace)
    report: dict[str, Any] = {
        "target": str(workspace),
        "config_path": str(config_path),
        "kind": "openclaw",
        "ok": False,
        "protected": False,
        "changed": False,
        "already": False,
        "backed_up": False,
        "dry_run": dry_run,
    }
    try:
        if not config_path.is_file():
            raise FileNotFoundError(f"OpenClaw config not found: {config_path}")
        data = openclaw_discovery._load_openclaw_config(config_path)

        detected_version = openclaw_discovery._openclaw_version(data)
        if detected_version is not None:
            report["version"] = ".".join(str(part) for part in detected_version)
            if detected_version < openclaw_discovery._OPENCLAW_MIN_VERSION:
                report["unsupported"] = True
                report["error"] = (
                    f"OpenClaw {report['version']} is unsupported; "
                    f"Blackbox requires OpenClaw {openclaw_discovery._OPENCLAW_MIN_VERSION_TEXT}+"
                )
                return report

        cfg = load_blackbox_config_snapshot()
        load_path = _openclaw_load_paths_entry()
        if load_path is None:
            report["note"] = (
                "integrations/openclaw not found next to this Blackbox copy "
                "(likely copied into a user home); recording intent without a load path."
            )
            logger.info("blackbox.attach: %s", report["note"])

        changed = _merge_openclaw(data, cfg, load_path)
        report["changed"] = changed
        report["already"] = not changed
        report["protected"] = load_path is not None and not changed if dry_run else load_path is not None

        if changed and not dry_run:
            # Back up before writing.
            if config_path.exists():
                backup = config_path.with_name(config_path.name + ".blackbox.bak")
                shutil.copy2(config_path, backup)
                report["backed_up"] = True
            yaml_files.atomic_write(config_path, json.dumps(data, indent=2) + "\n")
        # Honest status: without a load path the blackbox block is recorded but
        # OpenClaw won't actually load the hook, so this workspace isn't protected.
        report["ok"] = load_path is not None
    except Exception as exc:
        logger.debug("blackbox.attach: attach_openclaw(%s) failed: %s", workspace, exc)
        report["error"] = str(exc)
    return report


def _desired_entry(cfg: dict[str, Any]) -> dict[str, Any]:
    """The ``plugins.entries.blackbox`` block the bridge reads (the ONE shape attach writes)."""
    return {
        "enabled": True,
        "config": {
            "dkgUrl": cfg["dkg_url"],
            "dkgHome": cfg["dkg_home"],
            "contextGraphId": cfg["context_graph_id"],
            # The graph's owner, dialled before the first share: an edge that reaches the
            # graph only through relays gets the graph's definition from it (DKG #3264).
            "graphPeerId": cfg.get("graph_peer_id", ""),
            "mode": cfg["mode"],
            # Point OpenClaw's local findings log at THIS Hermes blackbox home so
            # the one dashboard surfaces OpenClaw detections too. OpenClaw writes
            # findings.openclaw.jsonl here; the dashboard merges all findings*.jsonl.
            "blackboxHome": cfg.get("blackbox_home") or str(constants.blackbox_home()),
            # KI-182 port: the bridge shares with the SAME community — the shared memory of
            # contextGraphId (one graph since 2026-10-16) — under the same gates: the switch
            # and the cap travel with it (consent is read from blackboxHome, so one consent
            # record covers both runtimes).
            "report": bool(cfg.get("report", False)),   # opt-in (2026-10-16); the consent record still gates sends
            "dailyReportLimit": int(cfg.get("daily_report_limit") or constants.DEFAULT_DAILY_REPORT_LIMIT),
            "reportMinSeverity": cfg.get("report_min_severity", "high"),
        },
        "hooks": {"allowConversationAccess": True},
    }


def _merge_openclaw(data: dict[str, Any], cfg: dict[str, Any], load_path: Optional[str]) -> bool:
    """Idempotently merge the Blackbox block into an ``openclaw.json`` dict.

    Returns ``True`` when anything changed. Pure (mutates *data* in place); the
    caller decides whether to persist.
    """
    changed = False
    plugins = data.setdefault("plugins", {})
    if not isinstance(plugins, dict):
        plugins = {}
        data["plugins"] = plugins

    allow = plugins.get("allow")
    if not isinstance(allow, list):
        allow = []
        plugins["allow"] = allow
    if "blackbox" not in allow:
        allow.append("blackbox")
        changed = True

    if load_path is not None:
        load = plugins.get("load")
        if not isinstance(load, dict):
            load = {}
            plugins["load"] = load
        paths = load.get("paths")
        if not isinstance(paths, list):
            paths = []
            load["paths"] = paths
        # One plugin id must resolve from one source.  Remove older Blackbox
        # checkout/bundle paths so OpenClaw cannot load a stale copy first.
        kept = [
            path
            for path in paths
            if not _is_missing_pre_blackbox_load_path(path)
            and (_same_openclaw_load_path(path, load_path) or not _is_blackbox_openclaw_load_path(path))
        ]
        if kept != paths:
            paths[:] = kept
            changed = True
        if not any(_same_openclaw_load_path(path, load_path) for path in paths):
            paths.append(load_path)
            changed = True

    entries = plugins.get("entries")
    if not isinstance(entries, dict):
        entries = {}
        plugins["entries"] = entries
    desired_entry = _desired_entry(cfg)
    if entries.get("blackbox") != desired_entry:
        entries["blackbox"] = desired_entry
        changed = True
    return changed


@declined.remembers("openclaw", switched_off=True)
def detach_openclaw(workspace: Path, *, dry_run: bool = False) -> dict[str, Any]:
    """Disable Blackbox in a single OpenClaw *workspace* (idempotent, fail-open)."""
    workspace = workspace.expanduser()
    config_path = openclaw_discovery._openclaw_config_path(workspace)
    report: dict[str, Any] = {
        "target": str(workspace),
        "kind": "openclaw",
        "ok": False,
        "changed": False,
        "already": False,
        "dry_run": dry_run,
    }
    try:
        if not config_path.exists():
            report["already"] = True
            report["ok"] = True
            return report
        data = openclaw_discovery._load_openclaw_config(config_path)
        plugins = data.get("plugins")
        changed = False
        if isinstance(plugins, dict):
            allow = plugins.get("allow")
            if isinstance(allow, list) and "blackbox" in allow:
                plugins["allow"] = [p for p in allow if p != "blackbox"]
                changed = True
            load = plugins.get("load")
            if isinstance(load, dict) and isinstance(load.get("paths"), list):
                # Remove ANY blackbox openclaw load path, not just the one that
                # resolves from this location — detaching an installed home would
                # otherwise orphan an entry pointing at a now-removed plugin.
                kept = [
                    p for p in load["paths"]
                    if not _is_blackbox_openclaw_load_path(p)
                ]
                if len(kept) != len(load["paths"]):
                    load["paths"] = kept
                    changed = True
            entries = plugins.get("entries")
            if isinstance(entries, dict) and "blackbox" in entries:
                del entries["blackbox"]
                changed = True
        report["changed"] = changed
        report["already"] = not changed
        if changed and not dry_run:
            yaml_files.atomic_write(config_path, json.dumps(data, indent=2) + "\n")
        report["ok"] = True
    except Exception as exc:
        logger.debug("blackbox.attach: detach_openclaw(%s) failed: %s", workspace, exc)
        report["error"] = str(exc)
    return report


# ---------------------------------------------------------------------------
# Config snapshot (for the OpenClaw entry) — decoupled from the running config
# ---------------------------------------------------------------------------


def load_blackbox_config_snapshot() -> dict[str, Any]:
    """Resolve the Blackbox config values to write into an OpenClaw workspace.

    Uses :func:`config.load_blackbox_config` when available (honours env +
    config.yaml), else falls back to constants. Kept tiny so ``attach`` stays
    testable without a full hermes config.
    """
    try:
        from ..kernel.config import load_blackbox_config

        cfg = load_blackbox_config()
        return {
            "dkg_url": cfg.dkg_url,
            "dkg_home": cfg.dkg_home,
            "context_graph_id": cfg.context_graph_id,
            "graph_peer_id": cfg.graph_peer_id,
            "mode": cfg.mode,
            "blackbox_home": str(constants.blackbox_home()),
            "report": cfg.report,
            "daily_report_limit": cfg.daily_report_limit,
            "report_min_severity": cfg.report_min_severity,
        }
    except Exception:
        return {
            "dkg_url": constants.DEFAULT_DKG_URL,
            "dkg_home": str(constants.blackbox_dkg_home()),
            "context_graph_id": constants.DEFAULT_CONTEXT_GRAPH_ID,
            "graph_peer_id": constants.DEFAULT_GRAPH_PEER_ID,
            "mode": "audit",
            "blackbox_home": str(constants.blackbox_home()),
            "report": False,   # the config could not be read: send nothing rather than guess
            "daily_report_limit": constants.DEFAULT_DAILY_REPORT_LIMIT,
            "report_min_severity": "high",
        }
