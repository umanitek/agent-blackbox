"""Attach / detach everything this machine has, in one call — and which targets an
automatic sweep may touch.

:func:`attach_all` / :func:`detach_all` run the Hermes and OpenClaw
discoverers and return a per-target report the CLI and dashboard render.
:func:`automatic_targets` is THE policy every automatic sweep (the dashboard's
rescan, its manual refresh) asks before it attaches anything; :func:`is_attached`
says whether a target has Blackbox switched on now.

Why automatic sweeps are narrow: every Hermes profile is its own trust and
credential boundary, so Blackbox joins one only when the operator names it
(``blackbox attach <home>``, ``--all``, the dashboard's per-agent switch) or
opts into ``auto_attach``. Left to itself a sweep only keeps already-attached
targets current (a fresh plugin copy after an upgrade) and never re-adds one
the operator switched off (:mod:`.declined`).
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterable

from ..kernel import yaml_files
from ..kernel.config import load_blackbox_config
from . import declined
from . import hermes_homes
from . import openclaw_bridge
from . import openclaw_discovery

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def attach_all(*, hermes: bool = True, openclaw: bool = True, dry_run: bool = False,
               explicit: bool = False, auto_attach: bool | None = None) -> dict[str, Any]:
    """Attach Blackbox to the discovered targets this call may touch. Returns a combined report.

    * ``explicit=True`` — the operator's own ``blackbox attach`` — attaches every target,
      which also clears a switch-off (:mod:`.declined`).
    * ``dry_run=True`` reports every target not switched off, and writes nothing.
    * Otherwise this is an AUTOMATIC sweep and asks :func:`automatic_targets` (a full pass):
      with ``auto_attach`` off (the default) only targets already attached are refreshed and
      nothing new is joined (KI-492: ``blackbox dashboard`` runs at every login and used to
      attach every agent on the machine). *auto_attach* defaults to the saved setting.
    """
    report: dict[str, Any] = {"hermes": [], "openclaw": [], "dry_run": dry_run}
    targets: list[Target] = []
    if hermes:
        targets += [("hermes", home) for home in hermes_homes.discover_hermes_homes()]
    if openclaw:
        targets += [("openclaw", workspace) for workspace in openclaw_discovery.discover_openclaw_workspaces()]
    if explicit:
        chosen = targets
    elif dry_run:
        chosen = [target for target in targets if not declined.is_declined(*target)]
    else:
        if auto_attach is None:
            auto_attach = load_blackbox_config().auto_attach
        allowed = automatic_targets(targets, (), reconcile=True, auto_attach=auto_attach)
        chosen = [target for target in targets if target in allowed]
    attach_one = {"hermes": hermes_homes.attach_hermes, "openclaw": openclaw_bridge.attach_openclaw}
    for kind, path in chosen:
        report[kind].append(attach_one[kind](path, dry_run=dry_run))
    report["count"] = _protected_count(report)
    return report


def attach_named(paths: Iterable[str | Path], *, hermes: bool = True, openclaw: bool = True,
                 dry_run: bool = False) -> dict[str, Any]:
    """Attach exactly the targets the operator named (``blackbox attach <home> …``).

    Each path's kind is inferred: a discovered OpenClaw workspace is ``openclaw``; a
    discovered Hermes home, or any folder holding a Hermes ``config.yaml``, is ``hermes``.
    Anything else is listed under ``"unknown"`` and nothing is written for it. Returns the
    :func:`attach_all` report shape plus ``"unknown"`` (the paths that were not agents).
    Naming a target the operator switched off earlier switches it back on (:mod:`.declined`)."""
    report: dict[str, Any] = {"hermes": [], "openclaw": [], "dry_run": dry_run, "unknown": []}
    workspaces = {_same_path(ws) for ws in openclaw_discovery.discover_openclaw_workspaces()}
    homes = {_same_path(home) for home in hermes_homes.discover_hermes_homes()}
    for raw in paths:
        path = Path(str(raw)).expanduser()
        key = _same_path(path)
        if key in workspaces:
            if openclaw:
                report["openclaw"].append(openclaw_bridge.attach_openclaw(path, dry_run=dry_run))
        elif key in homes or (path / "config.yaml").is_file():
            if hermes:
                report["hermes"].append(hermes_homes.attach_hermes(path, dry_run=dry_run))
        else:
            report["unknown"].append(str(path))
    report["count"] = _protected_count(report)
    return report


def _same_path(path: Path) -> str:
    """One spelling per folder, so ``~/x``, ``/home/me/x/`` and a symlink to it compare equal."""
    try:
        return str(path.expanduser().resolve())
    except OSError:
        return str(path.expanduser())


#: One discovered target: (kind, path) with kind ``"hermes"`` or ``"openclaw"``.
Target = tuple[str, str]


def is_attached(kind: str, target: str | Path) -> bool:
    """Whether Blackbox is switched on in this target's own config right now: ``blackbox`` in a
    Hermes home's ``plugins.enabled``, or in an OpenClaw config's ``plugins.allow``. An
    unreadable config reads as not attached (a sweep then leaves it alone)."""
    path = Path(str(target)).expanduser()
    try:
        if kind == "hermes":
            return hermes_homes.enabled_list_has(yaml_files.load_yaml(path / "config.yaml"), "blackbox")
        config_path = openclaw_discovery._openclaw_config_path(path)
        if not config_path.exists():
            return False
        allow = (openclaw_discovery._load_openclaw_config(config_path).get("plugins") or {}).get("allow")
        return isinstance(allow, list) and "blackbox" in allow
    except Exception as exc:   # a broken config is the operator's to fix; never a reason to write it
        logger.debug("blackbox.attach: could not read %s %s: %s", kind, path, exc, exc_info=True)
        return False


def automatic_targets(current: Iterable[Target], known: Iterable[Target], *, reconcile: bool,
                      auto_attach: bool) -> set[Target]:
    """The targets an automatic sweep may attach this round.

    *current* is what discovery found now, *known* what the previous round found;
    *reconcile* is the periodic (or manual) full pass. A target the operator switched
    off is never included.

    * ``auto_attach`` on (the operator's explicit opt-in): newly appeared targets, and
      on a reconcile every target — the self-heal.
    * ``auto_attach`` off (the default): nothing new, ever; a reconcile re-hooks only
      targets already attached (keeps their plugin copy current).

        targets = automatic_targets(found, previous, reconcile=force, auto_attach=cfg.auto_attach)
    """
    current = set(current)
    if auto_attach:
        candidates = current if reconcile else current - set(known)
    else:
        candidates = {target for target in current if is_attached(*target)} if reconcile else set()
    return {target for target in candidates if not declined.is_declined(*target)}


def detach_all(
    *, hermes: bool = True, openclaw: bool = True, remove_files: bool = False, dry_run: bool = False
) -> dict[str, Any]:
    """Detach Blackbox from every discovered target. Returns a combined report."""
    report: dict[str, Any] = {"hermes": [], "openclaw": [], "dry_run": dry_run}
    if hermes:
        for home in hermes_homes.discover_hermes_homes():
            report["hermes"].append(hermes_homes.detach_hermes(home, remove_files=remove_files, dry_run=dry_run))
    if openclaw:
        for ws in openclaw_discovery.discover_openclaw_workspaces():
            report["openclaw"].append(openclaw_bridge.detach_openclaw(ws, dry_run=dry_run))
    return report


def _protected_count(report: dict[str, Any]) -> int:
    """Number of targets Blackbox is (now) protecting in an attach report."""
    total = 0
    for row in report.get("hermes", []):
        if row.get("ok"):
            total += 1
    for row in report.get("openclaw", []):
        if row.get("ok"):
            total += 1
    return total
