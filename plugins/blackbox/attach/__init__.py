"""Attach — wire Blackbox protection into the agents the operator chooses on this machine.

Finds Hermes homes and OpenClaw workspaces, copies the plugin in (or points
OpenClaw at the bundled JS bridge), and enables it — idempotent, fail-open per
target. Callers use this surface:

* :func:`attach_all` / :func:`detach_all` — every target at once (``blackbox attach --all``,
  the dashboard's discovery, the opt-in ``auto_attach`` sweep).
* :func:`attach_hermes` / :func:`detach_hermes`, :func:`attach_openclaw` /
  :func:`detach_openclaw` — one target.
* :func:`is_declined` — whether the operator switched a target off (automatic sweeps skip it).
* :func:`discovered_target` — the discovered agent folder a caller-named target is, or None (a
  route acts only on agents this machine has).
* :func:`automatic_targets` — which targets an automatic sweep may attach (``auto_attach`` off by
  default: none new); :func:`is_attached` — whether a target has Blackbox switched on now.
* :func:`attach_named` — attach exactly the targets the operator named (``blackbox attach <home>``).
* :func:`protect_automatically` — the sweep's attach step (remembers what it protected by itself);
  :func:`coverage` — the switch, the unprotected agents and those recent protections;
  :func:`agent_label` — "Hermes · coder" / "OpenClaw · <folder>".
* :func:`discover_hermes_homes`, :func:`discover_openclaw_workspaces`,
  :func:`is_managed_blackbox_chat_profile`, :func:`enabled_list_has`.
* :func:`add_attach_parsers`, :func:`cmd_attach` / :func:`cmd_detach` — the CLI commands, and the
  :func:`print_hermes_attach_row` / :func:`print_openclaw_attach_row` report rows.
* :func:`copy_plugin_tree`, :func:`repo_root` — the copy step and the source
  checkout root (used by the dev sync script and the dashboard).
* :data:`ATTACH_LOCK` — the one lock every writer above holds (:mod:`.serial`); a caller that
  decides and attaches as one step (the dashboard's rescan) holds it around the whole step.

Internals: :mod:`.plugin_copy` · :mod:`.hermes_homes` · :mod:`.openclaw_discovery`
· :mod:`.openclaw_bridge` · :mod:`.openclaw_json5` · :mod:`.sweep` · :mod:`.coverage` · :mod:`.serial`.

Usage::

    from .. import attach
    report = attach.attach_named(["~/.hermes"])            # what `blackbox attach ~/.hermes` does
    report = attach.attach_all(explicit=True)               # what `blackbox attach --all` does
"""

from __future__ import annotations

from typing import Any, Mapping

from .coverage import agent_label, coverage, protect_automatically
from .command import add_attach_parsers, cmd_attach, cmd_detach, print_hermes_attach_row, print_openclaw_attach_row
from .hermes_homes import (
    attach_hermes,
    detach_hermes,
    discover_hermes_homes,
    enabled_list_has,
    is_managed_blackbox_chat_profile,
)
from .openclaw_bridge import attach_openclaw, detach_openclaw
from .openclaw_discovery import discover_openclaw_workspaces
from .plugin_copy import copy_plugin_tree, repo_root
from .declined import is_declined
from .report import AttachReport
from .serial import ATTACH_LOCK
from .sweep import attach_all, attach_named, automatic_targets, detach_all, discovered_target, is_attached, set_protection

def is_protected(row: Mapping[str, Any]) -> bool:
    """Whether an attach row says Blackbox loads there: ``protected``, or for rows that do not
    say (older, or a detach) ``already``."""
    return bool(row.get("protected", row.get("already")))


__all__ = [
    "ATTACH_LOCK",
    "AttachReport",
    "add_attach_parsers",
    "agent_label",
    "attach_all",
    "attach_hermes",
    "attach_named",
    "attach_openclaw",
    "automatic_targets",
    "cmd_attach",
    "cmd_detach",
    "copy_plugin_tree",
    "coverage",
    "detach_all",
    "detach_hermes",
    "detach_openclaw",
    "discover_hermes_homes",
    "discover_openclaw_workspaces",
    "discovered_target",
    "enabled_list_has",
    "is_attached",
    "is_declined",
    "is_managed_blackbox_chat_profile",
    "is_protected",
    "print_hermes_attach_row",
    "print_openclaw_attach_row",
    "protect_automatically",
    "repo_root",
    "set_protection",
]
