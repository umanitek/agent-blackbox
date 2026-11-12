"""Attach — wire Blackbox protection into the agents the operator chooses on this machine.

Finds Hermes homes and OpenClaw workspaces, copies the plugin in (or points
OpenClaw at the bundled JS bridge), and enables it — idempotent, fail-open per
target. Callers use this surface:

* :func:`attach_all` / :func:`detach_all` — every target at once (``blackbox attach --all``,
  the dashboard's discovery, the opt-in ``auto_attach`` sweep).
* :func:`attach_hermes` / :func:`detach_hermes`, :func:`attach_openclaw` /
  :func:`detach_openclaw` — one target.
* :func:`is_declined` — whether the operator switched a target off (automatic sweeps skip it).
* :func:`automatic_targets` — which targets an automatic sweep may attach (``auto_attach`` off by
  default: none new); :func:`is_attached` — whether a target has Blackbox switched on now.
* :func:`attach_named` — attach exactly the targets the operator named (``blackbox attach <home>``).
* :func:`discover_hermes_homes`, :func:`discover_openclaw_workspaces`,
  :func:`is_managed_blackbox_chat_profile`, :func:`enabled_list_has`.
* :func:`add_attach_parsers`, :func:`cmd_attach` / :func:`cmd_detach` — the CLI commands, and the
  :func:`print_hermes_attach_row` / :func:`print_openclaw_attach_row` report rows.
* :func:`copy_plugin_tree`, :func:`repo_root` — the copy step and the source
  checkout root (used by the dev sync script and the dashboard).

Internals: :mod:`.plugin_copy` · :mod:`.hermes_homes` · :mod:`.openclaw_discovery`
· :mod:`.openclaw_bridge` · :mod:`.openclaw_json5` · :mod:`.sweep`.

Usage::

    from .. import attach
    report = attach.attach_named(["~/.hermes"])            # what `blackbox attach ~/.hermes` does
    report = attach.attach_all(explicit=True)               # what `blackbox attach --all` does
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping, Optional

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
from .sweep import attach_all, attach_named, automatic_targets, detach_all, is_attached

def set_protection(kind: str, target: str, enabled: bool) -> Optional[AttachReport]:
    """Switch protection of one agent on or off — THE dispatch by agent kind ("hermes" /
    "openclaw") the dashboard's rescan and its protection route share; None for a kind
    Blackbox does not know."""
    switch = {"hermes": (detach_hermes, attach_hermes), "openclaw": (detach_openclaw, attach_openclaw)}.get(str(kind).lower())
    return switch[bool(enabled)](Path(target)) if switch else None


def is_protected(row: Mapping[str, Any]) -> bool:
    """Whether an attach row says Blackbox loads there: ``protected``, or for rows that do not
    say (older, or a detach) ``already``."""
    return bool(row.get("protected", row.get("already")))


__all__ = [
    "AttachReport",
    "add_attach_parsers",
    "attach_all",
    "attach_hermes",
    "attach_named",
    "attach_openclaw",
    "automatic_targets",
    "cmd_attach",
    "cmd_detach",
    "copy_plugin_tree",
    "detach_all",
    "detach_hermes",
    "detach_openclaw",
    "discover_hermes_homes",
    "discover_openclaw_workspaces",
    "enabled_list_has",
    "is_attached",
    "is_declined",
    "is_managed_blackbox_chat_profile",
    "is_protected",
    "print_hermes_attach_row",
    "print_openclaw_attach_row",
    "repo_root",
    "set_protection",
]
