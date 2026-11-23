"""Sandbox permissions: named abilities the person unlocks or locks for AI agents inside Blackbox's
sandbox — per agent, per project, or both (design "Sandbox permissions", 2026-11-23; founder
decisions F1–F9).

The sandbox is on by default and closes more than an agent sometimes needs (Docker, global
installs, the clipboard …). Each such ability is a :class:`~.model.Permission` in the
:mod:`.catalogue`, with a mode (block / ask / allow) the person sets per scope; the most specific
scope wins (F6). A permission is enforced either in the Seatbelt profile the agent starts in
(fixed at its start: a change applies at its next start) or by a broker that does the action
outside the sandbox after Blackbox's checks (applies at once). What no permission unlocks — the
never-list — is rendered last in every profile, so no rule can lift it.

Turning protection down waits for the person: :func:`section_weakening` is registered with the
approval gate for the whole ``agent_sandbox`` section (``approvals.SECTION_JUDGES``, wired by the
dashboard), and the permission endpoints judge each write the same way (:mod:`.judge`).

Pattern: **Facade** over the catalogue, the config section and the judge; the catalogue is a
table of **Strategy** records (data, no subclasses).

Usage::

    decide("docker", "claude-code", "/Users/me/work/shop")   # Mode.ASK
    section_weakening({"permissions": [...]})                  # why the change waits, or []
"""

from __future__ import annotations

from typing import Any

from .....kernel import settings as kernel_settings
from . import catalogue
from .catalogue import BY_ID, NEVER, NOT_CONTROLLABLE, PERMISSIONS
from .judge import loosened
from .model import Access, Allowances, Choice, FolderRule, Mode, Permission, Route, Rule, Scope, Settings
from .section import SECTION, current, parse, stored, validate_section, with_legacy

kernel_settings.SECTION_VALIDATORS[SECTION] = validate_section


def decide(permission: str, agent: str = "", folder: str = "") -> Mode:
    """The mode in force for *permission* when *agent* works in absolute *folder*."""
    return current().mode(BY_ID[permission], agent, folder)


def section_weakening(raw: Any) -> list[str]:
    """Why writing *raw* as the ``agent_sandbox`` section turns protection down (``[]`` when it does
    not, or when the writer will refuse it anyway)."""
    errors: list[str] = []
    after = parse(raw, errors)
    return [] if errors else loosened(stored(), with_legacy(after))


__all__ = ["BY_ID", "NEVER", "NOT_CONTROLLABLE", "PERMISSIONS", "SECTION", "Access", "Allowances", "Choice", "FolderRule", "Mode",
           "Permission", "Route", "Rule", "Scope", "Settings", "catalogue", "current", "decide", "loosened", "section_weakening",
           "stored", "validate_section"]
