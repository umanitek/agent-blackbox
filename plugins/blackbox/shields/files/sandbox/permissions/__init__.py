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

import os
from typing import Any

from .....kernel import constants, persistence_places, settings as kernel_settings
from .....kernel.config import load_blackbox_config
from ... import mode as mode_module
from . import answers, catalogue, grants, requests
from .api import API_WEAKENING, API_WRITES, not_here, view
from .catalogue import BY_ID, NEVER, NOT_CONTROLLABLE, PERMISSIONS, profile_permissions
from .judge import loosened
from .model import Access, Allowances, Choice, FolderLimits, FolderRule, Mode, Permission, PermissionRequest, Route, Rule, Scope, Settings
from .section import SECTION, current, parse, stored, validate_section, with_legacy

kernel_settings.SECTION_VALIDATORS[SECTION] = validate_section


def decide(permission: str, agent: str = "", folder: str = "") -> Mode:
    """The mode in force for *permission* when *agent* works in absolute *folder*."""
    return current().mode(BY_ID[permission], agent, folder)


def folder_limits(settings: Settings, agent: str = "", folder: str = "") -> FolderLimits:
    """The folder rules that apply to *agent* working in absolute *folder* ("" = no project), as
    canonical paths (the kernel matches real paths): kept out, and read only unless also kept out.
    The sandbox profile (:func:`allowances`) and the hook judgement (``files.folder_rules``) both
    read this one answer (LES-137, F9)."""
    real = [(os.path.realpath(os.path.expanduser(each.path)), each.access) for each in settings.folder_rules(agent, folder)]
    hidden = tuple(dict.fromkeys(path for path, access in real if access is Access.NONE))
    read_only = tuple(dict.fromkeys(path for path, access in real if access is Access.READ and path not in hidden))
    return FolderLimits(hidden=hidden, read_only=read_only)


def allowances(settings: Settings, agent: str = "", folder: str = "") -> Allowances:
    """What one profile lets through for *agent* working in absolute *folder* ("" = no project):
    the profile-route permissions in force as ALLOW, local-ports' reachable ports, and the folder
    rules that apply, as canonical paths (the kernel matches real paths). "Ask" is refused in the
    profile until the person answers (a profile is fixed when the agent starts)."""
    lifted = frozenset(each.id for each in profile_permissions() if settings.mode(each, agent, folder) is Mode.ALLOW)
    refused = frozenset(each.id for each in profile_permissions()) - lifted
    limits = folder_limits(settings, agent, folder)
    tools: tuple[list[str], list[str]] = ([], [])
    if "tool-folders" not in lifted:
        tools = persistence_places.user_path_folders(os.path.realpath(os.path.expanduser("~")), os.environ.get("PATH", ""),
                                                     getattr(os, "getuid", lambda: -1)(), exclude=(os.path.realpath(constants.blackbox_home()),))
    return Allowances(lifted=lifted, refused=refused, ports=settings.ports("local-ports", agent, folder),
                      dashboard_port=load_blackbox_config().dashboard_port, hidden=limits.hidden, read_only=limits.read_only,
                      tool_folders=tuple(tools[0]), tool_globs=tuple(tools[1]))


def _scope_of(settings: Settings, permission: str, agent: str, folder: str) -> Scope:
    """The scope a request is for: the deciding rule's project, else *folder* in its one spelling."""
    rule = settings.rule(permission, agent, folder)
    project = rule.scope.project if rule is not None and rule.scope.project else _spelling(folder)
    return Scope(agent=agent, project=project)


def _open(permission: str, scope: Scope, instance: str, what: str, pid: int, detail: str = "") -> bool:
    opened = requests.raise_request(permission, scope.agent, instance, scope.project, what, pid, detail=detail)
    if opened is not None:
        answers.requested(opened)
    return opened is not None


def ask(permission: str, agent: str, instance: str, folder: str, what: str, pid: int = 0, even_on_allow: bool = False) -> bool:
    """Opens a request for *permission* when it is on "ask" for *agent* in *folder* (*even_on_allow*:
    on "allow" too — a broker that must not act unasked); True when one was opened."""
    settings = current()
    mode = settings.mode(BY_ID[permission], agent, folder)
    if mode is not Mode.ASK and not (even_on_allow and mode is Mode.ALLOW):
        return False
    return _open(permission, _scope_of(settings, permission, agent, folder), instance, what, pid)


#: What a broker does with a request (:func:`broker_decision`).
ALLOWED, WAITING, REFUSED = "allow", "wait", "block"


def broker_decision(permission: str, agent: str, instance: str, folder: str, what: str, pid: int = 0, show_whole: bool = False) -> str:
    """For a broker asked to do *what* (Blackbox's own words for it, e.g. ``brew install tree``):
    :data:`ALLOWED` (the mode allows it, or the person allowed this exact request once — the grant
    is spent), :data:`REFUSED` (blocked, or the person kept it blocked lately, or the request
    bounds are reached) or :data:`WAITING` (a request is open: ask again shortly). *show_whole*: the
    person reads all of *what* before answering (an AppleScript), not only its first words."""
    settings = current()
    mode = settings.mode(BY_ID[permission], agent, folder)
    if mode is not Mode.ASK:
        return ALLOWED if mode is Mode.ALLOW else REFUSED
    scope = _scope_of(settings, permission, agent, folder)
    if grants.use(permission, scope, requests.digest(permission, agent, scope.project, what)):
        return ALLOWED
    asked = requests.state(instance or agent, permission)
    if asked == requests.COOLING:
        return REFUSED
    opened = asked == requests.OPEN or _open(permission, scope, instance, what, pid, what if show_whole else "")
    return WAITING if opened else REFUSED


#: Which permission a refusal kind asks for when several share it (``open`` of an app vs a link:
#: a link goes through Blackbox's ``open`` stand-in, so a bare LaunchServices refusal is an app).
_FIRST_FOR_KIND = {catalogue.KIND_OPEN_APP: "open-apps"}


def refused(kind: str, agent: str, instance: str, folder: str, pid: int = 0) -> bool:
    """A sandbox refusal of *kind* seen on *agent*'s call: asks the person when the permission it
    means is on "ask" (:func:`ask`); True when a request was opened."""
    wanted = _FIRST_FOR_KIND.get(kind) or next((each.id for each in PERMISSIONS if kind in each.refusal_kinds), "")
    if not wanted or not BY_ID[wanted].controllable:
        return False
    return ask(wanted, agent, instance, folder, BY_ID[wanted].name, pid)


def _spelling(folder: str) -> str:
    """*folder* in the one spelling a rule stores ("" when it is too broad to be a project)."""
    return mode_module.canonical_item(folder) or ""


def section_weakening(raw: Any) -> list[str]:
    """Why writing *raw* as the ``agent_sandbox`` section turns protection down (``[]`` when it does
    not, or when the writer will refuse it anyway)."""
    errors: list[str] = []
    after = parse(raw, errors)
    return [] if errors else loosened(stored(), with_legacy(after))


__all__ = ["ALLOWED", "API_WEAKENING", "API_WRITES", "BY_ID", "NEVER", "NOT_CONTROLLABLE", "PERMISSIONS", "REFUSED",
           "SECTION", "WAITING", "Access", "Allowances", "Choice", "FolderLimits", "FolderRule", "Mode", "Permission",
           "PermissionRequest", "Route", "Rule", "Scope", "Settings", "allowances", "answers", "ask",
           "broker_decision", "catalogue", "current", "decide", "folder_limits", "grants", "loosened", "not_here", "refused", "requests",
           "section_weakening", "stored", "validate_section", "view"]
