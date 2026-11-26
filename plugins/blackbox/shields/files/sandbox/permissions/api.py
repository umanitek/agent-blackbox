"""The sandbox permissions' endpoints, merged into File Shield's (``/api/shields/file-shield/api/<name>``).

Reads (GET):

* ``permissions`` — the catalogue with each permission's mode everywhere and per sandboxed agent,
  when a change applies (``now`` for a broker, ``after restart`` for the profile), the
  never-list, what can not be controlled, the person's rules and folder rules, and per agent
  whether only the hook-enforced part applies (F9).

Writes (POST), each through the ONE settings writer with the section's validator:

* ``permission-set`` ``{permission, mode, agent?, project?, ports?}`` — sets one rule;
* ``permission-clear`` ``{permission, agent?, project?}`` — removes one;
* ``folder-set`` ``{path, access, agent?, project?}`` / ``folder-clear`` ``{path, agent?, project?}``.

A write that loosens (:func:`weakening`) is held by the approval gate (428) until the person
approves it with the companion app's key or their password; the session token alone is not
enough. A project or folder is canonicalised here (``mode.canonical_item``), so the validator
sees its one spelling. Each change is written to the audit log (``permission_changed``).

Usage::

    API_WRITES["permission-set"](context, {"permission": "docker", "mode": "allow", "agent": "claude-code"})
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Mapping

from ..... import audit
from .....kernel.agent_hosts import product_name
from .....kernel.settings import write_settings
from ....shield_api import ShieldApiError, ShieldContext
from ... import mode as mode_module
from .catalogue import BY_ID, NEVER, NOT_CONTROLLABLE, PERMISSIONS
from .judge import loosened
from .model import Access, FolderRule, Mode, Route, Rule, Scope, Settings
from .section import SECTION, as_section, current, known_agent, stored

logger = logging.getLogger(__name__)
#: When a change reaches an agent, per route.
APPLIES = {Route.BROKER: "now", Route.PROFILE: "after restart"}
HOOKS_ONLY_NOTE = ("not in the sandbox: only folder rules and the places something starts from apply (through its hooks); "
                   "the other permissions need the sandbox")


def _scope(body: Mapping[str, Any]) -> Scope:
    agent = str(body.get("agent") or "")
    if agent and not known_agent(agent):
        raise ShieldApiError(400, f"unknown agent {agent!r}")
    raw = body.get("project")
    project = mode_module.canonical_item(raw) if raw else ""
    if raw and project is None:
        raise ShieldApiError(400, "Name the project as one folder under ~/ or / — not the whole disk or your whole home folder.")
    return Scope(agent=agent, project=project or "")


def _rule(body: Mapping[str, Any]) -> Rule:
    permission = BY_ID.get(str(body.get("permission") or ""))
    if permission is None:
        raise ShieldApiError(404, "no such permission")
    if not permission.controllable:
        raise ShieldApiError(400, f"{permission.name} is {permission.note}")
    mode = next((each for each in permission.modes if each.value == body.get("mode")), None)
    if mode is None:
        raise ShieldApiError(400, f"{permission.name} can be set to {', '.join(each.value for each in permission.modes)}")
    ports = body.get("ports") or ()
    return Rule(permission.id, mode, _scope(body), tuple(ports) if isinstance(ports, list) else ())


def _folder(body: Mapping[str, Any], access_needed: bool = True) -> FolderRule:
    path = mode_module.canonical_item(body.get("path"))
    if path is None:
        raise ShieldApiError(400, "Name one folder, written from ~/ or / — not the whole disk or your whole home folder.")
    access = next((each for each in Access if each.value == body.get("access")), Access.NONE if not access_needed else None)
    if access is None:
        raise ShieldApiError(400, "access is none or read")
    return FolderRule(path, access, _scope(body))


def _with_rule(settings: Settings, rule: Rule) -> Settings:
    kept = tuple(each for each in settings.rules if (each.permission, each.scope) != (rule.permission, rule.scope))
    return Settings(kept + (rule,), settings.folders)


def _without_rule(settings: Settings, permission: str, scope: Scope) -> Settings:
    return Settings(tuple(each for each in settings.rules if (each.permission, each.scope) != (permission, scope)), settings.folders)


def _with_folder(settings: Settings, folder: FolderRule) -> Settings:
    kept = tuple(each for each in settings.folders if (each.path, each.scope) != (folder.path, folder.scope))
    return Settings(settings.rules, kept + (folder,))


def _without_folder(settings: Settings, folder: FolderRule) -> Settings:
    return Settings(settings.rules, tuple(each for each in settings.folders if (each.path, each.scope) != (folder.path, folder.scope)))


def _planned(name: str, body: Mapping[str, Any]) -> Settings:
    """The settings write *name* with *body* would leave (raises ShieldApiError for a bad body)."""
    now = current()
    if name == "permission-set":
        return _with_rule(now, _rule(body))
    if name == "permission-clear":
        rule = _rule({**body, "mode": Mode.BLOCK.value})
        return _without_rule(now, rule.permission, rule.scope)
    if name == "folder-set":
        return _with_folder(now, _folder(body))
    return _without_folder(now, _folder(body, access_needed=False))


def _write(name: str, body: Mapping[str, Any]) -> dict[str, Any]:
    before, after = current(), _planned(name, body)
    result = write_settings({SECTION: as_section(after)})
    if not result.get("ok"):
        raise ShieldApiError(400, "; ".join(result.get("errors") or ["the sandbox permissions could not be saved"]))
    _audit(name, body, before, after)
    return view()


def _audit(name: str, body: Mapping[str, Any], before: Settings, after: Settings) -> None:
    try:
        audit.record_for(audit.SANDBOX_RECORDER, event="permission_changed",
                         detail={"change": name, "permission": str(body.get("permission") or ""), "path": str(body.get("path") or ""),
                                 "agent": str(body.get("agent") or ""), "project": str(body.get("project") or ""),
                                 "mode": str(body.get("mode") or body.get("access") or ""),
                                 "loosened": bool(loosened(before, after))})
    except Exception:   # health: allow BLE001 -- the change is saved; a failed record is logged
        logger.warning("blackbox: a sandbox permission change was not recorded", exc_info=True)


def weakening(name: str) -> Callable[[Mapping[str, Any]], list[str]]:
    """The approval gate's judge for write *name*: why it turns protection down (``[]``: it does not)."""
    def judge(body: Mapping[str, Any]) -> list[str]:
        try:
            return loosened(stored(), _planned(name, body))
        except ShieldApiError:
            return []   # refused by the endpoint itself: nothing to confirm
    return judge


def _mode_row(settings: Settings, agent: str) -> dict[str, str]:
    return {each.id: settings.mode(each, agent).value for each in PERMISSIONS if each.controllable}


def view(sandboxed: tuple[str, ...] = ()) -> dict[str, Any]:
    """The ``permissions`` read (see the module doc); *sandboxed*: the agents inside the sandbox."""
    settings = current()
    rules = as_section(settings)
    return {
        "permissions": [{"id": each.id, "name": each.name, "unlocks": each.unlocks, "cost": each.cost, "route": each.route.value,
                         "default": each.default.value, "modes": [mode.value for mode in each.modes],
                         "mode": settings.mode(each).value, "applies": APPLIES[each.route], "controllable": each.controllable,
                         "note": each.note, "ports": each.ports} for each in PERMISSIONS],
        "never": [{"id": each.id, "name": each.name, "why": each.why} for each in NEVER],
        "not_controllable": [{"id": each.id, "name": each.name, "why": each.why} for each in NOT_CONTROLLABLE],
        "rules": rules["permissions"], "folders": rules["folders"],
        "agents": [{"id": agent, "name": product_name(agent), "sandboxed": True, "modes": _mode_row(settings, agent)}
                   for agent in sandboxed],
        "hooks_only_note": HOOKS_ONLY_NOTE,
        "sandbox_unavailable": "",
    }


def not_here(view: dict[str, Any], why: str) -> dict[str, Any]:
    """*view* on a machine where agents can not be sandboxed (*why*, the platform's reason): every
    permission shown as not controllable, with that reason, and no never-list — none of them does
    anything here. KI-660 (Linux round L1): the page offered macOS's whole catalogue with live
    Block / Ask / Allow buttons (Homebrew, AppleScript, "Services on this Mac", pbpaste…) and
    "ssh into this Mac … (probed on macOS 27.2)" on a Linux machine with no sandbox at all."""
    permissions = [{**each, "controllable": False, "note": why} for each in view["permissions"]]
    return {**view, "permissions": permissions, "never": [], "not_controllable": [], "agents": [], "sandbox_unavailable": why}


def _writer(name: str) -> Callable[[ShieldContext, Mapping[str, Any]], dict[str, Any]]:
    def write(_context: ShieldContext, body: Mapping[str, Any]) -> dict[str, Any]:
        return _write(name, body)
    return write


WRITES = ("permission-set", "permission-clear", "folder-set", "folder-clear")
API_WRITES = {name: _writer(name) for name in WRITES}
API_WEAKENING = {name: weakening(name) for name in WRITES}

__all__ = ["API_WEAKENING", "API_WRITES", "APPLIES", "HOOKS_ONLY_NOTE", "WRITES", "view", "weakening"]
