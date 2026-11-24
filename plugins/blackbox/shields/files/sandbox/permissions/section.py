"""The person's sandbox permissions in the config: ``plugins.entries.blackbox.agent_sandbox``.

::

    agent_sandbox:
      permissions:   # at most 200; a permission not named keeps its catalogue default
        - {permission: docker, mode: allow, agent: claude-code, project: "~/work/shop"}
        - {permission: global-installs, mode: ask}
        - {permission: local-ports, mode: block, ports: [5432, 3000]}
      folders:       # at most 100; they only tighten
        - {path: "~/clients", access: none}
        - {path: "~/work/shop/secrets", access: read, agent: codex}

:func:`validate_section` is the settings writer's validator (``kernel.settings.SECTION_VALIDATORS``):
every permission is in the catalogue and controllable, every mode one it allows, ports only on
local-ports (1–65535, at most 32), every agent a known one, every project and folder in its ONE
canonical spelling (LES-105: refused otherwise, never rewritten) and not too broad, no folder rule
on Blackbox's own places, one rule per (permission, agent, project). :func:`current` reads the
setting for enforcement; until the person sets Homebrew here, its mode is read from the older
``agent_packages.installs`` (off → block), so nothing changes on upgrade.

Usage::

    settings = current()                      # Settings
    errors: list[str] = []
    clean = validate_section(raw, errors)     # {"permissions": [...], "folders": [...]}
"""

from __future__ import annotations

import os
from typing import Any, Mapping, Optional

from .....kernel import agent_hosts, constants
from .....kernel.config import shield_entry
from ... import mode as mode_module
from .catalogue import BY_ID, THIS_MACHINE
from .model import Access, FolderRule, Mode, Rule, Scope, Settings

SECTION = "agent_sandbox"
RULES, FOLDERS = "permissions", "folders"
MAX_RULES, MAX_FOLDERS, MAX_PORTS = 200, 100, 32
#: ssh into this Mac: in the never-list (F7), so no local-ports rule may list it.
NEVER_PORT = 22
_RULE_KEYS = frozenset({"permission", "mode", "agent", "project", "ports"})
_FOLDER_KEYS = frozenset({"path", "access", "agent", "project"})
#: The older Homebrew setting (``packages.SETTING`` values) read until a homebrew rule exists.
LEGACY_SECTION, LEGACY_KEY = "agent_packages", "installs"
_LEGACY = {"off": Mode.BLOCK, "ask": Mode.ASK, "allow": Mode.ALLOW}


def known_agent(agent: str) -> bool:
    return agent in agent_hosts.BY_ID or agent == agent_hosts.HERMES_ID


def _own_places() -> tuple[str, ...]:
    return tuple(os.path.realpath(path) for path in (constants.blackbox_home(), constants.hermes_root()))


def _scope(row: Mapping[str, Any], errors: list[str], where: str) -> Optional[Scope]:
    agent, project = row.get("agent") or "", row.get("project") or ""
    if not isinstance(agent, str) or (agent and not known_agent(agent)):
        errors.append(f"{where}: unknown agent {agent!r}")
        return None
    if not isinstance(project, str) or "\t" in project or (project and mode_module.canonical_item(project) != project):
        errors.append(f"{where}: name the project folder as {mode_module.canonical_item(project) or 'one folder under ~/ or /'}")
        return None
    return Scope(agent=agent, project=project)


def _rule(row: Any, errors: list[str], where: str) -> Optional[Rule]:
    if not isinstance(row, Mapping) or set(row) - _RULE_KEYS:
        errors.append(f"{where}: a rule has permission, mode and optionally agent, project and ports")
        return None
    permission = BY_ID.get(str(row.get("permission")))
    if permission is None:
        errors.append(f"{where}: unknown permission {row.get('permission')!r}")
        return None
    if not permission.controllable:
        errors.append(f"{where}: {permission.name} is {permission.note}")
        return None
    mode = next((each for each in permission.modes if each.value == row.get("mode")), None)
    if mode is None:
        errors.append(f"{where}: {permission.name} can be set to {', '.join(each.value for each in permission.modes)}")
        return None
    ports = row.get("ports") or []
    if ports and not permission.ports:
        errors.append(f"{where}: only local-ports takes ports")
        return None
    if not isinstance(ports, list) or len(ports) > MAX_PORTS or \
            not all(isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535 for port in ports):
        errors.append(f"{where}: ports are at most {MAX_PORTS} numbers from 1 to 65535")
        return None
    if NEVER_PORT in ports:
        errors.append(f"{where}: port {NEVER_PORT} (ssh into {THIS_MACHINE}) is never reachable from the sandbox")
        return None
    scope = _scope(row, errors, where)
    return None if scope is None else Rule(permission.id, mode, scope, tuple(sorted(set(ports))))


def _folder(row: Any, errors: list[str], where: str) -> Optional[FolderRule]:
    if not isinstance(row, Mapping) or set(row) - _FOLDER_KEYS:
        errors.append(f"{where}: a folder rule has path, access and optionally agent and project")
        return None
    path = row.get("path")
    if not isinstance(path, str) or mode_module.canonical_item(path) != path:
        errors.append(f"{where}: name the folder as {mode_module.canonical_item(path) or 'one folder under ~/ or /'}")
        return None
    real = os.path.realpath(os.path.expanduser(path))
    if any(real == own or real.startswith(own + "/") for own in _own_places()):
        errors.append(f"{where}: Blackbox's own places are already closed to agents")
        return None
    access = next((each for each in Access if each.value == row.get("access")), None)
    if access is None:
        errors.append(f"{where}: access is none or read")
        return None
    scope = _scope(row, errors, where)
    return None if scope is None else FolderRule(path, access, scope)


def parse(raw: Any, errors: list[str]) -> Settings:
    """*raw* (the section as stored or sent) as :class:`Settings`; every problem appended to *errors*."""
    if not isinstance(raw, Mapping) or set(raw) - {RULES, FOLDERS}:
        errors.append(f"{SECTION} holds {RULES} and {FOLDERS}")
        return Settings()
    rows, folder_rows = raw.get(RULES) or [], raw.get(FOLDERS) or []
    if not isinstance(rows, list) or len(rows) > MAX_RULES:
        errors.append(f"{SECTION}.{RULES}: at most {MAX_RULES} rules")
        rows = []
    if not isinstance(folder_rows, list) or len(folder_rows) > MAX_FOLDERS:
        errors.append(f"{SECTION}.{FOLDERS}: at most {MAX_FOLDERS} folder rules")
        folder_rows = []
    rules = [rule for index, row in enumerate(rows) if (rule := _rule(row, errors, f"{SECTION}.{RULES}[{index}]"))]
    folders = [each for index, row in enumerate(folder_rows) if (each := _folder(row, errors, f"{SECTION}.{FOLDERS}[{index}]"))]
    if len({(rule.permission, rule.scope) for rule in rules}) != len(rules):
        errors.append(f"{SECTION}.{RULES}: one rule per permission, agent and project")
    if len({(each.path, each.scope) for each in folders}) != len(folders):
        errors.append(f"{SECTION}.{FOLDERS}: one rule per folder, agent and project")
    return Settings(tuple(rules), tuple(folders))


def as_section(settings: Settings) -> dict[str, list[dict[str, Any]]]:
    """*settings* as the config section (the shape :func:`parse` reads back)."""
    def scope(each: Scope) -> dict[str, str]:
        return {key: value for key, value in (("agent", each.agent), ("project", each.project)) if value}
    return {RULES: [{"permission": rule.permission, "mode": rule.mode.value, **scope(rule.scope),
                     **({"ports": list(rule.ports)} if rule.ports else {})} for rule in settings.rules],
            FOLDERS: [{"path": each.path, "access": each.access.value, **scope(each.scope)} for each in settings.folders]}


def validate_section(raw: Any, errors: list[str]) -> dict[str, Any]:
    """The settings writer's validator for ``agent_sandbox``: the clean section, or ``{}`` with *errors*."""
    found: list[str] = []
    settings = parse(raw, found)
    errors.extend(found)
    return {} if found else as_section(settings)


def stored() -> Optional[Settings]:
    """The setting as stored, or None when it can not be read cleanly (judged as a loosening)."""
    raw = shield_entry().get(SECTION)
    if raw is None:
        return with_legacy(Settings())
    errors: list[str] = []
    settings = parse(raw, errors)
    return None if errors else with_legacy(settings)


def current() -> Settings:
    """The setting in force: what is stored, or the catalogue defaults when it can not be read."""
    return stored() or with_legacy(Settings())


def with_legacy(settings: Settings) -> Settings:
    """Homebrew's everywhere-rule from ``agent_packages.installs`` while the person has not set one here."""
    if any(rule.permission == "homebrew" and rule.scope == Scope() for rule in settings.rules):
        return settings
    legacy = shield_entry().get(LEGACY_SECTION)
    value = legacy.get(LEGACY_KEY) if isinstance(legacy, Mapping) else None
    if value not in _LEGACY:
        return settings
    return Settings(settings.rules + (Rule("homebrew", _LEGACY[value]),), settings.folders)


__all__ = ["FOLDERS", "MAX_FOLDERS", "MAX_PORTS", "MAX_RULES", "RULES", "SECTION", "as_section", "current", "known_agent", "parse",
           "stored", "validate_section", "with_legacy"]
