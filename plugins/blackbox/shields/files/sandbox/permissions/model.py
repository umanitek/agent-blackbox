"""The typed records of sandbox permissions (no I/O here).

A **permission** is one named ability an agent inside Blackbox's sandbox may be given or refused
(Docker, global installs, the clipboard …). The person sets a :class:`Mode` for it per
:class:`Scope` (everywhere, one agent, one project folder, or one agent in one project); the most
specific rule wins in both directions (founder decision F6). Folder rules (:class:`FolderRule`)
only ever tighten: a folder kept out of reach or read-only.

Usage::

    rule = Rule("docker", Mode.ALLOW, Scope(agent="claude-code", project="~/work/shop"))
    settings = Settings(rules=(rule,))
    settings.mode(catalogue.BY_ID["docker"], "claude-code", "/Users/me/work/shop/api")   # Mode.ALLOW
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional


class Mode(str, Enum):
    """What happens when an agent uses a permission; :attr:`rank` orders them, most protective first."""

    BLOCK = "block"
    ASK = "ask"
    ALLOW = "allow"

    @property
    def rank(self) -> int:
        return list(Mode).index(self)


class Route(str, Enum):
    """How a permission is enforced: in the Seatbelt PROFILE (fixed when the agent starts), by a
    BROKER (Blackbox does the action outside the sandbox, after its checks) or by both."""

    PROFILE = "profile"
    BROKER = "broker"


class Access(str, Enum):
    """What a folder rule leaves an agent: NONE (no read, no write) or READ (read only)."""

    NONE = "none"
    READ = "read"


class Choice(str, Enum):
    """The person's answer to a permission request (founder decision F3: "always" = this agent in this project)."""

    ONCE = "once"
    ALWAYS = "always"
    KEEP_BLOCKED = "keep-blocked"


@dataclass(frozen=True)
class Permission:
    """One catalogue entry: ``id``, ``name`` and ``unlocks`` (plain words), the security ``cost`` of
    allowing it, its ``route``, its ``default`` mode, the ``modes`` the person may pick, and
    ``refusal_kinds`` — the sandbox refusals (``agent_hooks`` kinds) that mean an agent wanted it.
    ``controllable`` is False until Blackbox can really enforce it on this OS; ``note`` says why."""

    id: str
    name: str
    unlocks: str
    cost: str
    route: Route
    default: Mode
    modes: tuple[Mode, ...]
    refusal_kinds: tuple[str, ...] = ()
    controllable: bool = True
    note: str = ""
    #: Takes a list of ports (local-ports only): the ports still reachable while it is blocked.
    ports: bool = False
    #: The broker acts when the person answers (the agent does not ask again): stopping a process.
    acts_on_answer: bool = False


@dataclass(frozen=True)
class Never:
    """A place or ability no permission can unlock (rendered last in every profile)."""

    id: str
    name: str
    why: str


@dataclass(frozen=True)
class Scope:
    """Where a rule applies: an ``agent`` id ("" = every agent) and a ``project`` folder in its one
    canonical spelling (``~/work/shop`` or an absolute path; "" = every folder)."""

    agent: str = ""
    project: str = ""

    def specificity(self) -> tuple[int, int]:
        """Higher wins: agent+project > project > agent > everywhere; a longer project wins a tie."""
        level = (2 if self.project else 0) + (1 if self.agent else 0)
        return level, len(self.project)

    def project_path(self) -> str:
        """The project as an absolute path ("" for none)."""
        return os.path.expanduser(self.project) if self.project else ""

    def covers(self, agent: str, folder: str) -> bool:
        """True when this scope applies to *agent* working in absolute *folder*."""
        if self.agent and self.agent != agent:
            return False
        root = self.project_path()
        return not root or folder == root or folder.startswith(root.rstrip("/") + "/")

    def words(self, name_of: Callable[[str], str] = str) -> str:
        """``Claude Code in ~/work/shop`` / ``every AI agent``; *name_of* turns an agent id into its name."""
        who = name_of(self.agent) if self.agent else "every AI agent"
        return who + (f" in {self.project}" if self.project else "")


@dataclass(frozen=True)
class Rule:
    """The person's mode for one permission in one scope (``ports``: local-ports only)."""

    permission: str
    mode: Mode
    scope: Scope = Scope()
    ports: tuple[int, ...] = ()


@dataclass(frozen=True)
class FolderRule:
    """A folder kept from agents in one scope: ``access`` NONE (no read or write) or READ (read only)."""

    path: str
    access: Access
    scope: Scope = Scope()


@dataclass(frozen=True)
class Settings:
    """Every rule and folder rule the person set (``agent_sandbox`` in the config)."""

    rules: tuple[Rule, ...] = ()
    folders: tuple[FolderRule, ...] = ()

    def rule(self, permission: str, agent: str, folder: str) -> Optional[Rule]:
        """The rule that decides *permission* for *agent* in *folder*: the most specific one (F6)."""
        found = [rule for rule in self.rules if rule.permission == permission and rule.scope.covers(agent, folder)]
        return max(found, key=lambda rule: rule.scope.specificity()) if found else None

    def mode(self, permission: Permission, agent: str = "", folder: str = "") -> Mode:
        """The effective mode: the deciding rule's, else the catalogue default."""
        rule = self.rule(permission.id, agent, folder)
        return rule.mode if rule is not None else permission.default

    def ports(self, permission: str, agent: str = "", folder: str = "") -> tuple[int, ...]:
        rule = self.rule(permission, agent, folder)
        return rule.ports if rule is not None else ()

    def folder_rules(self, agent: str, folder: str) -> tuple[FolderRule, ...]:
        """Every folder rule that applies to *agent* in *folder* (they only tighten, so all apply)."""
        return tuple(each for each in self.folders if each.scope.covers(agent, folder))


@dataclass(frozen=True)
class Allowances:
    """What one profile lets through — the OS-neutral input a platform module renders.

    ``lifted``: the profile-route permissions that are allowed (everything else in the catalogue
    with a profile route is refused); ``ports``: localhost ports reachable while local-ports is
    blocked; ``hidden`` / ``read_only``: canonical folders from folder rules; ``tool_folders`` /
    ``tool_globs``: the person's program folders, closed to writes while ``tool-folders`` is not allowed."""

    lifted: frozenset[str] = frozenset()
    ports: tuple[int, ...] = ()
    hidden: tuple[str, ...] = ()
    read_only: tuple[str, ...] = ()
    tool_folders: tuple[str, ...] = ()
    tool_globs: tuple[str, ...] = ()


@dataclass(frozen=True)
class PermissionRequest:
    """An agent wanted a permission it does not have: what the person is asked about. ``pid``: the
    asking process — for ``stop-processes`` the process the agent wanted stopped."""

    id: str
    permission: str
    agent: str
    instance: str
    project: str
    what: str
    digest: str
    pid: int
    created: float
    #: The whole text the person must read before answering (an AppleScript), "" otherwise.
    detail: str = ""


@dataclass(frozen=True)
class OnceGrant:
    """Allow once: bound to one permission, scope and exact request (``digest``), until ``expires``."""

    permission: str
    scope: Scope
    digest: str
    expires: float
    used: bool = False


@dataclass(frozen=True)
class PermissionChange:
    """One change of a permission, for the audit log."""

    permission: str
    scope: Scope
    before: str
    after: str
    approver: str = ""
    request: str = ""


__all__ = ["Access", "Allowances", "Choice", "FolderRule", "Mode", "Never", "OnceGrant", "Permission", "PermissionChange",
           "PermissionRequest", "Route", "Rule", "Scope", "Settings"]
