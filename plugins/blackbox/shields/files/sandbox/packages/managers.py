"""Global installs for sandboxed agents (``global-installs``, founder decision F1): ``npm i -g``,
``pipx install``, ``pip install --user``, ``cargo install``, ``gem install``, ``uv tool install`` —
validated here, run by Blackbox outside the sandbox (``installs``), like Homebrew.

Each :class:`Manager` names the agent's words Blackbox accepts and the FIXED argv it runs: names
only (from the default registry — no URL, path, git source, index or registry option), the verb,
and the one flag that makes the install global. Every other option is refused. Each name is
checked against the threat graph as ``<check> <name>`` (the guard's package rules).

**Security cost, said plainly:** a package's install scripts (npm ``postinstall``, a gem's native
build, a crate's ``build.rs``) run outside the sandbox with the person's rights, and its program
lands on the person's PATH — the same as the person typing the command.

Pattern: **Strategy** (one record per package manager, no subclasses).

Usage::

    request = parse("npm", ["install", "-g", "typescript"])
    request.words()     # ["install", "--global", "typescript"]
    request.shown()     # "npm install --global typescript"
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Sequence

from .request import Refused

MAX_NAMES, MAX_NAME_CHARS = 20, 120


@dataclass(frozen=True)
class Manager:
    """One package manager: ``id`` and ``program``, its ``name`` for a person, the agent's verbs
    (``{word: canonical verb}``), the words Blackbox runs before the names per canonical verb, the
    flags that must / may appear (``required`` / ``allowed``), the name pattern, and the command a
    name is threat-checked as (``check``)."""

    id: str
    program: str
    name: str
    verbs: dict[str, str]
    runs: dict[str, tuple[str, ...]]
    name_pattern: re.Pattern[str]
    check: str
    required: frozenset[str] = frozenset()
    allowed: frozenset[str] = frozenset()
    prefix: tuple[str, ...] = ()


_PY_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*(==[A-Za-z0-9.]+)?$")
MANAGERS: dict[str, Manager] = {each.id: each for each in (
    Manager("npm", "npm", "npm", {"install": "install", "i": "install", "add": "install", "uninstall": "uninstall",
                                  "un": "uninstall", "rm": "uninstall", "remove": "uninstall", "update": "upgrade", "up": "upgrade"},
            {"install": ("install", "--global"), "uninstall": ("uninstall", "--global"), "upgrade": ("update", "--global")},
            re.compile(r"^(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*(@[A-Za-z0-9.^~*-]+)?$"), "npm install -g",
            required=frozenset({"-g", "--global"})),
    Manager("pipx", "pipx", "pipx", {"install": "install", "uninstall": "uninstall", "upgrade": "upgrade"},
            {"install": ("install",), "uninstall": ("uninstall",), "upgrade": ("upgrade",)}, _PY_NAME, "pip install"),
    Manager("pip", "pip3", "pip", {"install": "install"}, {"install": ("install", "--user")}, _PY_NAME, "pip install",
            required=frozenset({"--user"}), allowed=frozenset({"-U", "--upgrade", "-q", "--quiet"})),
    Manager("cargo", "cargo", "cargo", {"install": "install", "uninstall": "uninstall"},
            {"install": ("install",), "uninstall": ("uninstall",)}, re.compile(r"^[A-Za-z0-9_-]+(@[0-9A-Za-z.^~*-]+)?$"),
            "cargo install", allowed=frozenset({"--locked", "-q", "--quiet"})),
    Manager("gem", "gem", "RubyGems", {"install": "install", "uninstall": "uninstall"},
            {"install": ("install", "--user-install"), "uninstall": ("uninstall", "--user-install")},
            re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$"), "gem install", allowed=frozenset({"--user-install"})),
    Manager("uv", "uv", "uv", {"install": "install", "uninstall": "uninstall", "upgrade": "upgrade"},
            {"install": ("tool", "install"), "uninstall": ("tool", "uninstall"), "upgrade": ("tool", "upgrade")}, _PY_NAME,
            "pip install", prefix=("tool",)),
)}


@dataclass(frozen=True)
class InstallRequest:
    """One validated global install: its ``manager`` id, canonical ``verb`` and ``names``."""

    manager: str
    verb: str
    names: tuple[str, ...]
    upgrade: bool = False

    @property
    def tool(self) -> str:
        return MANAGERS[self.manager].name

    @property
    def kind(self) -> str:
        return ""

    def words(self) -> list[str]:
        """The words after the program, exactly as Blackbox runs them."""
        return [*MANAGERS[self.manager].runs[self.verb], *(["--upgrade"] if self.upgrade else []), *self.names]

    def shown(self) -> str:
        return " ".join([MANAGERS[self.manager].program, *self.words()])

    def check_command(self, name: str) -> str:
        """What *name* is threat-checked as (the guard's package rules)."""
        return f"{MANAGERS[self.manager].check} {name}"

    def unchanged(self, line: str) -> str:
        """"": a manager's output is not read, so every name of a run that ended well counts as
        installed (Homebrew's is: ``request.BrewRequest.unchanged``)."""
        return ""


def parse(manager_id: str, argv: Sequence[str]) -> InstallRequest:
    """The :class:`InstallRequest` for ``<program> <argv>``; raises :class:`Refused` with the reason."""
    manager = MANAGERS.get(manager_id)
    if manager is None:
        raise Refused(f"Blackbox does not install with {manager_id!r}")
    words = [str(word) for word in argv] if isinstance(argv, (list, tuple)) else []
    if manager.prefix and words[:len(manager.prefix)] == list(manager.prefix):
        words = words[len(manager.prefix):]
    flags = {word for word in words if word.startswith("-")}
    plain = [word for word in words if not word.startswith("-")]
    verb = manager.verbs.get(plain[0], "") if plain else ""
    if not verb:
        raise Refused(f"Blackbox runs only {', '.join(sorted(set(manager.verbs.values())))} with {manager.name}")
    if flags - manager.required - manager.allowed:
        raise Refused(f"the option {sorted(flags - manager.required - manager.allowed)[0]} is not allowed "
                      "(names only, from the default registry)")
    if manager.required and not flags & manager.required:
        raise Refused(f"only a global {manager.name} install is done by Blackbox ({' or '.join(sorted(manager.required))})")
    names = plain[1:]
    if not names or len(names) > MAX_NAMES:
        raise Refused(f"name 1 to {MAX_NAMES} packages")
    for name in names:
        if len(name) > MAX_NAME_CHARS or not manager.name_pattern.match(name):
            raise Refused(f"{name!r} is not a {manager.name} package name (names only: no address, path or git source)")
    return InstallRequest(manager.id, verb, tuple(dict.fromkeys(names)), upgrade=bool(flags & {"-U", "--upgrade"}))


__all__ = ["MANAGERS", "InstallRequest", "Manager", "parse"]
