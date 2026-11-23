"""The three dependency-file checks the guard runs (KI-595) — the package's Facade.

* :func:`check_install_files` — BEFORE a call: an install that names no packages (``npm ci``,
  ``uv sync``, ``pip install -r …``) is judged by the files it installs from. It also remembers
  each install's lockfile as it is now, for the after-install check.
* :func:`check_landed` — AFTER a call: the packages an install ADDED to its lockfile (a named
  install's transitive dependencies, which no command line shows) are judged; a verified one
  that landed is a critical alert that names the removal command and warns that its install
  scripts may already have run. Before an install, Blackbox can only see what a lockfile already pins.
* :func:`check_dependency_write` — BEFORE a write: a write or edit of a manifest or lockfile is
  judged by the packages it ADDS.

Every check answers a :class:`DependencyCheck`: findings in the usual tiers (verified blocks,
community flags) and notes — "dependencies not checked: <reason>" — the guard records on the
session, so an unread file is never silent. Nothing here raises for a bad file or a bad command.

Usage::

    check = check_install_files("terminal", {"command": "npm ci", "workdir": "/app"}, ruleset)
    check.findings, check.notes
"""

from __future__ import annotations

import os
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from ...kernel import action_context
from ...kernel.bounded_files import read_small_text
from .. import action_parsing, shell_shapes
from ..finding import Finding
from . import registry
from .commands import InstallSite, install_sites
from .model import DependencyGraph, package_key
from .verdicts import findings_for, listed_packages

#: Tool-call arguments that name the folder a command runs in.
FOLDER_KEYS = ("workdir", "cwd", "working_directory", "dir")
#: Arguments a write or edit carries its new text in.
_CONTENT_KEYS = ("content", "contents", "file_text", "text")
_EDIT_PAIRS = (("old_string", "new_string"), ("old_str", "new_str"))
NOT_CHECKED = "dependencies not checked: "
PARTLY_CHECKED = "dependencies partly checked: "
_SNAPSHOTS = 64

#: The command that removes a package, per manager ({top}: the package the project asked for).
REMOVE_COMMANDS = {"npm": "npm uninstall {top}", "pnpm": "pnpm remove {top}", "yarn": "yarn remove {top}",
                   "bun": "bun remove {top}", "uv": "uv remove {top}", "poetry": "poetry remove {top}",
                   "pipenv": "pipenv uninstall {top}", "cargo": "cargo remove {top}", "bundle": "bundle remove {top}"}
_LANDED_ADVICE = ("Remove it now: `{remove}`{through}. Its install scripts may already have run on this machine — "
                  "check what it changed and rotate any secrets it could read.")


@dataclass
class DependencyCheck:
    """What one check found (*findings*), what it could not check (*notes*, said to the person)
    and how many dependency files it read (*files_read*)."""

    findings: list[Finding] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    files_read: int = 0


class _Snapshots:
    """Each lockfile as an install found it (its parsed graph, None when there was none), until
    its after-install check reads it. The cached graph is held, not copied: a snapshot costs nothing."""

    def __init__(self) -> None:
        self._before: OrderedDict[str, Optional[DependencyGraph]] = OrderedDict()
        self._lock = threading.Lock()

    def remember(self, path: str, graph: Optional[DependencyGraph]) -> None:
        with self._lock:
            self._before[path] = graph
            self._before.move_to_end(path)
            while len(self._before) > _SNAPSHOTS:
                self._before.popitem(last=False)

    def take(self, path: str) -> tuple[bool, Optional[DependencyGraph]]:
        """``(remembered, graph)``: whether an install remembered *path*, and what it held then."""
        with self._lock:
            if path not in self._before:
                return False, None
            return True, self._before.pop(path)

    def clear(self) -> None:
        with self._lock:
            self._before.clear()


SNAPSHOTS = _Snapshots()


def call_folder(args: Any) -> str:
    """The folder a call runs in: its own working-folder argument (absolute, or relative to the
    caller's folder), else the caller's (``kernel.action_context``); "" when nobody says."""
    ambient = action_context.working_folder()
    for key in FOLDER_KEYS:
        value = args.get(key) if isinstance(args, dict) else None
        if isinstance(value, str) and value.strip():
            given = os.path.expanduser(value.strip())
            if os.path.isabs(given):
                return os.path.normpath(given)
            return os.path.normpath(os.path.join(ambient, given)) if ambient else ""
    return ambient


def _sites(tool_name: str, args: Any) -> list[InstallSite]:
    command = shell_shapes.command_from_args(tool_name, args, any_tool=True)
    return install_sites(command, call_folder(args)) if command else []


def _snapshot(site: InstallSite) -> None:
    lockfile = registry.lockfile_for(site)
    if lockfile:
        SNAPSHOTS.remember(lockfile, registry.read(lockfile).graph if os.path.lexists(lockfile) else None)


def _judge(tool_name: str, ruleset: Any, read: registry.FileRead, check: DependencyCheck) -> None:
    if read.graph is None:
        check.notes.append(NOT_CHECKED + read.note)
        return
    check.files_read += 1
    check.notes += [PARTLY_CHECKED + note for note in read.graph.notes]
    check.findings += findings_for(tool_name, read.graph, listed_packages(ruleset, read.graph))


def check_install_files(tool_name: str, args: Any, ruleset: Any) -> DependencyCheck:
    """Judge the files every manifest install in the call installs from (see the module doc)."""
    check = DependencyCheck()
    for site in _sites(tool_name, args):
        _snapshot(site)
        if site.from_files:
            for read in registry.files_for(site):
                _judge(tool_name, ruleset, read, check)
    return check


def _advice(site: InstallSite) -> str:
    """The removal advice for a package that landed (``{top}`` / ``{through}`` filled per finding)."""
    remove = REMOVE_COMMANDS.get(site.manager)
    return _LANDED_ADVICE.replace("{remove}", remove) if remove else ""


def check_landed(tool_name: str, args: Any, rules: Callable[[], Any]) -> DependencyCheck:
    """Judge what each install in the call ADDED to its lockfile. *rules* gives the ruleset, asked
    only when the call was an install with a lockfile (so ordinary calls cost a parse of the command)."""
    check = DependencyCheck()
    ruleset: Any = None
    for site in _sites(tool_name, args):
        lockfile = registry.lockfile_for(site)
        if not lockfile:
            continue
        remembered, before_graph = SNAPSHOTS.take(lockfile)
        # Not remembered (no check ran before this call in this process): every package counts as new.
        before = (before_graph.package_keys() if before_graph is not None else frozenset()) if remembered else None
        if not os.path.lexists(lockfile):
            continue   # the install failed, or this manager wrote no lockfile
        after = registry.read(lockfile)
        if after.graph is None:
            check.notes.append(NOT_CHECKED + after.note)
            continue
        added = {node for node, package in after.graph.nodes.items()
                 if before is None or package_key(package) not in before}
        if not added:
            continue
        ruleset = ruleset if ruleset is not None else rules()
        hits = listed_packages(ruleset, after.graph, only=added)
        check.findings += findings_for(tool_name, after.graph, hits, title_prefix="Installed — ",
                                       advice=_advice(site), landed=True)
    return check


def _new_text(args: dict[str, Any], current: Optional[str]) -> Optional[str]:
    """The file's text after the write or edit, or None when the call's shape is not one read here."""
    for key in _CONTENT_KEYS:
        if isinstance(args.get(key), str):
            return args[key]
    for old_key, new_key in _EDIT_PAIRS:
        old, new = args.get(old_key), args.get(new_key)
        if isinstance(old, str) and isinstance(new, str) and current is not None and old in current:
            return current.replace(old, new) if args.get("replace_all") else current.replace(old, new, 1)
    return None


def check_dependency_write(tool_name: str, args: Any, ruleset: Any) -> list[Finding]:
    """Findings for listed packages a write or edit ADDS to a manifest, lockfile or requirements file."""
    access = action_parsing.file_access_arg(tool_name, args)
    if not access or access["mode"] != "write" or not isinstance(args, dict):
        return []
    name = os.path.basename(access["path"])
    if registry.reader_for(name) is None:
        return []
    path = os.path.expanduser(access["path"])
    folder = call_folder(args)
    path = path if os.path.isabs(path) else os.path.join(folder, path) if folder else ""
    before = registry.read(path) if path and os.path.lexists(path) else None
    current = _current_text(path) if path else None
    text = _new_text(args, current)
    if text is None:
        return []
    after = registry.parse_text(text, name)
    if after.graph is None:
        return []
    old = before.graph.package_keys() if before is not None and before.graph is not None else frozenset()
    added = {node for node, p in after.graph.nodes.items() if package_key(p) not in old}
    hits = listed_packages(ruleset, after.graph, only=added) if added else []
    return findings_for(tool_name, after.graph, hits, title_prefix=f"Writing {name} adds — ")


def _current_text(path: str) -> Optional[str]:
    """The file as it is now — an edit is applied to it to see what the file will hold."""
    return read_small_text(path, registry.MAX_FILE_BYTES, nofollow=True) if os.path.lexists(path) else None
