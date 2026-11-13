"""The user's protected paths: a file an agent must not touch unless the operator says so.

The operator lists paths in ``protected_paths`` (defaults: :data:`kernel.config.DEFAULT_PROTECTED_PATHS`
— SSH keys, ``.env`` files, key files, cloud credentials, Blackbox's own state). These
are personal, locally-configured rules (``source="custom"``): they always flag, they
block in block mode (the user wrote the rule), and they are NEVER reported to the
community graph — the matched pattern is the user's own configuration.

Three channels, one rule (KI-363, KI-470): a file tool names its path; a terminal command
names it among words (``cat .env``, ``tar czf x.tgz ~/.ssh``), read through
:mod:`.shell_files`; a code tool (``execute_code``) names it in its code. A wildcard is
checked against the files it would expand to (KI-471) and a link against where it points
(KI-472) — the only places this rule looks at the disk. A terminal command counts when it READS a protected file or
hands a folder holding one whole to a copy or archive — never for where a copy
writes (``cp .env.example .env`` sets a project up; it reads no secret).

A template (``.env.example``, ``.env.sample``…) is not a secret: it matches only
a pattern that names the template itself.

Usage::

    detect_custom_fileaccess("read_file", {"path": "~/.ssh/id_rsa"}, ["~/.ssh/*"])
    detect_custom_fileaccess("terminal", {"command": "cat .env"}, [".env"])
    # -> [Finding(category="fileaccess", source="custom", severity="critical", ...)]
"""

from __future__ import annotations

import fnmatch
import glob
import os
from typing import Any, Iterable

from .. import action_parsing, shell_shapes
from ..finding import Finding
from ...kernel import threat_ids
from . import shell_files

#: Tools that run code directly, with the code in ``args["code"]`` (Hermes's ``execute_code`` runs Python).
CODE_TOOLS = frozenset({"execute_code", "code_execution", "run_code", "run_python", "python"})
#: At most this many files a wildcard expands to are checked; a wildcard naming more is checked by its
#: own text only (a protected file still matches when the pattern itself names it).
_MAX_GLOB_FILES = 64
_GLOB_CHARS = "*?["

#: Endings that mark a file as a template to copy, not the secret itself.
_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".default")


def _protected_path_match(path: str, pattern: str) -> bool:
    """True when *path* matches a user's protected-path *pattern*.

    Patterns are matched three ways so plain paths, directories, and globs all
    behave intuitively: exact/glob match on the full expanded path, glob match
    on the basename (``*.pem``), and prefix match when the pattern names a
    directory (``~/secrets`` protects everything under it).
    """
    try:
        norm_path = os.path.normpath(os.path.expanduser(str(path or "")))
        norm_pat = os.path.normpath(os.path.expanduser(str(pattern or "")))
        if not norm_path or not norm_pat:
            return False
        if norm_path.lower().endswith(_TEMPLATE_SUFFIXES) and not norm_pat.lower().endswith(_TEMPLATE_SUFFIXES):
            return False
        if fnmatch.fnmatch(norm_path, norm_pat):
            return True
        if fnmatch.fnmatch(os.path.basename(norm_path), norm_pat):
            return True
        # Directory-prefix semantics for glob-free patterns.
        if not any(ch in norm_pat for ch in "*?[") and (
            norm_path == norm_pat or norm_path.startswith(norm_pat.rstrip(os.sep) + os.sep)
        ):
            return True
    except Exception:  # pragma: no cover - fail open
        return False
    return False


def _folder_holds(folder: str, pattern: str) -> bool:
    """True when copying *folder* whole would take a file *pattern* protects: the
    pattern names a place under the home or root (``~/.ssh/*``) and *folder* is that
    place or one of its parents (``tar czf x.tgz ~`` takes ``~/.ssh`` with it).
    Name-only patterns (``.env``, ``*.pem``) say nothing about where, so a folder
    copy is not matched against them."""
    expanded = os.path.expanduser(str(pattern or ""))
    if not os.path.isabs(expanded):
        return False
    place = expanded.split("*", 1)[0].split("?", 1)[0].split("[", 1)[0]
    place = os.path.normpath(place if place.endswith(os.sep) or place == expanded else os.path.dirname(place))
    norm_folder = os.path.normpath(os.path.expanduser(str(folder or "")))
    if not os.path.isabs(norm_folder):
        return False
    return place == norm_folder or place.startswith(norm_folder.rstrip(os.sep) + os.sep)


def _accesses(tool_name: str, args: Any) -> list[tuple[str, str, str]]:
    """``(tool, path, mode)`` for each file this call reads or copies: the file tool's
    path, or every path a terminal command reads, copies or archives (``mode`` is
    ``read`` or ``copy``; where a copy writes is left out)."""
    access = action_parsing.file_access_arg(tool_name, args)
    if access:
        return [(access["tool"], access["path"], access["mode"])]
    tool = (tool_name or "").strip().lower()
    if tool in CODE_TOOLS and isinstance(args, dict) and isinstance(args.get("code"), str):
        return [(tool, arg.path, "copy" if arg.recursive else "read")
                for arg in shell_files.code_file_args(args["code"])]   # KI-470
    if tool not in shell_shapes.SHELL_TOOLS:
        return []
    command = shell_shapes.command_from_args(tool_name, args)
    return [(tool, arg.path, "copy" if arg.recursive else "read")
            for arg in shell_files.shell_file_args(command) if not arg.destination]


def _candidates(path: str) -> list[str]:
    """*path* and the real files it stands for: what a wildcard expands to on disk (``cat server.k*``,
    KI-471) and where an existing link points (KI-472). The two lookups touch the disk only for a
    path that is anchored (absolute or under the home folder), at most :data:`_MAX_GLOB_FILES` files."""
    found = [path]
    expanded = os.path.expanduser(str(path or ""))
    if not os.path.isabs(expanded):
        return found
    try:
        if any(ch in expanded for ch in _GLOB_CHARS):
            found += [match for _, match in zip(range(_MAX_GLOB_FILES), glob.iglob(expanded, include_hidden=True))]
        found += [os.path.realpath(each) for each in list(found) if os.path.islink(os.path.expanduser(each))]
    except (OSError, ValueError):   # an unreadable folder or odd pattern: the text itself is still checked
        pass
    return found


def _name_glob_hits(path: str, pattern: str) -> bool:
    """True when *path* is a wildcard that could name a file a glob-free *pattern* protects:
    ``cat .env*`` reaches ``.env`` wherever it is (KI-471), with no file on disk to look at."""
    name = os.path.basename(os.path.normpath(os.path.expanduser(str(path or ""))))
    return (any(ch in name for ch in _GLOB_CHARS) and not any(ch in pattern for ch in _GLOB_CHARS)
            and fnmatch.fnmatch(os.path.basename(pattern.rstrip("/")), name))


def _protects(path: str, mode: str, pattern: str) -> bool:
    return (any(_protected_path_match(candidate, pattern) for candidate in _candidates(path))
            or _name_glob_hits(path, pattern)
            or (mode == "copy" and _folder_holds(path, pattern)))


def detect_custom_fileaccess(
    tool_name: str, args: Any, protected_paths: Iterable[str]
) -> list[Finding]:
    """Match a file tool or terminal command against the USER'S protected-path list.

    These are personal, locally-configured rules (``source="custom"``): they
    always flag, they block in block mode (the user wrote the rule), and they
    are NEVER reported to the community graph — the matched pattern is the
    user's own configuration, not shared threat intel. One finding per call.
    """
    patterns = [p for p in (protected_paths or []) if str(p or "").strip()]
    if not patterns:
        return []
    for tool, path, mode in _accesses(tool_name, args):
        for pattern in patterns:
            if _protects(path, mode, pattern):
                return [
                    Finding(
                        identifier=threat_ids.fileaccess_identifier(tool, "user-protected"),
                        category="fileaccess",
                        severity="critical",
                        title="Access to a user-protected path",
                        tool_name=tool,
                        matched="user-protected",
                        evidence=f"{mode} path matching protected pattern {str(pattern)[:120]}",
                        confirmed=False,
                        source="custom",
                        fields={},
                    )
                ]
    return []
