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

The ONE answer to "does this action touch any of these protected paths, and which" is
:func:`touches` — the person's list (:func:`detect_custom_fileaccess`), Blackbox's own keys
(``guard_secrets``) and any later list ask it. Every path is judged as written AND as what it
resolves to (``..``, links anywhere along it, ``$HOME``, and — where folders ignore case, macOS
and Windows — any mix of capitals): the canonical path, never the caller's spelling (LES-105).

Usage::

    touches("terminal", {"command": "xxd ~/.ssh/id_rsa"}, ["~/.ssh/*"])
    # -> [PathTouch(tool="terminal", path="~/.ssh/id_rsa", mode="read", pattern="~/.ssh/*")]
    detect_custom_fileaccess("read_file", {"path": "~/.ssh/id_rsa"}, ["~/.ssh/*"])
    detect_custom_fileaccess("terminal", {"command": "cat .env"}, [".env"])
    # -> [Finding(category="fileaccess", source="custom", severity="critical", ...)]
"""

from __future__ import annotations

import fnmatch
import glob
import os
import re
import sys
from typing import Any, Iterable, NamedTuple

from .. import action_parsing, shell_shapes
from ..finding import Finding
from ...kernel import threat_ids
from . import shell_files, shell_words

#: Tools that run code directly, with the code in ``args["code"]`` (Hermes's ``execute_code`` runs Python).
CODE_TOOLS = frozenset({"execute_code", "code_execution", "run_code", "run_python", "python"})
#: At most this many files a wildcard expands to are checked; a wildcard naming more is checked by its
#: own text only (a protected file still matches when the pattern itself names it).
_MAX_GLOB_FILES = 64
_GLOB_CHARS = "*?["

#: Folders on these systems ignore case: ``~/.SSH/id_rsa`` is ``~/.ssh/id_rsa``.
_FOLDS_CASE = sys.platform in ("darwin", "win32")
#: Argument names a non-shell tool (an MCP tool, a search tool) carries a path under.
_PATH_ARG = re.compile(r"path|file|dir|folder|target|source|cwd|root|location|uri", re.IGNORECASE)
#: Argument names any tool carries a command to run under (a shell by another name).
_COMMAND_ARG = re.compile(r"^(?:command|cmd|script|shell|argv|args|exec)$", re.IGNORECASE)

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
        if _FOLDS_CASE:
            norm_path, norm_pat = norm_path.casefold(), norm_pat.casefold()
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
    if _FOLDS_CASE:
        place, norm_folder = place.casefold(), norm_folder.casefold()
    return place == norm_folder or place.startswith(norm_folder.rstrip(os.sep) + os.sep)


def _accesses(tool_name: str, args: Any, *, whole: bool = False, every_route: bool = False,
              changes: bool = False) -> list[tuple[str, str, str]]:
    """``(tool, path, mode)`` for each file this call reads or copies: the file tool's
    path, every path a terminal command reads, copies or archives (``mode`` is ``read`` or
    ``copy``; where a copy writes is left out), the paths in code a code tool runs, and — for
    any other tool (an MCP tool, a search tool) — a command it carries and the paths in its
    arguments. *whole*: read a long command whole (Blackbox's own protection) rather than by
    the bounded window every other check reads. *every_route*: also where a command WRITES and
    every path it names at all (``ls``, ``rm``, ``touch``, ``cd`` …) — for a list nothing may touch
    by any route (File Shield's protected items), not only what would leave a secret. *changes*:
    with *every_route*, a named path counts only for a command that changes it (:data:`_CHANGE_COMMANDS`)."""
    access = action_parsing.file_access_arg(tool_name, args)
    if access:
        return [(access["tool"], access["path"], access["mode"])]
    tool = (tool_name or "").strip().lower()
    if tool in CODE_TOOLS and isinstance(args, dict) and isinstance(args.get("code"), str):
        return [(tool, arg.path, "copy" if arg.recursive else "read")
                for arg in shell_files.code_file_args(args["code"])]   # KI-470
    if tool in shell_shapes.SHELL_TOOLS:
        return [found for command in _commands(tool_name, args, whole)
                for found in _command_accesses(tool, command, every_route=every_route, changes=changes)]
    if not isinstance(args, dict):
        return []
    found: list[tuple[str, str, str]] = []
    for key, value in args.items():
        if not isinstance(value, str) or not value.strip():
            continue
        if _COMMAND_ARG.search(str(key)):
            found += _command_accesses(tool, shell_shapes.with_nested_commands(value[:_MAX_ARG_CHARS]),
                                       every_route=every_route, changes=changes)
        elif _PATH_ARG.search(str(key)):   # a search query that happens to hold a path is not a file access
            mode = ("write" if changes and _WRITING_TOOL.search(tool) else
                    "copy" if re.search(r"grep|search|find|copy|archive|zip|sync", tool) else "read")
            found.append((tool, value.strip(), mode))
    return found


#: The most of one non-shell argument read as a command.
_MAX_ARG_CHARS = 200_000


#: A sign that text can name a path: a home or variable sign, a wildcard, a slash, ``..`` or a ``cd``.
_PATH_SIGN = re.compile(r"[~$*?\[/]|\.\.|\bcd\b|\bpushd\b")


def _commands(tool_name: str, args: Any, whole: bool) -> list[str]:
    """The command text(s) to read: the bounded command every check shares (parsed once, cached),
    and — *whole* — the middle a long command's window leaves out, read only when it can name a
    path at all. WHY: a protected path hidden in the middle of a padded command must not pass, and
    harmless padding must not cost a second full parse (test_blackbox_long_commands)."""
    bounded = shell_shapes.command_from_args(tool_name, args)
    if not whole:
        return [bounded]
    full = shell_shapes.whole_command_from_args(tool_name, args)
    window = shell_shapes.COMMAND_SCAN_WINDOW
    middle = full[window:-window] if len(full) > 2 * window else ""
    return [bounded, shell_shapes.with_nested_commands(middle)] if middle and _PATH_SIGN.search(middle) else [bounded]


def _command_accesses(tool: str, command: str, *, every_route: bool = False, changes: bool = False) -> list[tuple[str, str, str]]:
    """The reads and copies of *command*, through the one shell-path parser (:mod:`.shell_files`);
    *every_route*: also its writes and every path it names (:func:`_named_paths`); *changes*: only
    its writes and the paths named to a command that changes them."""
    names = _find_names(command) if "find" in command else ()
    found = [(tool, arg.path, "write" if arg.destination else "copy-names:" + "\x00".join(names)
              if arg.command == "find" and names else "copy" if arg.recursive else "read")
             for arg in shell_files.shell_file_args(command) if every_route or not arg.destination]
    if not every_route:
        return found
    named = [(tool, path, "tree" if verb in _TREE_COMMANDS else "write" if changes else "name")
             for path, verb in _named_paths(command) if not changes or verb in _CHANGE_COMMANDS]
    return [each for each in found if each[2] == "write"] + named if changes else found + named


#: Commands that act on a folder's whole tree (delete, move, re-own, re-permission, sync, pack):
#: naming a folder that HOLDS a protected item reaches the item too (deleting ~/Work removes ~/Work/Taxes).
_TREE_COMMANDS = frozenset({"rm", "rmdir", "mv", "chmod", "chown", "chgrp", "chflags", "xattr", "trash", "srm",
                            "shred", "unlink", "find", "rsync", "ditto", "tar", "zip", "7z", "cp", "scp", "ln",
                            "del", "rd", "remove-item", "move-item", "copy-item", "robocopy", "xcopy"})
#: Commands that change what they name (a folder kept read-only refuses them): delete, move, link,
#: create, re-own, re-permission, a redirect (``>``). Readers that may also write (``sed``, ``dd``) are left to the sandbox.
_CHANGE_COMMANDS = frozenset({">", "rm", "rmdir", "mv", "chmod", "chown", "chgrp", "chflags", "xattr", "trash", "srm", "shred",
                              "unlink", "ln", "touch", "mkdir", "truncate", "tee", "install", "del", "rd", "remove-item",
                              "move-item", "rename-item", "new-item", "set-content", "add-content", "out-file"})
#: A non-shell tool (an MCP tool) whose name says it writes the path it is given.
_WRITING_TOOL = re.compile(r"write|edit|create|delete|remove|move|rename|patch|save|upload|mkdir", re.IGNORECASE)


def _named_paths(command: str) -> list[tuple[str, str]]:
    """Every path *command* names in any word, whatever the command does with it (``rm``, ``ls``,
    ``touch``, ``chmod``, ``mv``, a redirect target, ``cd``), with variables set on the line put in,
    a relative path placed under the folder an earlier ``cd`` moved to, and the home folder
    written ``~``. WHY: for an item nothing may touch, an unknown command naming it is enough —
    the list of commands that read files can never be complete. Each comes with its command's name."""
    words = shell_words.with_variables(shell_words.words(command))
    folder, found, index, verb = "", [], 0, ""
    while index < len(words):
        word = words[index]
        name = word.rsplit("/", 1)[-1].lower()
        if name in ("cd", "pushd"):
            moved, index = shell_files.cd_target(words, index, folder)
            folder, verb = moved, ""
            if moved:
                found.append((moved, "cd"))
            continue
        index += 1
        if word in shell_words.SEPARATORS:
            verb = ""
            continue
        if not verb and not word.startswith("-") and "=" not in word[:1]:
            verb = name   # the first word of a segment is its command (``sudo`` passes it on)
            if verb in ("sudo", "doas", "env", "nohup", "time", "command", "exec", "xargs"):
                verb = ""
            if not _NAMES_PLACE.search(word):
                continue
        if word.startswith("-") or not _NAMES_PLACE.search(word):
            continue
        path = word.split("=", 1)[1] if word.startswith(("if=", "of=")) else word
        if folder and not shell_words.is_anchored(path):
            path = folder.rstrip("/") + "/" + path.removeprefix("./")
        redirected = index > 1 and words[index - 2] in (">", ">>", ">|", "&>", "&>>")   # a redirect target is written
        found.append((shell_words.home_as_tilde(path), ">" if redirected else verb))
    return list(dict.fromkeys(found))


#: A word that can name a place: a slash, the home sign, a home variable or a leading dot.
_NAMES_PLACE = re.compile(r"/|^~|^\$HOME|^\$\{HOME\}|^\.")


def _find_names(command: str) -> tuple[str, ...]:
    """The ``-name`` / ``-iname`` patterns a ``find`` in *command* picks files by."""
    words = shell_words.words(command)
    return tuple(words[index + 1] for index, word in enumerate(words[:-1]) if word in ("-name", "-iname"))


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
        # Where each one really is: ``..`` folded away and a link ANYWHERE along it followed
        # (``~/projects/innocent/key`` when ``innocent`` links to a protected folder).
        found += [real for each in list(found)
                  if (real := os.path.realpath(os.path.expanduser(each))) != os.path.normpath(os.path.expanduser(each))]
    except (OSError, ValueError):   # an unreadable folder or odd pattern: the text itself is still checked
        pass
    return found


def _name_glob_hits(path: str, pattern: str) -> bool:
    """True when *path* is a wildcard that could name a file a glob-free *pattern* protects:
    ``cat .env*`` reaches ``.env`` wherever it is (KI-471), with no file on disk to look at."""
    expanded = os.path.normpath(os.path.expanduser(str(path or "")))
    name = os.path.basename(expanded)
    # WHY only where there is nothing on disk to look at (2026-11-21): ``cp ~/pkg/* ~`` names an
    # existing folder, whose real matches :func:`_candidates` already checks; judging its ``*`` by
    # name alone refused it for every protected file name anywhere (Blackbox's keystore, ``.env``).
    if os.path.isabs(expanded) and os.path.isdir(os.path.dirname(expanded)):
        return False
    return (any(ch in name for ch in _GLOB_CHARS) and not any(ch in pattern for ch in _GLOB_CHARS)
            and fnmatch.fnmatch(os.path.basename(pattern.rstrip("/")), name))


def _protects(path: str, mode: str, pattern: str) -> bool:
    if any(_protected_path_match(candidate, pattern) for candidate in _candidates(path)) or _name_glob_hits(path, pattern):
        return True
    if mode in ("copy", "tree") or mode.startswith("copy-names:"):
        names = mode.split(":", 1)[1].split("\x00") if ":" in mode else []
        return (not names or any(_names_overlap(name, pattern) for name in names)) and any(
            _folder_holds(candidate, pattern) for candidate in _candidates(path))
    return False


def _names_overlap(name: str, pattern: str) -> bool:
    """True when a file ``find -name NAME`` picks could be one *pattern* protects (``*.md`` never
    names ``wallets.key``). A folder pattern (``~/.ssh/*``, or a folder that exists) protects any name."""
    expanded = os.path.expanduser(str(pattern)).rstrip(os.sep)
    base = os.path.basename(expanded)
    folder = os.path.dirname(expanded) if base == "*" else expanded if os.path.isdir(expanded) else ""
    if folder:   # a protected folder: does it hold a file of that name? (it is small; at most a few hundred looked at)
        try:
            return any(True for _, _found in zip(range(_MAX_GLOB_FILES), glob.iglob(
                os.path.join(glob.escape(folder), "**", name), recursive=True, include_hidden=True)))
        except (OSError, ValueError):
            return True
    if not any(ch in base for ch in _GLOB_CHARS):
        return fnmatch.fnmatch(base, name)
    if not any(ch in name for ch in _GLOB_CHARS):
        return fnmatch.fnmatch(name, base)
    # Two globs: compare what each requires after its last wildcard (``*.md`` against ``*.pem``).
    tail_name, tail_base = name.rsplit("*", 1)[-1], base.rsplit("*", 1)[-1]
    return tail_name.endswith(tail_base) or tail_base.endswith(tail_name)


class PathTouch(NamedTuple):
    """One protected path an action reaches: the tool, the path as the action wrote it, how it
    reaches it (``read``, ``copy``, ``write``) and the pattern it matched."""

    tool: str
    path: str
    mode: str
    pattern: str


def touches(tool_name: str, args: Any, patterns: Iterable[str], *, whole: bool = False,
            first_only: bool = False, every_route: bool = False, changes: bool = False) -> list[PathTouch]:
    """Every (path, pattern) this call reaches among *patterns* — the reusable answer for any list
    of protected places (the person's, Blackbox's own keys, File Shield's). *whole*: read a long
    command whole (for a rule that must not be outrun); *first_only*: stop at the first;
    *every_route*: any touch at all counts — writes, deletes, moves, listings, a ``cd`` into it —
    not only reading or copying (File Shield's protected items); *changes*: only what WRITES, deletes,
    moves, creates or re-permissions there — a folder kept read-only (``mode`` ``write`` or ``tree``)."""
    wanted = [str(p) for p in (patterns or []) if str(p or "").strip()]
    found: list[PathTouch] = []
    if not wanted:
        return found
    for tool, path, mode in _accesses(tool_name, args, whole=whole, every_route=every_route or changes, changes=changes):
        if changes and mode not in ("write", "tree"):
            continue
        path = shell_words.home_as_tilde(path)   # a file tool's "$HOME/…" is the same "~/…"
        for pattern in wanted:
            if _protects(path, mode, pattern):
                found.append(PathTouch(tool, path, "copy" if mode.startswith("copy") else mode, pattern))
                if first_only:
                    return found
                break
    return found


#: A place written in prose: from the home sign, a home variable, or the root.
_TEXT_PATH = re.compile(r"(?<![\w.])(?:~|\$HOME|\$\{HOME\}|/)[^\s'\"`<>|;,(){}\[\]]*")
#: The most of one text read for places it names.
_MAX_TEXT_CHARS = 64 * 1024


def mentions(text: str, patterns: Iterable[str]) -> list[PathTouch]:
    """Every protected place *text* (a prompt, a message) names among *patterns*: a prompt that
    asks an agent for a protected item. Naming is not touching — the caller flags it; the agent's
    tool call that would touch the item is what is refused. Reads no disk."""
    wanted = [str(p) for p in (patterns or []) if str(p or "").strip()]
    found: list[PathTouch] = []
    for match in _TEXT_PATH.finditer(str(text or "")[:_MAX_TEXT_CHARS]) if wanted else ():
        path = shell_words.home_as_tilde(match.group(0).rstrip(".:!?"))
        pattern = next((item for item in wanted if _protected_path_match(path, item)), None)
        if pattern and len(path) > 1:
            found.append(PathTouch("prompt", path, "mention", pattern))
    return found


def detect_custom_fileaccess(
    tool_name: str, args: Any, protected_paths: Iterable[str]
) -> list[Finding]:
    """Match a file tool or terminal command against the USER'S protected-path list.

    These are personal, locally-configured rules (``source="custom"``): they
    always flag, they block in block mode (the user wrote the rule), and they
    are NEVER reported to the community graph — the matched pattern is the
    user's own configuration, not shared threat intel. One finding per call.
    """
    # Read whole, like Blackbox's own keys: one parse of the command serves both rules, and padding
    # a command past the bounded window no longer hides a protected path from the person's rule.
    for touch in touches(tool_name, args, protected_paths, whole=True, first_only=True):
        return [
            Finding(
                identifier=threat_ids.fileaccess_identifier(touch.tool, "user-protected"),
                category="fileaccess",
                severity="critical",
                title="Access to a user-protected path",
                tool_name=touch.tool,
                matched="user-protected",
                evidence=f"{touch.mode} path matching protected pattern {touch.pattern[:120]}",
                confirmed=False,
                source="custom",
                fields={},
            )
        ]
    return []
