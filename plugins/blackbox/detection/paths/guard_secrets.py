"""Blackbox's own secrets: what an agent may not READ (Blackbox's protection, in every mode).

The rest of self-protection (:mod:`.guard_settings`) lets an agent read Blackbox and refuses only
a change. Some of what Blackbox keeps is a key, and reading it is the harm: the key that signs the
system protection helper's plans and reports, Blackbox's reporter key and its DKG node's keys.
An agent holding one can make Blackbox's own records say what it likes.

Two kinds of secret (:func:`secret_places`):

* the helper's key folder (``kernel.system_helper.user_key_folder``) — SEALED: an agent's call may
  not name it at all, not even to list it;
* the key files inside Blackbox's data folders (``constants.blackbox_home``: the reporter and
  curator keys; ``constants.blackbox_dkg_home``: the node's keystore, wallets and API token) —
  :data:`KEY_FILES`. Blackbox's records beside them (findings, audit) stay readable, and a listing
  of names stays ordinary work.

A command that reads a whole folder (an archive, a recursive copy or search, a ``find`` that runs
a command on everything) is refused when that folder holds a secret: ``tar czf x.tgz ~/.hermes``
carries the reporter key with it, and ``grep -r BEGIN ~/.hermes`` prints it.

Every spelling is judged by the path it resolves to (LES-105): ``~``, ``$HOME``, variables, a
relative word after a ``cd``, a wildcard (checked against the files it matches), a link (checked
against where it points) and — macOS folders ignore case — any mix of capitals.

Usage::

    reads_a_secret("terminal", {"command": "xxd ~/Library/Application\\\\ Support/Blackbox/helper/plan.key"})
    # -> "a read of Blackbox's keys"
    reads_a_secret("terminal", {"command": "ls ~/.hermes/blackbox"})   # -> "" (names only)
"""

from __future__ import annotations

import fnmatch
import glob
import os
import re
import sys
from typing import Any, NamedTuple

from .. import action_parsing, shell_shapes
from ...kernel import constants, system_helper
from . import guard_paths, guard_places, protected, shell_files

EVIDENCE = "a read of Blackbox's keys"
#: Commands that only list names or report sizes — what a listing of a data folder may use.
LIST_ONLY = frozenset({"ls", "ll", "stat", "du", "tree", "test", "[", "cd", "pushd", "popd", "realpath", "readlink",
                       "basename", "dirname", "pwd", "which", "file"})
#: Commands that, handed a folder, read everything inside it.
_WHOLE_FOLDER_READERS = frozenset({"cp", "rsync", "scp", "ditto", "zip", "tar", "bsdtar", "gtar", "grep", "egrep",
                                   "fgrep", "rg", "ag", "ack", "7z", "rclone", "aws", "gsutil"})
#: Code that names one of the secret places in pieces (``"Application Support", "Blackbox", "helper"``).
_IN_PIECES = re.compile(r"plan\.key|Blackbox\W{1,8}helper|(?:reporter|curator)_key\.pem|agent-keystore\.json|wallets\.key",
                         re.IGNORECASE)
#: Argument names other tools carry a path under.
_PATH_KEY = re.compile(r"path|file|dir|folder|glob|pattern|target|source|cwd|root", re.IGNORECASE)
_MAX_GLOB = 200
#: macOS and Windows folders ignore case: ``~/library/…/HELPER`` is the same folder.
_FOLD = sys.platform in ("darwin", "win32")


#: The names of key files in Blackbox's data folders (the reporter and curator keys are ``.pem``;
#: the node keeps its keystore, wallets and API token by these names — see setup/uninstall's backup).
KEY_FILES = ("*.pem", "*.key", "*.p12", "agent-keystore.json", "wallets.json", "wallets.key", "auth.token")


class Places(NamedTuple):
    sealed: tuple[str, ...]       # no call may name these at all
    contents: tuple[str, ...]     # the KEY_FILES inside these may not be read


def is_key_file(path: str) -> bool:
    """True when the file name *path* ends in is one of :data:`KEY_FILES`."""
    name = os.path.basename(path)
    return any(fnmatch.fnmatch(name, pattern.casefold() if _FOLD else pattern) for pattern in KEY_FILES)


def secret_places() -> Places:
    """The secret places on this machine, as absolute, link-resolved paths (worked out again when
    the home folders change, at most every few seconds — the rule runs on every tool call)."""
    return _PLACES.get(guard_places._machine())


def _read_places() -> Places:
    sealed = (str(system_helper.user_key_folder()),)
    contents = (str(constants.blackbox_home()), str(constants.blackbox_dkg_home()))
    return Places(tuple(_canonical(path) for path in sealed), tuple(_canonical(path) for path in contents))


_PLACES = guard_places.Kept(_read_places)


def _canonical(path: str) -> str:
    """*path* resolved (links followed as far as they exist), case-folded where folders ignore case."""
    resolved = os.path.realpath(os.path.expanduser(os.path.expandvars(path)))
    return resolved.casefold() if _FOLD else resolved


def _within(path: str, place: str) -> bool:
    return path == place or path.startswith(place.rstrip(os.sep) + os.sep)


def _matches(word: str, folder: str) -> list[str]:
    """The canonical paths *word* stands for: itself, or the files a wildcard expands to."""
    joined = guard_paths._place(guard_paths._UNQUOTED.sub("", word), folder)
    path = guard_places._expanded(joined)
    if not path:
        return []
    if not any(char in path for char in "*?["):
        return [_canonical(path)]
    try:
        return [_canonical(found) for _, found in zip(range(_MAX_GLOB), glob.iglob(path, include_hidden=True))]
    except (OSError, ValueError):
        return []


def _word_reaches(word: str, folder: str, command: str, places: Places) -> bool:
    """True when *word*, used by *command*, reaches a secret: names a sealed place (or a file in it),
    names a file inside a data folder for anything but a listing, or hands a folder holding a
    secret whole to a command that reads everything inside."""
    for path in _matches(word, folder):
        if any(_within(path, place) for place in places.sealed):
            return True
        if command not in LIST_ONLY and is_key_file(path) and any(_within(path, place) for place in places.contents):
            return True
        if command in _WHOLE_FOLDER_READERS and any(_within(place, path) for place in (*places.sealed, *places.contents)):
            return True
    return False


#: A file name for each of :data:`KEY_FILES`, to test whether a ``find -name`` pattern could pick one.
_KEY_EXAMPLES = ("reporter_key.pem", "curator.key", "id.p12", "agent-keystore.json", "wallets.json", "wallets.key",
                 "auth.token")
#: Commands whose last word is where they write, not what they read.
_COPIERS = frozenset({"cp", "rsync", "scp", "ditto"})


def _as_reader(name: str, rest: list[str]) -> str:
    """*name* as this rule judges it: a ``find`` that runs a command on what it finds reads it all;
    a ``tar`` that unpacks reads nothing it is given."""
    if name == "find":
        names = [rest[index + 1] for index, word in enumerate(rest[:-1]) if word in ("-name", "-iname")]
        runs = any(word in ("-exec", "-execdir", "-ok", "-okdir") for word in rest)
        # A find that only picks files no key could be named after (``-name '*.md'``) reads no key.
        keys_possible = not names or any(fnmatch.fnmatch(key, guard_paths._UNQUOTED.sub("", pattern))
                                         for pattern in names for key in _KEY_EXAMPLES)
        return "grep" if runs and keys_possible else "find"
    if name in ("tar", "bsdtar", "gtar") and rest and "x" in rest[0].lstrip("-"):
        return "tar-unpack"
    return name


def _sources(name: str, rest: list[str]) -> list[str]:
    """The words a command reads from: for a copier, all but its destination (the last plain word)."""
    if name not in _COPIERS:
        return rest
    plain = [index for index, word in enumerate(rest) if not word.startswith("-")]
    return [word for index, word in enumerate(rest) if not plain or index != plain[-1]]


def _line_reaches(line: str, folder: str, places: Places) -> tuple[bool, str]:
    """``(reaches, folder)`` for one command line run in *folder*, following ``cd``."""
    words = shell_files._with_variables(shell_files._words(line))
    for segment in guard_paths._segments(words):
        name, rest = guard_paths._command_of(segment)
        if name in ("cd", "pushd"):
            target = shell_files._cd(segment, 0, folder)[0]
            if target and _word_reaches(target, guard_paths.START_FOLDER, name, places):
                return True, folder
            folder = target or folder
            continue
        reader = _as_reader(name, rest)
        pieces = [piece for word in _sources(name, rest) for piece in (word, *word.split("=", 1)[1:], *(word.split() if " " in word else []))]
        if any(_word_reaches(piece, folder, reader, places) for piece in pieces if piece and piece != "<"):
            return True, folder
    return False, folder


def _text_reaches(text: str, places: Places) -> bool:
    """True when command text *text* (nested shells, base64 words and heredocs included) reaches a secret."""
    from .guard_settings import _HANDS_ON, _inline_code, _lines   # one reading of a command for both rules
    hands_on = bool(_HANDS_ON.search(text))
    folder = guard_paths.START_FOLDER
    nested = shell_shapes.with_nested_commands(text, 1).split("\n")[1:] if hands_on else []
    for line in [*_lines(text), *nested]:
        # The cheap test first: a line with no path sign, after no ``cd``, cannot name a secret.
        if not line.strip() or (folder == guard_paths.START_FOLDER and not guard_paths._CAN_NAME_A_PLACE.search(line)):
            continue
        reaches, folder = _line_reaches(line, folder, places)
        if reaches:
            return True
    return hands_on and any(_code_reaches(code, places) for code in _inline_code(text))


def _code_reaches(code: str, places: Places) -> bool:
    """True when *code* names a secret file (whole, in pieces, or through a path it opens)."""
    if _IN_PIECES.search(code):
        return True
    return any(_word_reaches(arg.path, guard_paths.START_FOLDER, "cat", places) for arg in shell_files.code_file_args(code))


def _path_values(args: Any) -> list[str]:
    """Every string a non-shell tool carries under a path-like name, or that reads as a path."""
    if not isinstance(args, dict):
        return []
    return [value for key, value in args.items() if isinstance(value, str)
            and (_PATH_KEY.search(str(key)) or value.lstrip().startswith(("/", "~", "$HOME", "${HOME}")))]


def reads_a_secret(tool_name: str, args: Any) -> str:
    """The evidence when an agent's call would read (or, for the key folder, name) one of
    Blackbox's secrets — whatever the tool — else ``""``."""
    tool = (tool_name or "").strip().lower()
    places = secret_places()
    access = action_parsing.file_access_arg(tool_name, args)
    if access is not None:
        return EVIDENCE if _word_reaches(access["path"], guard_paths.START_FOLDER, "cat", places) else ""
    if tool in protected.CODE_TOOLS and isinstance(args, dict) and isinstance(args.get("code"), str):
        return EVIDENCE if _code_reaches(args["code"], places) else ""
    if tool in shell_shapes.SHELL_TOOLS:
        return EVIDENCE if _text_reaches(shell_shapes.whole_command_from_args(tool_name, args), places) else ""
    from .guard_settings import _COMMAND_KEY
    values = args if isinstance(args, dict) else {}
    commands = [value for key, value in values.items() if _COMMAND_KEY.search(str(key)) and isinstance(value, str)]
    if any(_text_reaches(command, places) for command in commands):
        return EVIDENCE
    reader = "grep" if re.search(r"grep|search", tool) else "ls" if re.search(r"glob|list|ls\b", tool) else "cat"
    return EVIDENCE if any(_word_reaches(path, guard_paths.START_FOLDER, reader, places) for path in _path_values(args)) else ""
