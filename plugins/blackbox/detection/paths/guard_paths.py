"""Does a command line do more to a guarded place than read it? (Blackbox's own protection.)

Deny by reference: a command that NAMES a guarded place (:mod:`.guard_places`) is taken as
changing it unless the command only reads (:data:`READ_ONLY`), copies FROM it, or is one of
Blackbox's own commands (judged by what they say, :mod:`.guard_commands`). Where a line sends
its output (``>``, ``tee``) is checked whatever the command was. A list of the commands that
write was the first design and lost to the next command nobody had listed (``git``, ``patch``,
``vim``, ``find -delete``).

* :func:`worth_reading` — a cheap test of whether a line can name a place at all; the costly
  word-by-word reading is kept for the lines that pass (a long command is mostly text that
  cannot).
* :func:`line_changes_a_place` — the reading itself; it follows ``cd`` from line to line.

Usage::

    changes, folder = line_changes_a_place("cd ~/.hermes", START_FOLDER)   # (False, "~/.hermes")
    changes, folder = line_changes_a_place("rm config.yaml", folder)       # (True, "~/.hermes")
"""

from __future__ import annotations

import os
import re

from . import guard_landing, guard_places, shell_files

#: The folder a command is taken to start in when no ``cd`` has said otherwise.
START_FOLDER = "~"
#: Commands that only read what they are given: a line naming a guarded place may hold only these.
READ_ONLY = frozenset({
    "cat", "less", "more", "head", "tail", "ls", "ll", "stat", "file", "wc", "grep", "egrep", "fgrep", "rg", "ag",
    "diff", "cmp", "jq", "md5", "md5sum", "shasum", "sha1sum", "sha256sum", "du", "tree", "test", "[", "cd", "pushd",
    "popd", "realpath", "readlink", "basename", "dirname", "sort", "uniq", "cut", "nl", "tac", "xxd", "hexdump",
    "strings", "od", "base64", "open", "pwd", "true", "which", "column", "df", "mdfind", "mdls",
})
#: Commands that only ADD a new entry and never change one already there: a folder that merely
#: holds a guarded place may be given to them (``mkdir -p ~/Documents``), a guarded place never.
_ONLY_ADDS = frozenset({"mkdir"})
#: Inside quoted text, the root folder or a wildcard right under it is how comments start
#: (``sed -i '1i // note'``, ``'/* c */'``), not a folder handed to a command: a root handed to a
#: command is a word of its own, and that is still read. KI-591.
_ROOT_IN_TEXT = re.compile(r"^/+(?:\*+)?$")
#: Commands that copy: a guarded place may be what they read, never where they write.
_COPIES = frozenset({"cp", "rsync", "scp", "ditto", "zip"})
#: Words that run another command: the command after them is the one judged.
_WRAPPERS = frozenset({"sudo", "env", "nohup", "time", "command", "exec", "nice", "builtin", "doas"})
_FIND_ACTS = frozenset({"-delete", "-exec", "-execdir", "-ok", "-okdir", "-fprint", "-fprintf", "-fls"})
#: ``git`` subcommands that rewrite the working tree: run in the checkout an install loads from, they rewrite Blackbox.
_GIT_REWRITES = frozenset({"checkout", "reset", "stash", "clean", "restore", "pull", "merge", "rebase", "switch", "apply",
                           "revert", "rm", "mv", "cherry-pick", "am"})
#: Where a line sends its output: after ``>`` / ``>>``, or the file ``tee`` is given.
_REDIRECT_TARGET = re.compile(r"(?<![0-9&])>>?\s*([^\s;&|<>]+)|\btee\b(?:\s+-[a-zA-Z]+)*\s+([^\s;&|<>]+)")
#: Quote marks, brackets and written-out line ends around a path inside quoted text.
_UNQUOTED = re.compile(r"\\[nrt0]|['\"`;()]")
#: Blackbox's own commands: judged by what they say (:func:`guard_commands.switches_off`), not by the
#: places they name — ``blackbox attach <profile>`` ADDS protection and must stay possible.
_OWN_COMMANDS = frozenset({"hermes", "blackbox"})
#: What a line must hold to be able to name a place: a home or variable sign, a wildcard, an
#: absolute path, a ``cd`` or ``git``, or the first folder of a guarded place written relatively.
_CAN_NAME_A_PLACE = re.compile(
    r"[~$*?\[`]|(?:^|[\s=:'\"(<>])/|\b(?:cd|pushd|git)\b|\.(?:hermes|openclaw|config|local)\b|Library|blackbox|integrations",
    re.IGNORECASE)


def worth_reading(line: str, folder: str) -> bool:
    """True when *line* could name a guarded place: it holds a path-like sign, or an earlier
    ``cd`` moved into (or above) a guarded place, where a bare file name is enough."""
    return bool(_CAN_NAME_A_PLACE.search(line)) or (folder != START_FOLDER and guard_places.reaches(folder))


def _command_of(segment: list[str]) -> tuple[str, list[str]]:
    """The command one simple command runs and its other words, past ``NAME=value`` words and
    wrappers (``sudo``, ``env``, ``nohup``…)."""
    index = 0
    while index < len(segment) and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", segment[index])
                                    or segment[index].rsplit("/", 1)[-1].lower() in _WRAPPERS):
        index += 1
    if index >= len(segment):
        return "", []
    return segment[index].rsplit("/", 1)[-1].lower(), segment[index + 1:]


def _place(word: str, folder: str) -> str:
    """*word* as a path, joined onto the folder an earlier ``cd`` moved to when it is relative."""
    if folder == START_FOLDER and word.strip("./") == "":
        return word      # "." with no ``cd`` before it: the folder the agent works in is not known
    if folder and not os.path.isabs(os.path.expanduser(os.path.expandvars(shell_files._home_as_tilde(word)))):
        return folder.rstrip("/") + "/" + word.removeprefix("./")
    return word


#: What a command line's words name: nothing, only a folder ABOVE a guarded place, or the place.
NAMES_NOTHING, HOLDS_ONE, NAMES_ONE = 0, 1, 2


def _named_places(words: list[str], folder: str) -> int:
    """:data:`NAMES_ONE` when one of *words* — or a word inside one that was quoted, or the value
    of a ``--flag=value`` / ``NAME=value`` — names a guarded place (or a wildcard matching one);
    :data:`HOLDS_ONE` when they name only a folder that holds one; else :data:`NAMES_NOTHING`."""
    level = NAMES_NOTHING
    for word in words:
        pieces = [(word, False), *((value, False) for value in word.split("=", 1)[1:]),
                  *((piece, True) for piece in (word.split() if " " in word else []))]
        for piece, in_text in pieces:
            path = _place(_UNQUOTED.sub("", piece), folder) if piece else ""
            if not path or (in_text and _ROOT_IN_TEXT.match(path)) or not guard_places.reaches(path):
                continue
            if not guard_places.holds(path):
                return NAMES_ONE
            level = HOLDS_ONE
    return level


def _git_rewrites_a_checkout(rest: list[str], folder: str) -> bool:
    """True for a ``git`` command that rewrites the working tree of a checkout a running install
    loads from (the folder it runs in, or the one after ``-C``)."""
    where = next((rest[index + 1] for index, word in enumerate(rest[:-1]) if word == "-C"), folder)
    return guard_places.is_source_checkout(_place(where, folder)) and any(word in _GIT_REWRITES for word in rest)


def _find_only_reads(rest: list[str]) -> bool:
    """True for a ``find`` that only lists, or hands what it finds to a command that only reads."""
    for index, word in enumerate(rest):
        if word in ("-exec", "-execdir", "-ok", "-okdir"):
            ran = rest[index + 1:index + 2]
            if not ran or ran[0].rsplit("/", 1)[-1].lower() not in READ_ONLY:
                return False
        elif word in _FIND_ACTS:
            return False
    return True


def _only_reads(name: str, rest: list[str]) -> bool:
    """True when command *name* with words *rest* cannot change the files it is given."""
    if name == "find":
        return _find_only_reads(rest)
    if name in ("tar", "bsdtar", "gtar"):          # making an archive reads; unpacking one writes
        return bool(rest) and "c" in rest[0].lstrip("-") and "x" not in rest[0].lstrip("-")
    if name in ("sed", "gsed", "perl", "yq", "awk", "gawk"):
        return not any(word.startswith("--in-place") or (word.startswith("-") and not word.startswith("--") and "i" in word)
                       for word in rest)
    return name in READ_ONLY


def _segments(words: list[str]) -> list[list[str]]:
    segments, current = [], []
    for word in words:
        if word in shell_files._SEPARATORS:
            segments.append(current)
            current = []
        else:
            current.append(word)
    return [segment for segment in segments + [current] if segment]


def line_changes_a_place(line: str, folder: str) -> tuple[bool, str]:
    """``(changes, folder)``: whether *line*, run in *folder*, does anything to a guarded place
    but read it or sends its output onto one; and the folder the next line runs in."""
    words = shell_files._with_variables(shell_files._words(line))
    for segment in _segments(words):
        name, rest = _command_of(segment)
        if name in ("cd", "pushd"):
            folder = shell_files._cd(segment, 0, folder)[0] or next((word for word in segment[1:] if word.startswith("$")), "")
            continue
        if _segment_changes_a_place(name, rest, segment, folder, line):
            return True, folder
    # Where output is sent is checked whatever the command was (``echo 'exit 0' > ~/.local/bin/blackbox``).
    return any(guard_places.reaches(_place(found.group(1) or found.group(2) or "", folder))
               for found in _REDIRECT_TARGET.finditer(line)), folder


def _segment_changes_a_place(name: str, rest: list[str], segment: list[str], folder: str, line: str) -> bool:
    """True when one simple command (*name* with words *rest*) changes a guarded place."""
    if name == "git" and _git_rewrites_a_checkout(rest, folder):
        return True
    if name in _OWN_COMMANDS:
        return False
    named = _named_places(segment, folder)
    if guard_places.inside(folder) and rest:
        named = NAMES_ONE
    if named == NAMES_NOTHING:
        return False
    if name in guard_landing.LANDING_COPIES:
        # Judged by what LANDS, not by the folder word: ``cp notes.md ~`` writes ``~/notes.md``.
        return guard_landing.copy_writes_a_place(name, segment, folder)
    if name in _COPIES:
        written = [arg.path for arg in shell_files.shell_file_args(" ".join(segment)) if arg.destination]
        return any(guard_places.reaches(_place(path, folder)) for path in written)
    if guard_landing.extracts(name, rest):
        return guard_landing.unpack_writes_a_place(name, rest, folder)
    if name in ("echo", "printf"):
        return bool(re.search(r"[|>]", line))          # printed into a file or another program
    if named == HOLDS_ONE and name in _ONLY_ADDS:
        return False      # it adds a folder; it cannot reach what the folder already holds (KI-591)
    return not _only_reads(name, rest)
