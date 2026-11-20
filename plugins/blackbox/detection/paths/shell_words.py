"""A shell command line as words, and one path among them — the base the shell file view stands on.

Split out of :mod:`.shell_files` (2026-11-20, a move only) when that file passed the size alarm:
this part knows how a command line is SPLIT and how a path is WRITTEN; ``shell_files`` knows which
commands read which of their words, and :mod:`.shell_scripts` reads paths out of script code.

* :class:`ShellFileArg` — one path a command touches (as written, the home folder spelled ``~``).
* ``_words`` / ``_split`` — the words of a command, split the way a POSIX shell splits them
  (quotes and backslash escapes respected; a Windows path line is split without POSIX escaping;
  an unbalanced quote falls back to whitespace).
* ``_with_variables`` — variables set earlier on the line put in where they are used.
* ``_home_as_tilde``, ``_is_anchored``, ``_looks_like_path``, ``_segment_end``, ``_SEPARATORS``.

Pure and deterministic; reads no files.
"""

from __future__ import annotations

import functools
import re
import shlex
from dataclasses import dataclass

_SEPARATORS = frozenset({";", "&&", "||", "|", "&", ">", ">>", "<", "|&"})


@dataclass(frozen=True)
class ShellFileArg:
    """One path a shell command touches. ``path`` is the word as written with the home
    folder spelled ``~`` (``$HOME`` and ``${HOME}`` are rewritten to it; ``~`` itself is NOT
    expanded — matching code expands); ``recursive`` is True when the command takes a folder
    argument as everything inside it."""

    path: str
    command: str
    recursive: bool
    #: True for where a copy or archive WRITES (``cp src DEST``, ``tar czf OUT.tgz``) —
    #: nothing is read from it. Rules about what leaves a file skip these.
    destination: bool = False


#: The home folder named by a variable at the start of a path: ``$HOME``, ``${HOME}``, ``%USERPROFILE%``.
_HOME_VARIABLE = re.compile(r"^(?:\$HOME(?![A-Za-z0-9_])|\$\{HOME\}|%USERPROFILE%)")


def _home_as_tilde(path: str) -> str:
    """*path* with a leading home-folder variable written as ``~`` (see the module doc)."""
    return _HOME_VARIABLE.sub("~", path, count=1)


#: A Windows path (``C:\\Users``, ``%APPDATA%\\``): backslash is a separator there,
#: not an escape, so such a line is split without POSIX escaping.
_WINDOWS_PATH = re.compile(r"[A-Za-z]:\\|%[A-Za-z_]+%\\")


def _words(command: str) -> list[str]:
    """The shell words of *command* (a fresh list). Several checks split the same command of
    one call, so the last few splits are remembered (:func:`_split`)."""
    return list(_split(command))


@functools.lru_cache(maxsize=4)
def _split(command: str) -> tuple[str, ...]:
    try:
        if _WINDOWS_PATH.search(command):
            lexer = shlex.shlex(command, posix=False, punctuation_chars=";&|<>")
            lexer.whitespace_split = True
            return tuple(word.strip("\"'") for word in lexer)
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>")
        lexer.whitespace_split = True
        return tuple(lexer)
    except ValueError:  # an unbalanced quote: still find the paths
        return tuple(command.split())


def _looks_like_path(word: str) -> bool:
    return "/" in word or "\\" in word or word.startswith(("~", ".", "$HOME", "%")) or "." in word


def _segment_end(words: list[str], start: int) -> int:
    """Index of the first separator at or after *start* (or the end)."""
    end = start
    while end < len(words) and words[end] not in _SEPARATORS:
        end += 1
    return end


#: ``NAME=VALUE`` at the start of a word: a variable set on the command line.
_ASSIGNMENT = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$", re.DOTALL)


def _with_variables(words: list[str]) -> list[str]:
    """*words* with the variables set earlier on the same line put in where they are used:
    after ``H=$HOME``, ``$H/.ssh/key`` reads as ``$HOME/.ssh/key``. Only names assigned on this
    line are replaced; an assignment word itself is kept as written."""
    values: dict[str, str] = {}
    out: list[str] = []
    for word in words:
        assignment = _ASSIGNMENT.match(word)
        if assignment and "/" not in assignment.group(1):
            values[assignment.group(1)] = assignment.group(2)
            out.append(word)
            continue
        if values and "$" in word:
            word = re.sub(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))",
                          lambda found: values.get(found.group(1) or found.group(2), found.group(0)), word)
        out.append(word)
    return out


def _is_anchored(path: str) -> bool:
    """True for a path that does not depend on the current folder."""
    return path.startswith(("/", "~", "$HOME", "%")) or bool(re.match(r"[A-Za-z]:[\\/]", path))
