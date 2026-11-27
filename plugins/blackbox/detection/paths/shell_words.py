"""A shell command line as words, and one path among them — the base the shell file view stands on.

Split out of :mod:`.shell_files` (2026-11-20, a move only) when that file passed the size alarm:
this part knows how a command line is SPLIT and how a path is WRITTEN; ``shell_files`` knows which
commands read which of their words, and :mod:`.shell_scripts` reads paths out of script code.

* :class:`ShellFileArg` — one path a command touches (as written, the home folder spelled ``~``).
* :func:`words` (``_words``) — the words of a command, split by the ONE lexer (:mod:`..command_line.lexer`:
  quotes and escapes respected, a Windows path judged per word, ``(``/``)`` words of their own,
  brace expansion).
* :func:`with_variables` — variables set earlier on the line put in where they are used, and
  ``${NAME:-default}`` read as the shell reads it.
* :func:`segments` — the simple commands of a list of words.
* :func:`home_as_tilde`, :func:`is_anchored`, :data:`SEPARATORS` (the public surface), ``_looks_like_path``, ``_segment_end``;
  the underscore names of the public ones stay for the callers that already use them.

Pure and deterministic; reads no files.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..command_line.lexer import split_words

#: The words that end one simple command: the list operators, pipes, redirects and a subshell's brackets.
SEPARATORS = _SEPARATORS = frozenset({";", "&&", "||", "|", "&", ">", ">>", "<", "|&", "(", ")"})


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
#: ``${HOME:-x}`` / ``${HOME-x}`` / ``${HOME:=x}`` / ``${HOME:?}`` are the home folder too (it is always set);
#: PowerShell names it ``$env:USERPROFILE`` / ``$env:HOME``.
_HOME_VARIABLE = re.compile(r"^(?:\$HOME(?![A-Za-z0-9_])|\$\{HOME(?::?[-=?][^}]*)?\}|%USERPROFILE%|(?i:\$env:(?:USERPROFILE|HOME))(?![A-Za-z0-9_]))")
#: Linux's ``/proc`` spellings of the root folder: a process's ``root`` link (``/proc/self/root``,
#: ``/proc/thread-self/root``, ``/proc/<pid>/root``, a thread's ``/proc/<pid>/task/<tid>/root``), as
#: often as it is repeated. Private security finding ``2026-11-24-linux-proc-self-root-home-reads-the-prot``
#: (Linux round L1, High): REAL Claude Code read ``cat /proc/self/root$HOME/Documents/Secret/…``.
_PROC_ROOT = re.compile(r"^(?:/+proc/+(?:self|thread-self|\d+)(?:/+task/+\d+)?/+root(?=/|\$|$))+")
#: The acting process's own working folder through ``/proc`` (``/proc/self/cwd/x``): the folder the
#: command runs in, which every caller joins a relative word onto. Another process's (``/proc/<pid>/cwd``)
#: and the descriptor links (``/proc/<pid>/fd/N``, ``/dev/fd/N``) are links on the machine that the
#: path checks follow where they exist (``protected._candidates``); a descriptor of the agent's own
#: shell is opened by a redirect on the same line, which is read as the read it is.
_PROC_CWD = re.compile(r"^/+proc/+(?:self|thread-self)(?:/+task/+\d+)?/+cwd(?:/+|$)")


def home_as_tilde(path: str) -> str:
    """*path* in the ONE spelling every path check reads: Linux's ``/proc`` aliases of the root
    folder taken away (``/proc/self/root/home/me/x`` is ``/home/me/x``), the acting process's own
    ``/proc/self/cwd/`` read as its working folder (a relative path), and a leading home-folder
    variable written as ``~`` (see the module doc)."""
    path = _PROC_ROOT.sub("", path, count=1) or ("/" if _PROC_ROOT.match(path) else path)
    path = _PROC_CWD.sub("", path, count=1) or ("." if _PROC_CWD.match(path) else path)
    return _HOME_VARIABLE.sub("~", path, count=1)


_home_as_tilde = home_as_tilde


def words(command: str) -> list[str]:
    """The shell words of *command* (a fresh list; see :mod:`..command_line.lexer`). Several checks split
    the same command of one call, so the last few splits are remembered."""
    return list(split_words(command))


_words = words
_split = split_words


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


#: A variable where it is used: ``$NAME``, ``${NAME}``, or ``${NAME<op>WORD}`` with a default
#: (``:-`` ``-``), an assignment (``:=`` ``=``) or a check (``:?`` ``?``).
_PARAMETER = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-=?])([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)")


def with_variables(words: list[str]) -> list[str]:
    """*words* with the variables set earlier on the same line put in where they are used:
    after ``H=$HOME``, ``$H/.ssh/key`` reads as ``$HOME/.ssh/key``. ``${HOME<op>…}`` is ``$HOME`` (it is
    always set), and a variable not set on the line that carries a default (``${NOPE:-~}``) reads as
    its default — what the shell gives for an unset one. Any other variable is kept as written; an
    assignment word itself too."""
    values: dict[str, str] = {}

    def value(found: re.Match) -> str:
        name, operator, default = found.group(1) or found.group(4), found.group(2), found.group(3)
        if name in values:
            return values[name]
        if name == "HOME":
            return "$HOME"
        return default if operator and operator.lstrip(":") in ("-", "=") else found.group(0)

    out: list[str] = []
    for word in words:
        assignment = _ASSIGNMENT.match(word)
        if assignment:
            values[assignment.group(1)] = assignment.group(2)
            out.append(word)
            continue
        out.append(_PARAMETER.sub(value, word) if "$" in word else word)
    return out


_with_variables = with_variables


def segments(words: list[str]) -> list[list[str]]:
    """The simple commands in *words*: the words between two :data:`SEPARATORS`, empty ones left out."""
    found, current = [], []
    for word in words:
        if word in SEPARATORS:
            found.append(current)
            current = []
        else:
            current.append(word)
    return [segment for segment in found + [current] if segment]


def is_anchored(path: str) -> bool:
    """True for a path that does not depend on the current folder."""
    return path.startswith(("/", "~", "$HOME", "%")) or bool(re.match(r"[A-Za-z]:[\\/]", path))


_is_anchored = is_anchored
