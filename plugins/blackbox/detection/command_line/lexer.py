"""How a shell splits one command line into words — the ONE lexer every shell check reads through.

:mod:`.shell_words` asks it; nothing else should split a command line by hand.

What it does, the way bash does it:

* whitespace separates words; ``'…'`` keeps everything literal; ``"…"`` keeps everything but
  ``\\$``, ``\\```, ``\\"``, ``\\\\`` and a line continuation; a backslash outside quotes takes the next
  character literally;
* ``;`` ``&`` ``|`` ``<`` ``>`` runs are operator words (``&&``, ``>>``, ``2>&1`` → ``2`` ``>&`` ``1``),
  and ``(`` / ``)`` (a subshell, ``(cd ~ && cat x)``) are words of their own;
* ``$(…)``, ``${…}`` and backticks stay whole inside their word, untouched (what they run is read by
  ``detection.hidden_commands``; ``${HOME:-x}`` by :func:`.shell_words.with_variables`);
* ``#`` starts a comment only at the start of a word (``https://x/#top`` is one word);
* brace expansion — ``~/.s{s,}h/id_rsa`` is the two words ``~/.ssh/id_rsa`` ``~/.sh/id_rsa``,
  ``f{1..3}`` three — bounded by :data:`MAX_BRACE_WORDS`; a group past the bound stays as written
  and the line is marked :func:`unresolved` (File Shield's "a hook cannot read this" flag).

Windows paths: a backslash is a separator there, not an escape. That is decided PER WORD — a word
is a Windows path from the backslash after a drive (``C:\\``), a ``%VAR%``, ``~``, ``$HOME``,
``$env:NAME`` or a leading ``.``/``..`` on — so one Windows path never switches quote handling off
for the other words of the line (``echo C:\\x; cat ~/.s"s"h/id_rsa`` reads ``~/.ssh/id_rsa``).

An unbalanced quote (a line the shell itself refuses) falls back to plain whitespace splitting,
so a malformed command still yields its paths.

Pure and deterministic; reads no files. Linear in the line's length.

Usage::

    split_words('cat ~/.s{s,}h/"id_rsa"; ls')   # ('cat', '~/.ssh/id_rsa', '~/.sh/id_rsa', ';', 'ls')
    unresolved("echo {1..99999}")                 # True: past the bound, left as written
"""

from __future__ import annotations

import functools
import itertools
import re

#: The most words one brace-expanded word becomes; a group past it is left as written.
MAX_BRACE_WORDS = 64
#: The characters that make operator words (runs of them are one word, as ``shlex`` groups them).
_OPERATOR_CHARS = frozenset(";&|<>")
_SUBSHELL_CHARS = frozenset("()")
_WHITESPACE = frozenset(" \t\r\n")
#: Brace-expansion marks for an UNQUOTED ``{`` ``,`` ``}`` while a word is built (a quoted or escaped
#: one is a literal character): private-use code points, never typed in a real command.
_OPEN, _COMMA, _CLOSE = "\ue000", "\ue001", "\ue002"
_MARKS = str.maketrans({_OPEN: "{", _COMMA: ",", _CLOSE: "}"})
#: What a word holds just before a backslash that makes it a Windows path (see the module doc).
_WINDOWS_BEFORE = re.compile(r"(?:^|[^A-Za-z0-9])[A-Za-z]:$|%[A-Za-z_][A-Za-z0-9_]*%$|^\.{1,2}$|^~$|^\$HOME$|^\$env:[A-Za-z_]\w*$",
                             re.IGNORECASE)
#: A Windows path inside double quotes (``"C:\\Program Files\\x"``): its backslashes stay as written.
_WINDOWS_INSIDE = re.compile(r"(?:^|[^A-Za-z0-9])[A-Za-z]:\\|%[A-Za-z_][A-Za-z0-9_]*%\\|^(?:\.{1,2}|~)\\")
#: A run of characters that mean nothing special inside a word.
#: How much of the word being built the Windows-path checks read: they look only at its end (a drive
#: letter, ``%VAR%``, ``~`` or ``..`` just before a backslash), so a bounded tail keeps the lexer
#: linear. WHY: re-joining the whole word at every quote or backslash was quadratic — a 900,000
#: character call of nested JSON hung the hook for minutes (CI, 2026-11-27).
_WINDOWS_TAIL = 256
_PLAIN = re.compile(r"[^\s;&|<>()\\'\"$`{},]+")
#: The longest body a ``{1..3}`` / ``{a..c}`` sequence can have (two six-digit signed numbers and ``..``).
_MAX_SEQUENCE_BODY = 16
_SEQUENCE = re.compile(r"^(-?\d{1,6})\.\.(-?\d{1,6})$|^([A-Za-z])\.\.([A-Za-z])$")


class _Unbalanced(ValueError):
    """A quote or a ``$(`` that never closes."""


def _closing(text: str, start: int, open_char: str, close_char: str) -> int:
    """The index just past the *close_char* that balances the *open_char* before *start*; quotes
    inside are skipped as the shell skips them."""
    depth, index, length = 1, start, len(text)
    while index < length:
        char = text[index]
        if char == "\\":
            index += 2
            continue
        if char in "'\"" and open_char != "`":
            end = text.find("'", index + 1) if char == "'" else _double_quote_end(text, index + 1)
            if end < 0:
                raise _Unbalanced(text)
            index = end + 1
            continue
        if char == close_char and (open_char != close_char or depth == 1):
            depth -= 1
            if depth == 0:
                return index + 1
        elif char == open_char:
            depth += 1
        index += 1
    raise _Unbalanced(text)


def _double_quote_end(text: str, start: int) -> int:
    """The index of the ``"`` that closes a double-quoted run starting at *start*, or -1."""
    index, length = start, len(text)
    while index < length:
        char = text[index]
        if char == "\\":
            index += 2
        elif char == '"':
            return index
        elif text.startswith("$(", index) or text.startswith("${", index):
            index = _closing(text, index + 2, text[index + 1], ")" if text[index + 1] == "(" else "}")
        elif char == "`":
            index = _closing(text, index + 1, "`", "`")
        else:
            index += 1
    return -1


class _Lexer:
    """One pass over one line (State: the word being built and whether it is a Windows path)."""

    def __init__(self, text: str) -> None:
        self.text, self.index = text, 0
        self.words: list[str] = []
        self.current: list[str] = []
        self.started = self.windows = self.unresolved = False
        self._reset_word()

    def _reset_word(self) -> None:
        #: The last :data:`_WINDOWS_TAIL` characters of the word (marks made literal), whether the word
        #: is longer than that, and whether a Windows path showed anywhere in it so far.
        self.tail, self.long, self.windows_seen = "", False, False

    def add(self, piece: str) -> None:
        """Append *piece* to the word being built, keeping the bounded tail the Windows checks read."""
        self.current.append(piece)
        joined = self.tail + piece.translate(_MARKS)
        # A Windows path ends in a backslash: only a piece holding one can make a new match.
        if not self.windows_seen and "\\" in piece and _WINDOWS_INSIDE.search(self._anchored(joined)):
            self.windows_seen = True
        self.long = self.long or len(joined) > _WINDOWS_TAIL
        self.tail = joined[-_WINDOWS_TAIL:]

    def _anchored(self, text: str) -> str:
        """*text* as the checks read it. A word cut to its tail does not start where the word does, so
        a letter goes in front: nothing anchors at the cut (``^`` and a non-letter boundary), and the
        place it hides was already read with its real neighbours when it was the end of the word."""
        return "a" + text if self.long else text

    def finish(self) -> None:
        if self.started:
            for word in _expanded("".join(self.current), self):
                self.words.append(word)
        self.current, self.started, self.windows = [], False, False
        self._reset_word()

    def run(self) -> tuple[str, ...]:
        text, length = self.text, len(self.text)
        while self.index < length:
            char = text[self.index]
            if char in _WHITESPACE:
                self.finish()
                self.index += 1
            elif char == "#" and not self.started:
                newline = text.find("\n", self.index)
                self.index = length if newline < 0 else newline
            elif char in _OPERATOR_CHARS or char in _SUBSHELL_CHARS:
                self.finish()
                end = self.index + 1
                while char in _OPERATOR_CHARS and end < length and text[end] in _OPERATOR_CHARS:
                    end += 1
                self.words.append(text[self.index:end])
                self.index = end
            else:
                self.started = True
                self.word_part(char)
        self.finish()
        return tuple(self.words)

    def word_part(self, char: str) -> None:
        text = self.text
        if char == "\\":
            self.backslash()
        elif char == "'":
            end = text.find("'", self.index + 1)
            if end < 0:
                raise _Unbalanced(text)
            self.add(text[self.index + 1:end])
            self.index = end + 1
        elif char == '"':
            self.double_quoted()
        elif text.startswith(("$(", "${"), self.index):
            end = _closing(text, self.index + 2, text[self.index + 1], ")" if text[self.index + 1] == "(" else "}")
            self.add(text[self.index:end])
            self.index = end
        elif char == "`":
            end = _closing(text, self.index + 1, "`", "`")
            self.add(text[self.index:end])
            self.index = end
        else:
            plain = _PLAIN.match(text, self.index)
            if plain:
                self.add(plain.group(0))
                self.index = plain.end()
            else:
                self.add({"{": _OPEN, ",": _COMMA, "}": _CLOSE}.get(char, char))
                self.index += 1

    def backslash(self) -> None:
        text, at = self.text, self.index
        if self.windows or _WINDOWS_BEFORE.search(self._anchored(self.tail)):
            self.windows = True
            self.add("\\")
            self.index = at + 1
        elif at + 1 < len(text):
            if text[at + 1] != "\n":   # a line continuation joins the lines
                self.add(text[at + 1])
            self.index = at + 2
        else:
            self.index = at + 1

    def double_quoted(self) -> None:
        text = self.text
        end = _double_quote_end(text, self.index + 1)
        if end < 0:
            raise _Unbalanced(text)
        inner = text[self.index + 1:end]
        if self.windows_seen or ("\\" in inner and _WINDOWS_INSIDE.search(self._anchored(self.tail) + inner)):
            self.windows = True
        if not self.windows:
            inner = re.sub(r'\\([$`"\\\n])', lambda found: "" if found.group(1) == "\n" else found.group(1), inner)
        self.add(inner)
        self.index = end + 1


def _expanded(word: str, lexer: _Lexer) -> list[str]:
    """*word* (with brace marks) as the words brace expansion makes of it, marks made literal."""
    if _OPEN not in word:
        return [word.translate(_MARKS)]
    found = _alternatives(word)
    if found is None:
        lexer.unresolved = True
        return [word.translate(_MARKS)]
    return [each.translate(_MARKS) for each in found]


def _groups(word: str) -> dict[int, tuple[int, list[int]]]:
    """Every ``{`` mark of *word* that is closed: its index -> (the closing ``}`` mark's index, its
    top-level commas). One pass with a stack. WHY: scanning to the end of the word for each ``{`` was
    quadratic — 150,000 nested braces hung the hook (CI, 2026-11-27)."""
    found: dict[int, tuple[int, list[int]]] = {}
    open_marks: list[tuple[int, list[int]]] = []
    for index, char in enumerate(word):
        if char == _OPEN:
            open_marks.append((index, []))
        elif char == _COMMA and open_marks:
            open_marks[-1][1].append(index)
        elif char == _CLOSE and open_marks:
            start, commas = open_marks.pop()
            found[start] = (index, commas)
    return found


def _sequence(body: str) -> list[str] | None:
    """``1..3`` / ``a..c`` as its items (at most one past :data:`MAX_BRACE_WORDS`, so a longer one
    is seen as too long), None when *body* is no sequence."""
    found = _SEQUENCE.match(body)
    if not found:
        return None
    numbers = found.group(1) is not None
    first, last = (int(found.group(1)), int(found.group(2))) if numbers else (ord(found.group(3)), ord(found.group(4)))
    step = 1 if last >= first else -1
    values = itertools.islice(range(first, last + step, step), MAX_BRACE_WORDS + 1)
    return [str(value) if numbers else chr(value) for value in values]


def _alternatives(word: str) -> list[str] | None:
    """Every word *word*'s brace groups make, at most :data:`MAX_BRACE_WORDS` (None past it)."""
    groups = _groups(word)
    start = word.find(_OPEN)
    while start >= 0:
        if start not in groups:   # no ``}`` closes it: the rest is literal
            return [word]
        end, commas = groups[start]
        if commas:
            cuts = [start, *commas, end]
            choices = [word[cuts[at] + 1:cuts[at + 1]] for at in range(len(cuts) - 1)]
        else:
            body = word[start + 1:end] if end - start - 1 <= _MAX_SEQUENCE_BODY else ""
            choices = _sequence(body.translate(_MARKS)) if body and _OPEN not in body else None
        if choices is not None:
            out: list[str] = []
            prefix, suffix = word[:start], word[end + 1:]
            for choice in choices:
                rest = _alternatives(choice + suffix)
                if rest is None or len(out) + len(rest) > MAX_BRACE_WORDS:
                    return None
                out += [prefix + each for each in rest]
            return out
        start = word.find(_OPEN, start + 1)   # ``{}`` or ``{x}``: a literal brace; look further on
    return [word]


@functools.lru_cache(maxsize=8)
def _lexed(command: str) -> tuple[tuple[str, ...], bool]:
    lexer = _Lexer(command)
    try:
        return lexer.run(), lexer.unresolved
    except _Unbalanced:   # an unbalanced quote: still find the paths
        return tuple(command.split()), False


def split_words(command: str) -> tuple[str, ...]:
    """The shell words of *command* (see the module doc). The last few lines are remembered:
    several checks split the same command of one call."""
    return _lexed(command)[0]


def unresolved(command: str) -> bool:
    """True when *command* holds a brace group too large to expand (left as written)."""
    return _lexed(command)[1]


__all__ = ["MAX_BRACE_WORDS", "split_words", "unresolved"]
