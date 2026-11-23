"""The files a shell command writes, read off its words: heredocs, ``echo`` / ``printf`` into a
file and ``… | tee`` — the shell half of :mod:`.` (``detection.script_files``).

Split out of ``script_files.py`` (a move only, 2026-11-23): what a command line WRITES is read
here, what it RUNS in the package entry. Words are read as the shell joins them
(``'Doc''uments'`` is ``Documents``).

Usage::

    _shell_words("printf 'x' > r.py; python3 r.py")   # ['printf', 'x', '>', 'r.py', ';', 'python3', 'r.py']
    _shell_writes("cat > r.py <<'EOF'\nprint(1)\nEOF")  # [('r.py', 'print(1)')]

Pure and deterministic; reads no files.
"""

from __future__ import annotations

import re
import shlex

#: The most of one written content judged.
MAX_CONTENT_CHARS = 64 * 1024
#: A heredoc opener and where its text goes, on one line: ``cat > x.py <<'EOF'``, ``tee x.py <<EOF``.
_HEREDOC_OPEN = re.compile(r"<<-?\s*(['\"]?)(\w+)\1")
_HEREDOC_TARGET = re.compile(r"(?:>>?|\btee\s+(?:-a\s+)?)\s*([^\s<>|;&]+)")
#: The characters a word that ends one simple command is made of (as :func:`_shell_words` splits
#: them: ``;``, ``&&``, ``||``, ``&``, ``|`` and a line end, alone or run together like ``;\n``).
_COMMAND_END_CHARS = frozenset(";&|\n")
#: The escapes ``printf`` and ``echo -e`` turn into characters.
_ESCAPES = {"\\n": "\n", "\\t": "\t", "\\\\": "\\"}


def _shell_words(command: str) -> list[str]:
    """*command* split as the shell splits it: quotes joined (``'Doc''uments'`` → ``Documents``),
    and ``>``, ``>>``, ``|``, ``;``, ``&&`` and a line end outside quotes as words of their own; []
    when it can not be split.

    WHY the line end (security round 4, 2026-11-23): ``detection.command_from_args`` hands every
    check a wrapped command with what it runs added on lines of its own (``bash -lc 'python3 r.py'``
    then ``python3 r.py``). Read as one command, the inner run was never seen as a run — a
    protected file leaked through ``bash -lc``. A newline ends a shell command; here too."""
    lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>\n")
    lexer.whitespace = " \t\r"
    lexer.whitespace_split = True
    try:
        return list(lexer)
    except ValueError:
        return []


def _ends_command(word: str) -> bool:
    """True when *word* (one of :func:`_shell_words`) ends a simple command."""
    return bool(word) and set(word) <= _COMMAND_END_CHARS


def _echoed(words: list[str]) -> str:
    """What ``echo``/``printf`` *words* print (``printf``'s format and ``echo -e`` escapes read)."""
    name, rest = words[0], words[1:]
    escapes = name == "printf"
    while name == "echo" and rest and re.fullmatch(r"-[neE]+", rest[0]):
        escapes = escapes or "e" in rest[0]
        rest = rest[1:]
    text = " ".join(rest)
    return re.sub(r"\\[nt\\]", lambda found: _ESCAPES[found.group(0)], text) if escapes else text


def _printed_into_files(command: str) -> list[tuple[str, str]]:
    """``(file, text)`` for each ``echo``/``printf`` whose output a command sends into a file:
    ``printf '…' > x.sh``, ``echo '…' >> x.py``, ``echo '…' | tee [-a] x.sh``."""
    words = _shell_words(command[:MAX_CONTENT_CHARS * 2])
    out, start = [], 0
    while start < len(words):
        end = next((at for at in range(start, len(words)) if _ends_command(words[at])), len(words))
        segment = words[start:end]
        if segment and segment[0] in ("echo", "printf"):
            redirect = next((at for at, word in enumerate(segment) if word in (">", ">>")), -1)
            if redirect > 0 and redirect + 1 < len(segment):
                out.append((segment[redirect + 1], _echoed(segment[:redirect])))
            elif end < len(words) and words[end].strip("\n") == "|":
                tee_end = next((at for at in range(end + 1, len(words)) if _ends_command(words[at])), len(words))
                tee = words[end + 1:tee_end]
                if tee and tee[0] == "tee":
                    out += [(target, _echoed(segment)) for target in tee[1:] if not target.startswith("-") and target not in (">", ">>")]
        start = end + 1
    return [(path, text[:MAX_CONTENT_CHARS]) for path, text in out]


def _shell_writes(command: str) -> list[tuple[str, str]]:
    out = []
    lines = command.split("\n")
    for index, line in enumerate(lines):
        opener, target = _HEREDOC_OPEN.search(line), _HEREDOC_TARGET.search(_HEREDOC_OPEN.sub(" ", line))
        if opener and target:
            tag = opener.group(2)
            body = []
            for following in lines[index + 1:]:
                if following.strip() == tag:
                    break
                body.append(following)
            out.append((target.group(1).strip("'\""), "\n".join(body)[:MAX_CONTENT_CHARS]))
    return out + _printed_into_files(command)
