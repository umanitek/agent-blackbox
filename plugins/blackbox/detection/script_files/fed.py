"""The scripts a command FEEDS its runner instead of naming a file it opens — read off its words.

Private security finding ``2026-11-23-round-7-hooks-only-bypasses-remain-stdin`` (security round 7,
High): a hooks-only agent ran ``python3 - Doc Sec <<'EOF' <script> EOF`` and
``cat /tmp/x.py | python3 - Doc Sec``; the script built ``~/Documents/Secret/…`` from its arguments
and the protected file was read. A script file a command runs was judged by its text since round 5,
but a script on stdin was not a "script file", so nothing read it. Each form below is now handed to
the one script judgement (``script_files.judge_runs``) as the run it is, with its arguments:

* a heredoc: ``python3 - a b <<'EOF' … EOF`` (``node -``, ``ruby``, ``perl``, ``bash -s``…);
* a here-string: ``python3 - <<< "…"``;
* a file on stdin: ``python3 - < x.py``, ``bash -s arg < job.sh``, ``node - < c.js``;
* a pipe from ``cat FILE`` (or ``cat <<EOF``), ``echo`` or ``printf``: ``cat x.py | python3 -``;
* inline code read from a file: ``python3 -c "$(cat k.py)" a b``, ``bash -c "$(< job.sh)"``.

A runner reads stdin as its script when it is given ``-`` (or a shell ``-s``), or no script file at
all. A feed from anything else (``curl … | sh``, a variable) can not be read here; the escalation
shapes flag the remote pipe, and only the OS sandbox stops the rest.

Usage::

    fed_scripts("cat k.py | python3 - ssh authorized x")
    # -> [Fed(runner="python3", argv=("ssh", "authorized", "x"), text=None, file="k.py")]

Pure and deterministic; reads no files (the package entry reads :attr:`Fed.file`).
"""

from __future__ import annotations

import os
import re
from typing import NamedTuple, Optional

from .shell_writes import MAX_CONTENT_CHARS, _echoed, _shell_words


class Fed(NamedTuple):
    """One script fed to *runner* with *argv*: its *text* when the command line holds it (a heredoc,
    a here-string, an ``echo``), else the *file* it comes from (as written; "" when not known)."""

    runner: str
    argv: tuple[str, ...]
    text: Optional[str]
    file: str = ""


#: Programs that read a script from stdin.
STDIN_RUNNERS = frozenset({"python", "python3", "python2", "py", "pypy", "pypy3", "node", "nodejs", "bun", "ruby", "perl",
                           "php", "sh", "bash", "zsh", "dash", "ksh"})
_SHELLS = frozenset({"sh", "bash", "zsh", "dash", "ksh"})
#: Options that hand the runner inline code (the next word).
_INLINE = frozenset({"-c", "-e", "-E", "-r", "--eval"})
_INLINE_CLUSTER = re.compile(r"-[A-Za-z]*c")
#: Inline code that is a file's text: ``$(cat k.py)``, ``$(< k.py)``, `` `cat k.py` ``.
_FROM_FILE = re.compile(r"^\s*(?:\$\(\s*(?:cat\s+|<\s*)(?P<a>[^\s()]+)\s*\)|`\s*cat\s+(?P<b>[^\s`]+)\s*`)\s*$")
#: A heredoc opener (``<<'EOF'``, ``<<-EOF``) — never a here-string's ``<<<``.
_HEREDOC = re.compile(r"(?<!<)<<-?(?!<)\s*(['\"]?)(\w+)\1")
#: Words that send output elsewhere, with their target after them.
_OUTPUT = re.compile(r"\d?>{1,2}|&>{1,2}|\d?>&\d?")
#: Wrappers before the runner that change nothing about what it reads.
_PASS_THROUGH = frozenset({"env", "exec", "command", "nohup", "time", "nice"})
#: The most lines one command is read for heredocs, and the most lines one quoted word (a
#: here-string's script) may span.
MAX_LINES = 2000
MAX_JOINED_LINES = 200


def _bodies(command: str) -> list[tuple[str, Optional[str]]]:
    """``(line, heredoc body)`` for each line of *command* that is not inside a heredoc's body: the
    body of the first heredoc that line opens, else None.

    WHY an empty body takes the last full one of the same tag: ``detection.command_from_args``
    hands ``bash -lc "python3 - <<'EOF' … EOF"`` on with the inner command on a line of its own,
    where the heredoc's body is cut off; the outer line (inside quotes, never split into words
    here) holds it."""
    lines = command.split("\n")[:MAX_LINES]
    out, at, last = [], 0, {}
    while at < len(lines):
        line, body = lines[at], None
        opener = _HEREDOC.search(line)
        at += 1
        if opener:
            start = at
            # WHY the quote: inside ``bash -lc "… <<'EOF' … EOF"`` the closing line is ``EOF"``.
            while at < len(lines) and lines[at].strip().rstrip("'\"") != opener.group(2):
                at += 1
            body = "\n".join(lines[start:at])[:MAX_CONTENT_CHARS] or last.get(opener.group(2), "")
            last[opener.group(2)] = body
            at += 1
        out.append((line, body))
    return out


def _stages(words: list[str]) -> list[list[list[str]]]:
    """*words* (one line's) as its pipelines, each a list of stages (the words between ``|``)."""
    pipelines: list[list[list[str]]] = [[[]]]
    for word in words:
        if word.strip("\n") == "|":
            pipelines[-1].append([])
        elif word and set(word) <= set(";&|\n"):
            pipelines.append([[]])
        else:
            pipelines[-1][-1].append(word)
    return [[stage for stage in pipeline] for pipeline in pipelines if any(pipeline)]


def _program(stage: list[str]) -> tuple[str, list[str]]:
    """The program a stage runs (its name) and the words after it, past ``NAME=value`` words and
    pass-through wrappers."""
    at = 0
    while at < len(stage) and (re.match(r"^[A-Za-z_][A-Za-z0-9_]*=", stage[at]) or os.path.basename(stage[at]) in _PASS_THROUGH):
        at += 1
    return (os.path.basename(stage[at]), stage[at + 1:]) if at < len(stage) else ("", [])


def _piped_in(stage: list[str], body: Optional[str]) -> Optional[Fed]:
    """What the stage before a runner sends it: a file ``cat`` reads, a heredoc ``cat`` reads, or
    what ``echo`` / ``printf`` print (as a Fed with no runner yet); None for anything else."""
    name, rest = _program(stage)
    if name == "cat":
        if "<<" in rest and body is not None:
            return Fed("", (), body)
        files = [word for word in rest if not word.startswith("-") and not _OUTPUT.fullmatch(word)]
        return Fed("", (), None, files[0]) if len(files) == 1 else None
    if name in ("echo", "printf"):
        return Fed("", (), _echoed([name, *rest])[:MAX_CONTENT_CHARS])
    return None


def _fed(stage: list[str], before: Optional[list[str]], body: Optional[str]) -> Optional[Fed]:
    """The script a runner stage is fed (*before*: the stage piped into it, None when none)."""
    name, rest = _program(stage)
    if name not in STDIN_RUNNERS:
        return None
    argv: list[str] = []
    source: Optional[Fed] = None
    script_started, at = False, 0
    while at < len(rest):
        word = rest[at]
        if word in ("<", "<<", "<<<") and at + 1 < len(rest):
            target = rest[at + 1]
            source = Fed("", (), None, target) if word == "<" else Fed("", (), body if word == "<<" else target[:MAX_CONTENT_CHARS])
            at += 2
            continue
        if _OUTPUT.fullmatch(word):
            at += 2
            continue
        if script_started:
            argv.append(word)
        elif word in _INLINE or _INLINE_CLUSTER.fullmatch(word):
            code = _FROM_FILE.match(rest[at + 1]) if at + 1 < len(rest) else None
            if not code:
                return None   # inline code itself: read on its own line (``detection.command_from_args``)
            after = [each for each in rest[at + 2:] if not _OUTPUT.fullmatch(each) and each not in ("<", "<<", "<<<")]
            return Fed(name, tuple(after[:40]), None, code.group("a") or code.group("b"))
        elif word == "-" or (word == "-s" and name in _SHELLS):
            script_started = True
        elif not word.startswith("-"):
            return None   # a script file by its name: ``script_files`` reads it
        at += 1
    if source is None and before is not None:
        source = _piped_in(before, body)
    if source is None or (source.text is None and not source.file):
        return None
    return Fed(name, tuple(argv[:40]), source.text, source.file)


def _logical_lines(command: str) -> list[tuple[list[str], Optional[str]]]:
    """``(words, heredoc body)`` for each command line of *command*: a line whose quotes close only
    on a later line (a here-string's script) joined with those lines; a line whose quotes never
    close (the outer line of ``bash -lc "…"``, whose inner command is read on its own line) skipped."""
    lines = _bodies(command)
    out, at = [], 0
    while at < len(lines):
        text, body = lines[at]
        words, end = _shell_words(text), at + 1
        while text.strip() and not words and end < min(len(lines), at + MAX_JOINED_LINES):
            text, end = text + "\n" + lines[end][0], end + 1
            words = _shell_words(text)
        if words:
            out.append((words, body))
            at = end
        else:
            at += 1
    return out


def fed_scripts(command: str) -> list[Fed]:
    """Every script *command* feeds a runner on stdin or as a file's text (see the module doc)."""
    out: list[Fed] = []
    for words, body in _logical_lines(command):
        for pipeline in _stages(words):
            for index, stage in enumerate(pipeline):
                fed = _fed(stage, pipeline[index - 1] if index else None, body)
                if fed is not None:
                    out.append(fed)
    return out


__all__ = ["STDIN_RUNNERS", "Fed", "fed_scripts"]
