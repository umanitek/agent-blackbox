"""The OS sandbox's refusals as an agent sees them, read from a tool's output (KI-590).

Inside Blackbox's agent sandbox the kernel refuses some things outright, and the agent sees only
a bare error: ``operation not permitted: sudo`` (exit 127), LaunchServices'
``_LSOpenURLsWithCompletionHandler() failed … error -54``, ``kill 8240 failed: operation not
permitted``, ``sandbox-exec: sandbox_apply: Operation not permitted``. Nothing in them says
Blackbox refused it, so an agent could not tell "the sandbox stopped this" from "this is broken"
(sandbox developer day, 2026-11-22: unsure about ``open``, puzzled by exit 127). The system
protection helper's deny-log watch reports only refusals that name a protected path, so these
were never counted either.

:func:`refusals` reads a sandboxed tool call's output for those errors, and :func:`note` says each
in one line: "Blackbox's sandbox refused this (<what>): <why and what to do>". The hook post-call
passes that line to the agent (beside the output, where the agent's hook allows) and records the
call as refused on its instance, with the line as the reason. A file the sandbox kept closed is
explained but not counted here: the helper's deny-log watch counts it with its exact path.

It reads text only, and only for a session the hook has proven to be inside the sandbox (the
canary), so an output that merely quotes such an error elsewhere is not taken for one.

Usage::

    found = refusals("(eval):1: operation not permitted: sudo")
    note(found)   # "Blackbox's sandbox refused this (sudo, a setuid program): macOS doesn't allow …"
    counted(found)  # True: not a file refusal
"""

from __future__ import annotations

import os
import re
import shutil
import stat
from dataclasses import dataclass

#: The kinds of refusal; only :data:`FILE` is left for the helper's deny-log watch to count.
SETUID, APP_DRIVER, OPEN_APP, SIGNAL, NESTED, FILE = "setuid", "app-driver", "open-app", "signal", "nested", "file"
#: Programs that drive other apps: refused inside (the app they drive would act outside it).
APP_DRIVERS = frozenset({"osascript", "automator", "shortcuts"})
SETUID_NOTE = "macOS doesn't allow setuid programs inside the agent sandbox; run it in your own terminal"
_WHY = {
    SETUID: SETUID_NOTE,
    APP_DRIVER: "a program that drives another app would act outside the sandbox; do that step in your own terminal",
    OPEN_APP: "opening another app would run it outside the sandbox; open it yourself",
    SIGNAL: "an agent may stop only the programs it started itself, never one outside its sandbox",
    NESTED: ("a tool that starts its own sandbox (Homebrew, for one) can not run inside Blackbox's; "
             "run it in your own terminal"),
    FILE: "this file is kept closed to agents (a protected item, or a file that keeps Blackbox's hook)",
}
_WHAT = {SETUID: "{name}, a setuid program", APP_DRIVER: "{name}", OPEN_APP: "open", SIGNAL: "kill",
         NESTED: "a second sandbox", FILE: "{name}"}
#: zsh: ``(eval):1: operation not permitted: sudo``; bash: ``bash: /usr/bin/sudo: Operation not
#: permitted``; sandbox-exec itself: ``execvp() of '/bin/ps' failed: Operation not permitted``.
_EXEC = re.compile(r"operation not permitted: (?P<z>\S+)\s*$|(?:^|\s)(?P<b>/\S+): operation not permitted"
                   r"|execvp\(\) of '(?P<x>[^']+)' failed: operation not permitted", re.IGNORECASE | re.MULTILINE)
_OPEN = re.compile(r"LSOpenURLs\w*\(\) failed.*?error -54|LSOpenURLsWithRole\(\) failed with error -54", re.IGNORECASE)
_SIGNAL = re.compile(r"kill(?::\d+:)? kill \d+ failed: operation not permitted|kill: \(\d+\) - operation not permitted", re.IGNORECASE)
_NESTED = re.compile(r"sandbox_apply: operation not permitted", re.IGNORECASE)
#: The most refusals one output is read for, and the most characters read.
MAX_FOUND = 8
MAX_READ_CHARS = 64 * 1024


@dataclass(frozen=True)
class Refusal:
    """One refusal: its *kind* (:data:`SETUID` …) and *name*, the program or file it named."""

    kind: str
    name: str = ""

    def line(self) -> str:
        """``<what>): <why>`` — the part of the note after "refused this (". """
        return f"{_WHAT[self.kind].format(name=self.name)}): {_WHY[self.kind]}"


def _privileged(program: str) -> bool:
    found = program if os.path.isabs(program) else shutil.which(program, path="/usr/bin:/bin:/usr/sbin:/sbin")
    try:
        return bool(found) and bool(os.stat(found).st_mode & (stat.S_ISUID | stat.S_ISGID))
    except OSError:
        return False


def _exec_kind(word: str) -> Refusal:
    """A program the kernel would not start, or a file it would not open (zsh words both alike)."""
    name = os.path.basename(word.rstrip(":"))
    if name in APP_DRIVERS:
        return Refusal(APP_DRIVER, name)
    if _privileged(word):
        return Refusal(SETUID, name)
    return Refusal(FILE, word)


def refusals(output: str) -> list[Refusal]:
    """The sandbox refusals a tool's *output* shows, each once, at most :data:`MAX_FOUND`."""
    text = (output or "")[:MAX_READ_CHARS]
    found: list[Refusal] = []
    if _SIGNAL.search(text):
        found.append(Refusal(SIGNAL))
    if _OPEN.search(text):
        found.append(Refusal(OPEN_APP))
    if _NESTED.search(text):
        found.append(Refusal(NESTED))
    for match in _EXEC.finditer(text):
        word = match.group("z") or match.group("b") or match.group("x") or ""
        if word:
            found.append(_exec_kind(word))
    return list(dict.fromkeys(found))[:MAX_FOUND]


def counted(found: list[Refusal]) -> bool:
    """True when *found* holds a refusal the post-call counts (every kind but a file's)."""
    return any(each.kind != FILE for each in found)


def note(found: list[Refusal]) -> str:
    """One line per refusal, "Blackbox's sandbox refused this (<what>): <why>." — "" for none."""
    return " ".join(f"Blackbox's sandbox refused this ({each.line()})." for each in found)
