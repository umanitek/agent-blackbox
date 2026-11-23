"""Codex's ``apply_patch`` heredoc, read as the patch it is — the files it adds, changes, deletes
or moves — instead of as lines of shell (KI-583).

Codex writes a file by running ``apply_patch <<'PATCH' … PATCH`` (often inside ``bash -lc '…'``).
The body is not run by any shell: it is the patch format (``*** Begin Patch``, ``*** Add File:
<path>``, ``*** Update File: <path>``, ``*** Delete File: <path>``, ``*** Move to: <path>``, then
``+`` / ``-`` / `` `` lines). Read as shell, its ``***`` marker lines were wildcards matching every
guarded place, so EVERY patch — a new ``hello.py`` in the project — was refused as "Change to
Blackbox's own settings" (security round 3, Codex 0.171.0).

:func:`split` hands the guard each patch's target paths and the text it adds to each file, and the
command with only the patch's MARKER lines taken out (``*** …`` headers, ``@@`` hunk lines). The
guard refuses a patch that touches a guarded place, or whose added text is a script that would
itself be refused — the same rules as for a file tool writing that file — and still reads every
other line as shell, as before. WHY keep the content lines: ``apply_patch`` could be a program of
the agent's own that runs its input; a content line that would be refused as a command still is.

Usage::

    rest, patches = split(command)
    for patch in patches:
        patch.paths          # ("r.py", …) as the patch names them
        patch.added          # {"r.py": "import os…"} — the lines the patch adds, per file
        patch.verbs          # {"r.py": "Add File"}
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: ``apply_patch <<'TAG'`` … ``TAG`` — the tag's closing line may carry the quote that ends a ``bash -lc '…'``.
_PATCH_HEREDOC = re.compile(
    r"(?m)^(?P<head>[^\n]*?(?<![\w./-])(?:\S*/)?apply_patch\b[^\n]*?<<-?[ \t]*(?P<quote>['\"]?)(?P<tag>\w+)(?P=quote)[^\n]*)\n"
    r"(?P<body>.*?)\n[ \t]*(?P=tag)(?P<close>['\"]?)[ \t]*$", re.DOTALL)
#: ``apply_patch '*** Begin Patch …'`` — the patch as the program's ARGUMENT (KI-616: Codex 0.171.0's
#: own patch tool reaches the hook as this shell command, quoted, or as its argv joined unquoted) —
#: also on the line AFTER the program, with no quote (KI-645, security round 7's full capture:
#: ``apply_patch\n*** Begin Patch\n…\n*** End Patch``; read as shell its ``***`` lines matched
#: every guarded place, and a package.json description edit was refused as a Blackbox change).
_PATCH_ARGUMENT = re.compile(
    r"(?m)^(?P<head>[^\n]*?(?<![\w./-])(?:\S*/)?apply_patch)(?:[ \t]+|[ \t]*\n)(?P<quote>['\"]?)"
    r"(?P<body>\*\*\* Begin Patch[ \t]*\n.*?\n\*\*\* End Patch)[ \t]*\n?(?P=quote)(?P<close>['\"]?)[ \t]*$", re.DOTALL)
#: The patch format's file headers (Codex's apply_patch grammar).
_FILE_HEADER = re.compile(r"(?m)^\*\*\* (?P<verb>Add File|Update File|Delete File|Move to): (?P<path>[^\n]+?)[ \t]*$")
#: The patch format's own lines that are not file content.
_MARKER = re.compile(r"^(?:\*\*\* (?:Begin Patch|End Patch|End of File|Add File: |Update File: |Delete File: |Move to: ).*|@@.*)$")
#: The most patches read from one command (a model sends one).
MAX_PATCHES = 16


@dataclass(frozen=True)
class Patch:
    """One patch: every path it names (*paths*), what it does to each (*verbs*: ``Add File`` /
    ``Update File`` / ``Delete File`` / ``Move to``), and per added or updated file the text of its
    ``+`` lines (*added*)."""

    paths: tuple[str, ...]
    added: dict[str, str] = field(default_factory=dict)
    verbs: dict[str, str] = field(default_factory=dict)


def _parse(body: str) -> Patch:
    paths: list[str] = []
    added: dict[str, list[str]] = {}
    verbs: dict[str, str] = {}
    current = ""
    for line in body.split("\n"):
        header = _FILE_HEADER.match(line)
        if header:
            current = header.group("path").strip()
            paths.append(current)
            verbs[current] = header.group("verb")
            continue
        if current and line.startswith("+"):
            added.setdefault(current, []).append(line[1:])
    return Patch(tuple(paths), {path: "\n".join(lines) for path, lines in added.items()}, verbs)


def split(command: str) -> tuple[str, list[Patch]]:
    """*command* with each ``apply_patch`` patch's marker lines taken out — a heredoc
    (``apply_patch <<'PATCH' …``) or the program's argument (``apply_patch '*** Begin Patch …'``) —
    and the patches they hold. A command with no patch is returned as is."""
    if "apply_patch" not in command or ("<<" not in command and "*** Begin Patch" not in command):
        return command, []
    patches: list[Patch] = []

    def take(found: re.Match[str]) -> str:
        if len(patches) >= MAX_PATCHES:
            return found.group(0)   # past the cap: left in place, read as shell (refused if it names a place)
        body = found.group("body")
        patches.append(_parse(body))
        content = [line for line in body.split("\n") if not _MARKER.match(line)]
        # The heredoc's closing tag, or the quote that ends a ``bash -lc '…'`` around the argument form.
        tail = [found.group("tag") + found.group("close")] if "tag" in found.re.groupindex else \
            [found.group("close")] if found.group("close") else []
        return "\n".join([found.group("head"), *content, *tail])

    if "<<" in command:
        command = _PATCH_HEREDOC.sub(take, command)
    return _PATCH_ARGUMENT.sub(take, command), patches


__all__ = ["MAX_PATCHES", "Patch", "split"]
