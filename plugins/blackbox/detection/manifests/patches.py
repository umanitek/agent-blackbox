"""A dependency file as Codex's ``apply_patch`` will leave it — so a patch is judged like an edit (KI-602).

Codex changes files with its patch format (``*** Begin Patch``, ``*** Add File: <path>`` /
``*** Update File: <path>``, then ``@@`` hunks of `` ``/``-``/``+`` lines), as its own
``apply_patch`` tool or as ``apply_patch <<'PATCH' …`` run in a shell. The manifest write check
(:func:`.checks.check_dependency_write`) judges what a write ADDS to the file it will produce:
:func:`patched_text` produces it — an added file's ``+`` lines, an updated file with each hunk
applied to its current text in order. A hunk whose old lines are not in the file can not be
applied: None, so nothing is claimed (Codex itself refuses such a patch).

Usage::

    patched_paths(patch)                       # ["package.json", …] the files it adds or updates
    patched_text(patch, "package.json", text)  # the file after the patch, or None
"""

from __future__ import annotations

import re
from typing import Optional

_HEADER = re.compile(r"^\*\*\* (?P<verb>Add File|Update File|Delete File): (?P<path>.+?)[ \t]*$")
#: Lines of the format that are neither a header nor file content.
_END = ("*** End Patch", "*** End of File", "*** Move to: ")
#: The most files of one patch read.
MAX_FILES = 50


def patched_paths(patch: str) -> list[str]:
    """Every file *patch* adds or updates, as it names them (relative to the agent's folder)."""
    out = [found.group("path") for line in patch.split("\n")
           if (found := _HEADER.match(line)) and found.group("verb") != "Delete File"]
    return list(dict.fromkeys(out))[:MAX_FILES]


def _section(patch: str, path: str) -> tuple[str, list[str]]:
    """``(verb, lines)`` of *path*'s part of *patch* ("" when the patch does not name it)."""
    verb, lines, inside = "", [], False
    for line in patch.split("\n"):
        header = _HEADER.match(line)
        if header:
            if inside:
                break
            inside = header.group("path") == path
            verb = header.group("verb") if inside else verb
            continue
        if inside:
            if line.startswith("*** End Patch"):
                break
            lines.append(line)
    return verb, lines


def _hunks(lines: list[str]) -> list[tuple[list[str], list[str]]]:
    """Each hunk's ``(old lines, new lines)``: context and ``-`` lines were there, context and ``+`` will be."""
    hunks: list[tuple[list[str], list[str]]] = []
    old: list[str] = []
    new: list[str] = []
    for line in lines:
        if line.startswith("@@"):
            if old or new:
                hunks.append((old, new))
            old, new = [], []
        elif line.startswith(_END):
            continue
        elif line.startswith("-"):
            old.append(line[1:])
        elif line.startswith("+"):
            new.append(line[1:])
        else:   # context: a leading space (or an empty line some models send)
            context = line.removeprefix(" ")
            old.append(context)
            new.append(context)
    if old or new:
        hunks.append((old, new))
    return hunks


def patched_text(patch: str, path: str, current: Optional[str]) -> Optional[str]:
    """The text *path* will hold after *patch* (*current*: its text now, None when absent), or None
    when the patch does not add or update it or a hunk can not be applied."""
    verb, lines = _section(patch, path)
    if verb == "Add File":
        return "\n".join(line[1:] for line in lines if line.startswith("+"))
    if verb != "Update File" or current is None:
        return None
    text = current
    for old, new in _hunks(lines):
        before, after = "\n".join(old), "\n".join(new)
        if not before or before not in text:
            return None
        text = text.replace(before, after, 1)
    return text


__all__ = ["MAX_FILES", "patched_paths", "patched_text"]
