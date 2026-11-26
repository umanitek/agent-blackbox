"""Where a copy, move, link or unpacked archive LANDS — so a write into the home folder is not
taken for a write onto Blackbox (Blackbox's protection).

The home folder holds Blackbox (``~/.hermes/…``), so ``~`` "reaches" a guarded place
(:func:`.guard_places.reaches` answers True for a folder that holds one). Judging a copy by its
destination word alone therefore refused ``cp notes.md ~`` — which writes ``~/notes.md`` and
nothing of Blackbox's. Here the destination is judged by what actually lands in it:

* the destination IS a guarded place, lies inside one, or is not an existing folder (the copy
  would replace the word itself) → judged as written;
* the destination is a folder that HOLDS guarded places → each thing that lands in it is judged:
  ``<folder>/<name of each source>``, or — for a copy of a folder's CONTENTS (``rsync src/ dst``,
  ``cp -R src/. dst``, ``ditto src dst``) — ``<folder>/<each entry of src>``, read from the disk
  (bounded). A landing name that is or holds a guarded place is refused (a folder named
  ``.hermes`` merges into Blackbox's).
* what lands cannot be known (a variable, a source folder that cannot be listed or has too many
  entries) → refused: when the target holds Blackbox, unknown is not safe.

**Unpacking an archive** (``tar -x``, ``unzip``) into a folder that holds guarded places is refused
unless the command names the members it extracts (``tar -C ~ -xf a.tar notes/todo.md``), which are
then judged like copied names. DECISION (2026-11-21): the guard does NOT open the archive to list
its members. It runs on every tool call, offline and in microseconds; an archive can be any size
and compressed, can arrive on stdin (``curl … | tar -xz -C ~``), and can be swapped between the
check and the run. So a whole-archive unpack into such a folder is refused; unpack into a
project folder (``tar -C ~/projects -xf a.tar``) never reaches this check.

Moves and links also reach their SOURCE: moving a guarded place away (``mv ~/.hermes/config.yaml
/tmp``) changes it, and a link to one is a second name for it (KI-472) — both refused.

Usage::

    copy_writes_a_place("cp", ["cp", "notes.md", "~"], "~")                    # False: ~/notes.md
    copy_writes_a_place("cp", ["cp", "x", "~/.hermes/plugins/blackbox/"], "~") # True
    unpack_writes_a_place("tar", ["-C", "~", "-xf", "a.tar"], "~")             # True: members unknown
"""

from __future__ import annotations

import glob
import os
from typing import Optional

from . import guard_places, shell_files

#: Commands whose destination is a folder things are dropped into.
LANDING_COPIES = frozenset({"cp", "rsync", "scp", "ditto", "mv", "ln"})
#: Of those, the ones that also change their source (a move takes it away; a link aliases it).
_CHANGES_SOURCE = frozenset({"mv", "ln"})
#: Archive extractors judged by :func:`unpack_writes_a_place`.
UNPACKERS = frozenset({"tar", "bsdtar", "gtar", "unzip"})
#: At most this many entries of a source folder are read to learn what a contents-copy lands; more
#: is treated as unknown (refused) rather than read on the hot path.
MAX_LISTED = 2000


def _joined(word: str, folder: str) -> str:
    """*word* as a path, joined onto *folder* when relative (the same rule :mod:`.guard_paths` uses)."""
    from .guard_paths import _place   # one joining rule for every check (no cycle: guard_paths imports lazily)
    return _place(word, folder)


def _on_disk(word: str) -> str:
    """*word* as an absolute path on this machine (``~``/``$HOME`` expanded), or "" when it is not one."""
    path = os.path.expanduser(os.path.expandvars(shell_files._home_as_tilde(str(word or "").strip())))
    return os.path.normpath(path) if os.path.isabs(path) else ""


def _copies_contents(name: str, source: str) -> bool:
    """True when *name* copies the CONTENTS of *source* rather than *source* itself."""
    if name == "ditto":
        return True                                     # ditto src dst: src's contents go into dst
    return source.endswith("/") or source.endswith("/.")   # rsync src/ dst · cp -R src/ dst · cp -R src/. dst


def _landing_names(name: str, source: str, folder: str) -> Optional[list[str]]:
    """The names *source* lands under in the destination folder, or None when they cannot be known."""
    path = _joined(source, folder)
    if "$" in path or "`" in path:
        return None
    if any(char in path for char in "*?["):              # a wildcard the shell expands
        found = _on_disk(path)
        if not found:
            return None
        matches = [match for _, match in zip(range(MAX_LISTED + 1), glob.iglob(found))]
        return None if len(matches) > MAX_LISTED else [os.path.basename(match) for match in matches]
    if _copies_contents(name, source):
        found = _on_disk(path)
        if not found or not os.path.isdir(found):
            return None if name != "ditto" else [os.path.basename(found.rstrip("/"))] if found else None
        try:
            with os.scandir(found) as entries:
                names = [entry.name for _, entry in zip(range(MAX_LISTED + 1), entries)]
        except OSError:
            return None
        return None if len(names) > MAX_LISTED else names
    base = os.path.basename(path.rstrip("/").removesuffix("/."))
    return [base] if base not in ("", ".", "..", "~") else None


def _lands_on_a_place(destination: str, names: list[Optional[list[str]]]) -> bool:
    """True when dropping things named *names* into *destination* writes a guarded place."""
    if not guard_places.reaches(destination):
        return False
    on_disk = _on_disk(destination)
    if guard_places.inside(destination) or not (on_disk and os.path.isdir(on_disk)):
        return True                     # the destination itself is Blackbox's, or would be replaced
    for landing in names:
        if landing is None:
            return True                 # what lands in a folder that holds Blackbox is not known
        if any(guard_places.reaches(destination.rstrip("/") + "/" + entry) for entry in landing):
            return True
    return False


def copy_writes_a_place(name: str, segment: list[str], folder: str) -> bool:
    """True when one copy/move/link command (*segment*, run in *folder*) writes a guarded place."""
    args = shell_files.shell_file_args(" ".join(segment))
    sources = [arg.path for arg in args if not arg.destination]
    if name in _CHANGES_SOURCE and any(guard_places.reaches(_joined(source, folder)) for source in sources):
        return True
    names = [_landing_names(name, source, folder) for source in sources]
    return any(_lands_on_a_place(_joined(arg.path, folder), names) for arg in args if arg.destination)


def _tar_target_and_members(rest: list[str], folder: str) -> tuple[str, list[str]]:
    """Where ``tar -x`` unpacks (``-C DIR`` / ``--directory=DIR``, else *folder*) and the members it names."""
    target, members, skip = folder, [], False
    old_style = bool(rest) and rest[0].isalpha()          # ``tar xf in.tar …``
    for position, word in enumerate(rest):
        if skip:
            skip = False
            continue
        if word in ("-C", "--directory"):
            target = rest[position + 1] if position + 1 < len(rest) else target
            skip = True
        elif word.startswith("--directory="):
            target = word.split("=", 1)[1]
        elif word.startswith("-") or (old_style and position == 0):
            cluster = word.lstrip("-")
            if not word.startswith("--") and "f" in cluster and cluster.isalpha():
                skip = True                               # the next word is the archive itself
        else:
            members.append(word)
    return target, members


def _unzip_target_and_members(rest: list[str], folder: str) -> tuple[str, list[str]]:
    """Where ``unzip`` unpacks (``-d DIR``, else *folder*) and the members it names after the archive."""
    target, operands, skip = folder, [], False
    for position, word in enumerate(rest):
        if skip:
            skip = False
        elif word == "-d":
            target = rest[position + 1] if position + 1 < len(rest) else target
            skip = True
        elif not word.startswith("-"):
            operands.append(word)
    return target, operands[1:]                           # the first operand is the archive


#: ``unzip`` options that only list or test an archive.
_UNZIP_READS = frozenset({"-l", "-t", "-v", "-Z", "-z"})


def extracts(name: str, rest: list[str]) -> bool:
    """True when *name* with words *rest* unpacks an archive (``tar -x``/``--extract``/``--get``,
    ``unzip`` without a list or test option). Appending to an archive (``tar -r``) is not this."""
    if name == "unzip":
        return not any(word in _UNZIP_READS for word in rest)
    if name not in UNPACKERS:
        return False
    clusters = [word.lstrip("-") for position, word in enumerate(rest)
                if (word.startswith("-") and not word.startswith("--")) or (position == 0 and word.isalpha())]
    return any("x" in cluster for cluster in clusters) or bool({"--extract", "--get"} & set(rest))


def unpack_writes_a_place(name: str, rest: list[str], folder: str) -> bool:
    """True when an archive extraction (*name* with words *rest*, run in *folder*) writes a guarded place."""
    reader = _unzip_target_and_members if name == "unzip" else _tar_target_and_members
    target, members = reader(rest, folder)
    destination = _joined(target, folder)
    if not guard_places.reaches(destination):
        return False
    if guard_places.inside(destination) or not members:
        return True                     # into Blackbox itself, or a whole archive whose members are not known
    return any(guard_places.reaches(destination.rstrip("/") + "/" + member) for member in members)
