"""Whether a path is out of a sandboxed agent's reach because ROOT holds it (shared by the POSIX ports).

The sandbox profile refuses writes by a deny list, so anything the person may write the agent may
write too: ``~/Applications``, ``~/.local/share/applications``, an app bundle the person dragged
into ``/Applications``. The broker opens an app OUTSIDE the sandbox, so an app it opens must be one
the agent can not have built or changed. Ownership is the boundary the agent can not cross
(LES-154): the resolved path and every folder above it are owned by root, nobody but root can write
them, and a folder that is group-writable is accepted only when its group is root's too — or when it
is one of the *shared_parents* the caller names (``/Applications`` is ``root:admin 775``: the person
may add and rename entries there, but can not change a root-owned bundle inside it).

The sandbox permission ``user-apps`` (block by default) widens the owners to root AND the person
(:func:`held_by` with ``owners={0, uid}``): an app the person installed themselves. Never another
user's, never a folder anyone else may write. That is the cost the person accepts by allowing it —
a bundle the person owns can be replaced by any program running as them.

Usage::

    held_by_root("/System/Applications/Preview.app")                          # True
    held_by_root("/Applications/Excel.app", shared_parents={"/Applications"})  # True when root installed it
    held_by_root(os.path.expanduser("~/Applications/X.app"))                   # False
    held_by(os.path.expanduser("~/Applications/X.app"), owners=person_or_root())   # True when the person owns it
"""

from __future__ import annotations

import os
import stat
from typing import Callable, Collection

#: The owners trusted to hold an app the broker opens (root only).
TRUSTED_OWNERS = frozenset({0})
#: Write bits for the group and for everyone else.
_GROUP_WRITE = stat.S_IWGRP
_OTHER_WRITE = stat.S_IWOTH

Lstat = Callable[[str], os.stat_result]


def person_or_root() -> frozenset[int]:
    """Root and the person Blackbox runs as: the owners ``user-apps`` accepts."""
    return TRUSTED_OWNERS | {getattr(os, "getuid", lambda: 0)()}   # POSIX only; no other user is ever added


def _entry_held(path: str, facts: os.stat_result, shared_parents: Collection[str], owners: Collection[int]) -> bool:
    if facts.st_uid not in owners or facts.st_mode & _OTHER_WRITE:
        return False
    # WHY root's group only: a group write lets every member (another user too) change the entry
    return not facts.st_mode & _GROUP_WRITE or facts.st_gid in TRUSTED_OWNERS or path in shared_parents


def held_by(path: str, *, owners: Collection[int], shared_parents: Collection[str] = (), lstat: Lstat = os.lstat) -> bool:
    """True when *path* (links resolved) and every folder above it belong to one of *owners* and
    nobody else may write them (see the module doc); False for anything else, and for a path that
    can not be read (fail closed)."""
    current = os.path.realpath(path)
    while True:
        try:
            facts = lstat(current)
        except OSError:
            return False
        if not _entry_held(current, facts, shared_parents, owners):
            return False
        parent = os.path.dirname(current)
        if parent == current:
            return True
        current = parent


def held_by_root(path: str, *, shared_parents: Collection[str] = (), lstat: Lstat = os.lstat) -> bool:
    """True when *path* (links resolved) and every folder above it are root's (see the module doc)."""
    return held_by(path, owners=TRUSTED_OWNERS, shared_parents=shared_parents, lstat=lstat)


def entries_held(folder: str, *, owners: Collection[int] = TRUSTED_OWNERS, lstat: Lstat = os.lstat) -> bool:
    """True when every entry directly in *folder* belongs to one of *owners* (root by default; a
    link: its target, with every folder above it); False when one does not or the folder can not
    be listed."""
    try:
        names = os.listdir(folder)
    except OSError:
        return False
    for name in names:
        path = os.path.join(folder, name)
        try:
            facts = lstat(path)
        except OSError:
            return False
        if stat.S_ISLNK(facts.st_mode):
            if not held_by(path, owners=owners, lstat=lstat):
                return False
        elif not _entry_held(path, facts, (), owners):
            return False
    return True


__all__ = ["TRUSTED_OWNERS", "entries_held", "held_by", "held_by_root", "person_or_root"]
