"""Whether a path is out of a sandboxed agent's reach because ROOT holds it (shared by the POSIX ports).

The sandbox profile refuses writes by a deny list, so anything the person may write the agent may
write too: ``~/Applications``, ``~/.local/share/applications``, an app bundle the person dragged
into ``/Applications``. The broker opens an app OUTSIDE the sandbox, so an app it opens must be one
the agent can not have built or changed. Ownership is the boundary the agent can not cross
(LES-154): the resolved path and every folder above it are owned by root, nobody but root can write
them, and a folder that is group-writable is accepted only when its group is root's too — or when it
is one of the *shared_parents* the caller names (``/Applications`` is ``root:admin 775``: the person
may add and rename entries there, but can not change a root-owned bundle inside it).

Usage::

    held_by_root("/System/Applications/Preview.app")                          # True
    held_by_root("/Applications/Excel.app", shared_parents={"/Applications"})  # True when root installed it
    held_by_root(os.path.expanduser("~/Applications/X.app"))                   # False
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


def _entry_held(path: str, facts: os.stat_result, shared_parents: Collection[str]) -> bool:
    if facts.st_uid not in TRUSTED_OWNERS or facts.st_mode & _OTHER_WRITE:
        return False
    return not facts.st_mode & _GROUP_WRITE or facts.st_gid in TRUSTED_OWNERS or path in shared_parents


def held_by_root(path: str, *, shared_parents: Collection[str] = (), lstat: Lstat = os.lstat) -> bool:
    """True when *path* (links resolved) and every folder above it are root's (see the module doc);
    False for anything else, and for a path that can not be read (fail closed)."""
    current = os.path.realpath(path)
    while True:
        try:
            facts = lstat(current)
        except OSError:
            return False
        if not _entry_held(current, facts, shared_parents):
            return False
        parent = os.path.dirname(current)
        if parent == current:
            return True
        current = parent


def entries_held(folder: str, *, lstat: Lstat = os.lstat) -> bool:
    """True when every entry directly in *folder* is root's (a link: its target, with every folder
    above it); False when one is not or the folder can not be listed."""
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
            if not held_by_root(path, lstat=lstat):
                return False
        elif not _entry_held(path, facts, ()):
            return False
    return True


__all__ = ["TRUSTED_OWNERS", "entries_held", "held_by_root"]
