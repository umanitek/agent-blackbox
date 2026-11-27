"""The process's in-memory ruleset generation, kept in step with the disk cache.

Several processes share one ``ruleset.json`` (the dashboard, each agent's
hooks, ``blackbox sync``); any of them may replace the file. Every reader in
this process asks :class:`RulesetCache` for the newest generation: it serves
memory while the file's stamp is unchanged and reloads from disk when another
process has replaced it.

Pattern: Monitor object — the cached ruleset and the stamp it was loaded at
change together, under ONE lock, so the check ("is my copy current?") and the
reload are a single step. Before this class (audit item G5) the check and the
reload took the lock separately: two threads could both see a stale stamp and
both reload, and a reader holding an older file's contents could overwrite a
generation ``refresh()`` had just stored.

Usage::

    cache = RulesetCache(stamp=lambda: file_mtime_ns(), load=read_cache_file)
    rs = cache.current()      # newest generation, or None when nothing exists
    cache.store(rs)           # after writing rs to disk: install it in memory
    cache.memory_only()       # what memory holds, without touching disk
"""

from __future__ import annotations

import threading
from typing import Any, Callable, Optional

from .compiler import Ruleset

StampReader = Callable[[], Optional[int]]
RulesetLoader = Callable[[], Optional[Ruleset]]
#: ``store``'s default: take the stamp at store time.
_NOW = object()


class RulesetCache:
    """One in-memory ruleset generation plus the disk stamp it matches.

    ``stamp`` returns the cache file's current stamp (mtime in ns, None when
    the file is missing); ``load`` reads the file (None when missing or
    unreadable). Both are called with the lock held — a concurrent reader
    waits for one reload instead of starting its own.
    """

    def __init__(self, stamp: StampReader, load: RulesetLoader) -> None:
        self._stamp = stamp
        self._load = load
        self._lock = threading.Lock()
        self._ruleset: Optional[Ruleset] = None
        self._known_stamp: Optional[int] = None

    def current(self) -> Optional[Ruleset]:
        """The newest generation: memory when the file is unchanged since it
        was loaded, else re-read from disk (a failed read keeps memory)."""
        with self._lock:
            stamp = self._stamp()
            if self._ruleset is not None and stamp == self._known_stamp:
                return self._ruleset
            disk = self._load()
            if disk is not None:
                self._ruleset = disk
            self._known_stamp = stamp
            return self._ruleset

    def store(self, ruleset: Ruleset, stamp: Any = _NOW) -> None:
        """Install a generation the caller just wrote to disk (the stamp is taken
        now, so the next :meth:`current` serves it) — or read from disk: then pass
        the *stamp* taken BEFORE that read, so a file another process replaced
        during the read is reloaded by the next :meth:`current`, never pinned."""
        with self._lock:
            self._ruleset = ruleset
            self._known_stamp = self._stamp() if stamp is _NOW else stamp

    def memory_only(self) -> Optional[Ruleset]:
        """What memory holds right now, without checking the disk."""
        with self._lock:
            return self._ruleset
