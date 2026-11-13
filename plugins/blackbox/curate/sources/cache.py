"""The "not listed" cache: a source's CLEAN answer, remembered for 24 hours (§03.3, F-029).

Only a CLEAN answer is ever stored. A FOUND answer is never cached as its
opposite (KI-270 stays fixed) — it evicts any stale entry instead — and
UNAVAILABLE ("could not tell") is not an answer, so it is never stored either.

State: ``<curate home>/sources/not_listed_cache.json`` — ``{source: {identifier:
expires_epoch}}``. One class owns the file, one lock, atomic writes; expired
entries are dropped on every write so the file stays bounded.

Usage::

    cache = NotListedCache()
    if not cache.is_not_listed("osv", identifier): ...ask...; cache.remember_not_listed("osv", identifier)
    with cache.session(): ...many lookups...   # one read, one merged write (a beat asks 7 sources × 100 items)
"""

from __future__ import annotations

import json
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable, Iterator, Optional

from .. import keys
from ...kernel.bounded_files import atomic_write, read_json_object

NOT_LISTED_TTL_SECONDS = 24 * 60 * 60
_FILE = "not_listed_cache.json"

Entries = dict[str, dict[str, float]]


class NotListedCache:
    """Per-source "not listed" answers, each valid for :data:`NOT_LISTED_TTL_SECONDS`."""

    _lock = threading.Lock()

    def __init__(self, path: Optional[Path] = None, *, clock: Callable[[], float] = time.time) -> None:
        self._path = path or (keys.curate_home() / "sources" / _FILE)
        self._clock = clock
        self._view: Optional[Entries] = None              # the file as a session read it (None: no session)
        self._remembered: dict[tuple[str, str], float] = {}
        self._forgotten: set[tuple[str, str]] = set()

    @contextmanager
    def session(self) -> Iterator[None]:
        """Read the file once, answer and change in memory, write once at the end — merged into
        the file as it is THEN, so another process's entries written meanwhile are kept. Without
        it every lookup re-read the whole file and every CLEAN answer rewrote it (a beat: up to
        700 parses). One session at a time per instance (the registry runs one beat)."""
        with self._lock:
            self._view = self._read()
        self._remembered, self._forgotten = {}, set()
        try:
            yield
        finally:
            self._view = None
            if self._remembered or self._forgotten:
                with self._lock:
                    entries = self._read()
                    for source, identifier in self._forgotten:
                        entries.get(source, {}).pop(identifier, None)
                    for (source, identifier), expires in self._remembered.items():
                        entries.setdefault(source, {})[identifier] = expires
                    self._write(entries)

    def is_not_listed(self, source: str, identifier: str) -> bool:
        """True when *source* answered CLEAN for *identifier* less than 24 h ago."""
        if self._view is not None:
            return self._view.get(source, {}).get(identifier, 0.0) > self._clock()
        with self._lock:
            return self._read().get(source, {}).get(identifier, 0.0) > self._clock()

    def remember_not_listed(self, source: str, identifier: str) -> None:
        """Record *source*'s CLEAN answer for *identifier* for the next 24 h."""
        expires = self._clock() + NOT_LISTED_TTL_SECONDS
        if self._view is not None:
            self._view.setdefault(source, {})[identifier] = expires
            self._remembered[(source, identifier)] = expires
            self._forgotten.discard((source, identifier))
            return
        with self._lock:
            entries = self._read()
            entries.setdefault(source, {})[identifier] = expires
            self._write(entries)

    def forget(self, source: str, identifier: str) -> None:
        """Drop any "not listed" entry — called when *source* now lists *identifier*."""
        if self._view is not None:
            self._view.get(source, {}).pop(identifier, None)
            self._remembered.pop((source, identifier), None)
            self._forgotten.add((source, identifier))
            return
        with self._lock:
            entries = self._read()
            if entries.get(source, {}).pop(identifier, None) is not None:
                self._write(entries)

    def _read(self) -> Entries:
        data = read_json_object(self._path) or {}
        return {str(source): {str(identifier): float(expires) for identifier, expires in listed.items()
                              if isinstance(expires, (int, float))}
                for source, listed in data.items() if isinstance(listed, dict)}

    def _write(self, entries: Entries) -> None:
        now = self._clock()
        live = {source: {identifier: expires for identifier, expires in listed.items() if expires > now}
                for source, listed in entries.items()}
        live = {source: listed for source, listed in live.items() if listed}
        self._path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(self._path, json.dumps(live, sort_keys=True))
