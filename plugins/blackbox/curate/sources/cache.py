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
"""

from __future__ import annotations

import json
import threading
import time
from pathlib import Path
from typing import Callable, Optional

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

    def is_not_listed(self, source: str, identifier: str) -> bool:
        """True when *source* answered CLEAN for *identifier* less than 24 h ago."""
        with self._lock:
            return self._read().get(source, {}).get(identifier, 0.0) > self._clock()

    def remember_not_listed(self, source: str, identifier: str) -> None:
        """Record *source*'s CLEAN answer for *identifier* for the next 24 h."""
        with self._lock:
            entries = self._read()
            entries.setdefault(source, {})[identifier] = self._clock() + NOT_LISTED_TTL_SECONDS
            self._write(entries)

    def forget(self, source: str, identifier: str) -> None:
        """Drop any "not listed" entry — called when *source* now lists *identifier*."""
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
