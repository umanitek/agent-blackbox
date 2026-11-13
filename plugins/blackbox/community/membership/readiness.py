"""Whether this node already added the verified graph's shared memory (2026-10-22, KI-449).

On DKG 10.0.25 every subscribe that includes shared memory makes the node restart its
shared-memory catch-up. Blackbox used to subscribe again from every fresh process (each
`blackbox sync` run, each dashboard restart), so a fresh node's verified download kept
being pushed back. Membership now adds the shared memory once per NODE: this record
survives restarts, and afterwards membership only confirms the node's own listing.

One instance per process (:data:`READINESS`), backed by ``verified_ready.json`` in the
Blackbox home; one lock. An unreadable record reads as "not added yet": the worst case is
one more subscribe, never a lost subscription.

Usage::

    READINESS.shared_memory_added(graph)          # membership, before subscribing
    READINESS.mark_shared_memory_added(graph)     # membership, once the node confirmed it
"""

from __future__ import annotations

import json
import logging
import threading
import time
from pathlib import Path
from typing import Callable, Optional

from ...kernel import constants, yaml_files
from ...kernel.bounded_files import read_json_object

logger = logging.getLogger(__name__)

_SHARED_MEMORY = "shared_memory_at"


class GraphReadiness:
    """Per graph: when its shared memory was added to this node's subscription."""

    def __init__(self, store: Optional[Callable[[], Path]] = None, clock: Callable[[], float] = time.time) -> None:
        self._store = store or (lambda: constants.blackbox_home() / "verified_ready.json")
        self._clock = clock
        self._lock = threading.Lock()
        self._cache: Optional[dict[str, dict[str, float]]] = None

    def shared_memory_added(self, graph: str) -> bool:
        """True once the node confirmed a subscription of *graph* with its shared memory."""
        return _SHARED_MEMORY in self._read().get(graph, {})

    def mark_shared_memory_added(self, graph: str) -> None:
        """Record that *graph*'s shared memory is in the node's subscription (idempotent)."""
        cache = self._read()   # the same dict the lock guards
        if not graph or _SHARED_MEMORY in cache.get(graph, {}):
            return
        with self._lock:
            cache.setdefault(graph, {})[_SHARED_MEMORY] = self._clock()
            try:
                yaml_files.atomic_write(self._store(), json.dumps(cache))
            except OSError as exc:   # the memory is lost; the next process re-learns it
                logger.warning("blackbox: could not record the community subscription: %s", exc)

    def _read(self) -> dict[str, dict[str, float]]:
        with self._lock:
            if self._cache is None:
                data = read_json_object(self._store()) or {}
                self._cache = {g: dict(v) for g, v in data.items() if isinstance(v, dict)}
            return self._cache


#: The process's record (see module docstring).
READINESS = GraphReadiness()
