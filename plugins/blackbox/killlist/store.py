"""The last-good kill list on disk (R14) — what the hook enforces.

The ruleset refresh writes here only after a list passed the signature
check and the blast-radius gates; the hook reads here on every call.
Anything that goes wrong on the way (an unreadable graph, a bad signature,
a refused version, a clock problem) simply never writes, so the last good
list stays in force. One lock, atomic tmp+rename, the plugin's store shape.

Usage::

    store = LastGoodStore()                       # $BLACKBOX_HOME/kill_list.json
    store.current()                               # KillList or None
    store.remember(decision, kill_list.day)       # after gates.admit accepted a version
    store.current().held                          # entries of that version still in their 24 h hold
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from typing import Any, Optional

from ..kernel import constants
from .gates import Decision
from .statement import KillEntry, KillList
from ..kernel.bounded_files import atomic_write

logger = logging.getLogger(__name__)
_STORE_FILE = "kill_list.json"


class LastGoodStore:
    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or (constants.blackbox_home() / _STORE_FILE)
        self._lock = threading.Lock()

    def current(self) -> Optional[KillList]:
        with self._lock:
            return self._load()

    def remember(self, decision: Decision, day: str) -> None:
        """Persist the entries a decision put in force (refused decisions are not written)."""
        if decision.refused:
            return
        with self._lock:
            self._save(KillList(version=decision.version, day=day, entries=decision.applied, held=decision.deferred))

    def _load(self) -> Optional[KillList]:
        try:
            data: dict[str, Any] = json.loads(self._path.read_text(encoding="utf-8-sig"))
            entries = [KillEntry.from_json(item) for item in data.get("entries", []) if isinstance(item, dict)]
            held = [KillEntry.from_json(item) for item in data.get("held", []) if isinstance(item, dict)]
            if any(e is None for e in entries + held):
                return None
            return KillList(version=int(data.get("version", 0)), day=str(data.get("day") or ""),
                            entries=tuple(e for e in entries if e is not None), held=tuple(e for e in held if e is not None))
        except (OSError, ValueError, TypeError, AttributeError):
            return None

    def _save(self, kill_list: KillList) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(self._path, json.dumps({"version": kill_list.version, "day": kill_list.day,
                                       "entries": [e.as_json() for e in kill_list.entries],
                                       "held": [e.as_json() for e in kill_list.held]}))
        except OSError as exc:
            logger.warning("blackbox: could not save the kill list (%s); the previous one stays in force", exc)
