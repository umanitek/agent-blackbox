"""Canaries — planted identifiers that only a scraper or a liar would report (R9).

The curator plants identifiers that exist nowhere in the wild (a domain it
registered and never used, a package name it reserved). An honest reporter
can never meet one; a report naming one is bad faith by construction:
``canary = hold + zero count`` (plan §06). Readers cannot know the planted
set (it would stop working), so the hold reaches them the ordinary way —
the curator rejects the report with reason ``bad-faith`` and records a
STRIKE for the reporter (:mod:`..reputation`), which is what zeroes its
count everywhere.

Curator-PRIVATE file ``$BLACKBOX_HOME/curate/canaries.json`` (``{"planted":
[identifier, ...]}``); one lock, atomic writes.

Usage (curator machine)::

    store = CanaryStore()
    store.plant("ioc:domain:never-used-7f3a.example")
    hits = store.hits(read.reports)      # {reporter key: [identifier, ...]}
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path
from typing import Iterable, Optional, Protocol

from ...kernel import constants
from ...kernel.bounded_files import read_json_object, write_json_object

logger = logging.getLogger(__name__)
_CANARY_FILE = "canaries.json"


class _Report(Protocol):
    identifier: str
    author: str


class CanaryStore:
    """The planted identifiers, curator-private."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or (constants.blackbox_home() / "curate" / _CANARY_FILE)
        self._lock = threading.Lock()

    def planted(self) -> list[str]:
        with self._lock:
            return self._load()

    def plant(self, identifier: str) -> None:
        with self._lock:
            current = self._load()
            if identifier not in current:
                self._save(current + [identifier])

    def remove(self, identifier: str) -> bool:
        with self._lock:
            current = self._load()
            if identifier not in current:
                return False
            self._save([i for i in current if i != identifier])
            return True

    def hits(self, reports: Iterable[_Report]) -> dict[str, list[str]]:
        """``{reporter key: [canary identifiers it reported]}`` — each one a
        strike candidate for the curator (never automatic: the curator
        records the outcome, so a planted-by-mistake real threat can be
        unplanted first)."""
        planted = set(self.planted())
        found: dict[str, list[str]] = {}
        for report in reports:
            if report.identifier in planted:
                found.setdefault(report.author, []).append(report.identifier)
        return {author: sorted(set(ids)) for author, ids in found.items()}

    def _load(self) -> list[str]:
        data = read_json_object(self._path) or {}
        try:
            return [str(i) for i in data.get("planted", []) if str(i).strip()]
        except (OSError, ValueError, AttributeError):
            return []

    def _save(self, planted: list[str]) -> None:
        write_json_object(self._path, {"planted": planted}, what="the canary store")
