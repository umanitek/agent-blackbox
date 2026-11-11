"""The live-reports memory — what this node must keep alive on the network (R5).

Shared memory expires per node (30 days by default, measured 2026-10-02), so a
report this node shared would silently vanish from every peer unless someone
re-shares it. Only its AUTHOR may do that (a curator re-share would make the
curator the author, plan §06), so each node remembers every report it got
accepted — name, graph, identifier and the already-signed quads — and the
publisher (:mod:`.publisher`) re-shares each one under an epoch-named asset
while it is still inside its community lifetime.

This is the one piece of state R5 adds beyond the reader's persistence
window: the signed quads must be re-sent byte-for-byte (re-signing would
mint a new statement), and neither the share ledger nor the ruleset holds
them. Pattern: a small persisted store with one lock and atomic writes (the
same shape as :mod:`..share_retry`); bounded to :data:`MAX_LIVE` entries so a
node can never keep more alive than the reader-side per-author cap counts.

Usage::

    store = LiveReportStore()
    store.remember(graph=..., name=..., identifier=..., subject=..., severity=..., quads=..., epoch=...)
    store.due(current_epoch, now)        # LiveReports whose newest copy is from an older epoch
    store.mark_published(name, epoch)
    store.forget_identifier(identifier)  # retracted: never kept alive again
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Iterable, Optional

from ...kernel import constants
from ..statements.lifetimes import lifetime_days
from .epochs import Epoch
from ...kernel.bounded_files import read_json_object, write_json_object

logger = logging.getLogger(__name__)

#: Most reports one node keeps alive (the reader-side per-author cap is 500).
MAX_LIVE = 500
_STORE_FILE = "live_reports.json"
_DAY_SECONDS = 86_400.0


@dataclass(frozen=True)
class LiveReport:
    """One report this node shared and keeps alive.

    ``name`` is the base asset name (the first share), ``graph`` the community
    graph, ``identifier`` / ``subject`` / ``severity`` what the share ledger
    rows say, ``quads`` the signed statement exactly as first shared,
    ``first_shared`` when (epoch seconds, this node's clock) and
    ``last_epoch`` the keep-alive epoch of the newest copy on the network.
    """

    name: str
    graph: str
    identifier: str
    subject: str
    severity: str
    quads: tuple[dict[str, str], ...]
    first_shared: float
    last_epoch: int

    def within_lifetime(self, now: float) -> bool:
        """Still inside the community lifetime of its threat type (plan §03)."""
        return (now - self.first_shared) <= lifetime_days(self.identifier) * _DAY_SECONDS

    def as_json(self) -> dict[str, Any]:
        return {"name": self.name, "graph": self.graph, "identifier": self.identifier, "subject": self.subject,
                "severity": self.severity, "quads": list(self.quads), "first_shared": self.first_shared,
                "last_epoch": self.last_epoch}

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> LiveReport:
        return cls(name=str(data["name"]), graph=str(data["graph"]), identifier=str(data.get("identifier", "")),
                   subject=str(data.get("subject", "")), severity=str(data.get("severity", "")),
                   quads=tuple(dict(q) for q in data.get("quads", [])), first_shared=float(data.get("first_shared", 0)),
                   last_epoch=int(data.get("last_epoch", 0)))


class LiveReportStore:
    """$BLACKBOX_HOME/live_reports.json — one lock, atomic writes, bounded.

    Several processes may share a home (the hook, ``blackbox report``, the
    dashboard): last writer wins, and the worst case of a lost update is one
    extra copy of an idempotent asset.
    """

    def __init__(self, path: Optional[Path] = None, clock: Callable[[], float] = time.time) -> None:
        self._path = path or (constants.blackbox_home() / _STORE_FILE)
        self._clock = clock
        self._lock = threading.Lock()

    def all(self) -> list[LiveReport]:
        with self._lock:
            return self._load()

    def remember(self, *, graph: str, name: str, identifier: str, subject: str, severity: str,
                 quads: Iterable[dict[str, str]], epoch: Epoch) -> LiveReport:
        """Record an ACCEPTED share (idempotent by name: an existing entry keeps
        its first_shared and quads). The oldest entries drop past MAX_LIVE."""
        now = self._clock()
        with self._lock:
            live = self._load()
            existing = next((r for r in live if r.name == name), None)
            entry = (replace(existing, last_epoch=max(existing.last_epoch, int(epoch))) if existing else
                     LiveReport(name=name, graph=graph, identifier=identifier, subject=subject, severity=severity,
                                quads=tuple(dict(q) for q in quads), first_shared=now, last_epoch=int(epoch)))
            live = [r for r in live if r.name != name] + [entry]
            live.sort(key=lambda r: r.first_shared)
            self._save(live[-MAX_LIVE:])
            return entry

    def due(self, current: Epoch, now: float) -> list[LiveReport]:
        """Reports whose newest copy is from an older epoch and that are still
        within their lifetime; reports past their lifetime are retired here."""
        with self._lock:
            live = self._load()
            alive = [r for r in live if r.within_lifetime(now)]
            if len(alive) < len(live):
                logger.info("blackbox: %d report(s) reached their community lifetime and are no longer kept alive",
                            len(live) - len(alive))
                self._save(alive)
        return [r for r in alive if r.last_epoch < int(current)]

    def mark_published(self, name: str, epoch: Epoch) -> None:
        with self._lock:
            live = self._load()
            self._save([replace(r, last_epoch=int(epoch)) if r.name == name else r for r in live])

    def forget_all(self) -> int:
        """Identity erasure (R13): nothing of this node's is ever re-published again."""
        with self._lock:
            live = self._load()
            self._save([])
            return len(live)

    def forget_names(self, names: Iterable[str]) -> int:
        """Stop keeping the entries with these base asset *names* alive; returns how many."""
        gone = set(names)
        with self._lock:
            live = self._load()
            kept = [r for r in live if r.name not in gone]
            self._save(kept)
            return len(live) - len(kept)

    def forget_identifier(self, identifier: str) -> int:
        """Stop keeping every report of *identifier* alive (a retraction); returns how many."""
        with self._lock:
            live = self._load()
            kept = [r for r in live if r.identifier != identifier]
            self._save(kept)
            return len(live) - len(kept)

    def _load(self) -> list[LiveReport]:
        data = read_json_object(self._path) or {}
        try:
            return [LiveReport.from_json(item) for item in data.get("live", [])]
        except (OSError, ValueError, KeyError, TypeError):
            return []   # missing or unreadable: nothing to keep alive

    def _save(self, live: list[LiveReport]) -> None:
        # fail-open: an unwritable home only loses the keep-alive memory
        write_json_object(self._path, {"live": [r.as_json() for r in live]}, what="the live-reports store")
