"""Retrying refused community shares — a new node's first reports are not lost (R16, KI-202).

On mainnet a freshly subscribed node is refused for some minutes before its
writes are accepted (``CONTEXT_GRAPH_NOT_FOUND``, then the same write passes
~10 minutes later — measured 2026-10-02). Before R16 a failed share was logged
once and forgotten, so a node's first catches never reached the network.

Now every FAILED share (never an "already shared" one, never a "cannot sign"
one) is queued here with its already-built, already-signed quads and retried
with exponential backoff — 20 s, 40 s, 80 s, then every 2 minutes, at most
:data:`MAX_ATTEMPTS` attempts within :data:`GIVE_UP_AFTER_SECONDS` — by the
community pulse (:mod:`.pulse`, every ~20 s while the agent is active) and by
every full ruleset refresh. The queue is persisted, so a share refused in a
short-lived ``blackbox report`` process is retried by the next long-lived one.
Re-sending the same asset name is safe: the node client tolerates an
already-sealed draft and re-shares the sealed assertion.

Pattern: a small persisted queue class with one lock (``ShareRetryQueue``) +
pure scheduling rules; ``retry_due_shares`` is the drain.

Usage::

    share_retry.queue_failed_share(graph=..., name=..., identifier=..., category=..., severity=...,
                                   subject=..., quads=..., error=...)   # from the share paths, on FAILED
    sent = share_retry.retry_due_shares(client, cfg)                    # from the pulse / the refresh
    stats = share_retry.default_queue().stats()                          # for the health line
"""

from __future__ import annotations

import json
import logging
import os
import secrets
import threading
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from .. import audit
from ..kernel import constants
from ..kernel.dkg_client import DkgClient
from . import keep_alive

logger = logging.getLogger(__name__)

#: Backoff: the n-th retry waits RETRY_BASE_SECONDS * 2**(n-1), capped. The cap
#: is two minutes: mainnet accepted a fresh node's writes 30 s, ~10 min and
#: ~11 min after subscribing in three measured runs, and a coarser cap turned
#: the ~5-min window into an 11-min landing (bench 2026-10-02).
RETRY_BASE_SECONDS = 20.0
RETRY_MAX_SECONDS = 120.0
#: A share that failed this many times (≈ 75 min at the cap), or that has
#: been failing this long, is given up.
MAX_ATTEMPTS = 40
GIVE_UP_AFTER_SECONDS = 24 * 3600.0
#: Most shares waiting at once (a flood of refusals never grows the file without bound).
MAX_PENDING = 200
#: How many given-up shares the health line can still name.
MAX_GIVEN_UP_REMEMBERED = 50
_STORE_FILE = "share_retry.json"

#: Ledger outcomes this module writes (community.ShareOutcome has the live ones).
OUTCOME_RETRYING = "retrying"
OUTCOME_GIVEN_UP = "failed-after-retries"


@dataclass(frozen=True)
class PendingShare:
    """One refused share: everything needed to send it again unchanged.

    ``name`` is the asset name (unique per reporter and threat), ``graph`` the
    graph it is shared to, ``quads`` the built and signed report, ``attempts`` how
    many sends have failed so far, ``first_failed`` / ``next_due`` epochs,
    ``last_error`` the sanitized reason of the latest failure.
    """

    name: str
    graph: str
    identifier: str
    category: str
    severity: str
    subject: str
    quads: tuple[dict[str, str], ...]
    attempts: int
    first_failed: float
    next_due: float
    last_error: str = ""

    def as_json(self) -> dict[str, Any]:
        return {"name": self.name, "graph": self.graph, "identifier": self.identifier, "category": self.category,
                "severity": self.severity, "subject": self.subject, "quads": list(self.quads), "attempts": self.attempts,
                "first_failed": self.first_failed, "next_due": self.next_due, "last_error": self.last_error}

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> PendingShare:
        return cls(name=str(data["name"]), graph=str(data["graph"]), identifier=str(data.get("identifier", "")),
                   category=str(data.get("category", "")), severity=str(data.get("severity", "")),
                   subject=str(data.get("subject", "")), quads=tuple(dict(q) for q in data.get("quads", [])),
                   attempts=int(data.get("attempts", 0)), first_failed=float(data.get("first_failed", 0)),
                   next_due=float(data.get("next_due", 0)), last_error=str(data.get("last_error", "")))


@dataclass(frozen=True)
class RetryStats:
    """``pending`` shares still being retried; ``given_up`` shares abandoned (remembered, bounded)."""

    pending: int
    given_up: int


def backoff_seconds(attempts: int) -> float:
    """How long to wait after the *attempts*-th failure (pure)."""
    return min(RETRY_MAX_SECONDS, RETRY_BASE_SECONDS * (2 ** max(0, attempts - 1)))


def should_give_up(share: PendingShare, now: float) -> bool:
    """Pure: too many attempts, or failing for too long."""
    return share.attempts >= MAX_ATTEMPTS or (now - share.first_failed) > GIVE_UP_AFTER_SECONDS


class ShareRetryQueue:
    """The persisted queue of refused shares ($BLACKBOX_HOME/share_retry.json).

    One lock, atomic tmp+rename writes, bounded size. Several processes may
    share a home: last writer wins, and the worst case of a lost update is one
    extra send of an idempotent asset.
    """

    def __init__(self, path: Optional[Path] = None, clock: Callable[[], float] = time.time) -> None:
        self._path = path or (constants.blackbox_home() / _STORE_FILE)
        self._clock = clock
        self._lock = threading.Lock()

    # -- reads ---------------------------------------------------------------

    def pending(self) -> list[PendingShare]:
        with self._lock:
            return self._load()[0]

    def due(self) -> list[PendingShare]:
        """Shares whose backoff has elapsed, oldest first."""
        now = self._clock()
        return sorted((s for s in self.pending() if s.next_due <= now), key=lambda s: s.first_failed)

    def stats(self) -> RetryStats:
        with self._lock:
            pending, given_up = self._load()
        return RetryStats(pending=len(pending), given_up=len(given_up))

    # -- writes --------------------------------------------------------------

    def add(self, share: PendingShare) -> None:
        """Queue *share* (replacing an older entry with the same name); the
        oldest entries are dropped past :data:`MAX_PENDING`."""
        with self._lock:
            pending, given_up = self._load()
            pending = [s for s in pending if s.name != share.name] + [share]
            pending.sort(key=lambda s: s.first_failed)
            self._save(pending[-MAX_PENDING:], given_up)

    def clear(self) -> int:
        """Identity erasure (R13): drop every pending share; returns how many."""
        with self._lock:
            pending, _given_up = self._load()
            self._save([], [])
            return len(pending)

    def remove(self, name: str) -> None:
        with self._lock:
            pending, given_up = self._load()
            self._save([s for s in pending if s.name != name], given_up)

    def reschedule(self, share: PendingShare, error: str) -> Optional[PendingShare]:
        """Record one more failure: the share is re-queued with its next due
        time, or given up (remembered, returned as None)."""
        now = self._clock()
        failed = replace(share, attempts=share.attempts + 1, last_error=audit.sanitize_text(error, 200))
        with self._lock:
            pending, given_up = self._load()
            pending = [s for s in pending if s.name != share.name]
            if should_give_up(failed, now):
                given_up = (given_up + [{"name": share.name, "identifier": share.identifier, "at": now}])[-MAX_GIVEN_UP_REMEMBERED:]
                self._save(pending, given_up)
                return None
            kept = replace(failed, next_due=now + backoff_seconds(failed.attempts))
            self._save(pending + [kept], given_up)
            return kept

    # -- storage -------------------------------------------------------------

    def _load(self) -> tuple[list[PendingShare], list[dict[str, Any]]]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8-sig"))
            pending = [PendingShare.from_json(item) for item in data.get("pending", [])]
            given_up = [dict(item) for item in data.get("given_up", [])]
            return pending, given_up
        except (OSError, ValueError, KeyError, TypeError):
            return [], []   # missing or unreadable: an empty queue

    def _save(self, pending: list[PendingShare], given_up: list[dict[str, Any]]) -> None:
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_name(f"{self._path.name}.tmp.{os.getpid()}.{secrets.token_hex(6)}")
            tmp.write_text(json.dumps({"pending": [s.as_json() for s in pending], "given_up": given_up}), encoding="utf-8")
            os.replace(tmp, self._path)
        except OSError as exc:   # fail-open: an unwritable home only loses the retry memory
            logger.warning("blackbox: could not save the share retry queue (%s)", exc)


def default_queue() -> ShareRetryQueue:
    """The queue in this node's Blackbox home (a fresh handle; the file is the state)."""
    return ShareRetryQueue()


def queue_failed_share(*, graph: str, name: str, identifier: str, category: str, severity: str, subject: str,
                       quads: list[dict[str, str]], error: str, queue: Optional[ShareRetryQueue] = None,
                       now: Optional[float] = None) -> PendingShare:
    """Queue a share whose first send FAILED and ledger it as ``retrying``.
    The first retry is due after :data:`RETRY_BASE_SECONDS`."""
    when = time.time() if now is None else now
    share = PendingShare(name=name, graph=graph, identifier=identifier, category=category, severity=severity,
                         subject=subject, quads=tuple(dict(q) for q in quads), attempts=1, first_failed=when,
                         next_due=when + backoff_seconds(1), last_error=audit.sanitize_text(error, 200))
    (queue or default_queue()).add(share)
    audit.record_share_outcome(identifier=identifier, category=category, severity=severity, subject=subject,
                               asset_name=name, ok=False, error=error, outcome=OUTCOME_RETRYING)
    return share


def retry_due_shares(client: DkgClient, cfg: Any, queue: Optional[ShareRetryQueue] = None) -> int:
    """Send every due share again; returns how many reached the network.

    ACCEPTED and already-shared results close the entry with a ledger row; a
    FAILED one reschedules it (no ledger row per attempt — only the terminal
    outcomes are ledgered) or gives it up with a ``failed-after-retries`` row.
    Fail-open at every step. Does nothing while community sharing is off.
    """
    from . import consent, sharing   # the drain uses the one send path; sharing queues through this module

    if not getattr(cfg, "community_enabled", False) or not consent.in_force():   # round 4: consent gates retries
        return 0
    store = queue or default_queue()
    accepted = 0
    for share in store.due():
        outcome, detail = sharing.send_report(client, share.graph, share.name, list(share.quads))
        if outcome is sharing.ShareOutcome.FAILED:
            if store.reschedule(share, detail) is None:
                audit.record_share_outcome(identifier=share.identifier, category=share.category, severity=share.severity,
                                           subject=share.subject, asset_name=share.name, ok=False, error=detail,
                                           outcome=OUTCOME_GIVEN_UP)
                logger.warning("blackbox: community share given up after %d attempts: %s", share.attempts + 1, share.identifier)
            continue
        store.remove(share.name)
        audit.record_share_outcome(identifier=share.identifier, category=share.category, severity=share.severity,
                                   subject=share.subject, asset_name=share.name,
                                   ok=outcome is sharing.ShareOutcome.ACCEPTED, error=detail, outcome=outcome.value)
        if outcome is sharing.ShareOutcome.ACCEPTED:
            accepted += 1
            # R5: only reports are ever queued here, and an accepted report is kept alive by its author.
            keep_alive.remember_accepted_share(cfg, name=share.name, identifier=share.identifier, subject=share.subject,
                                               severity=share.severity, quads=share.quads)
    if accepted:
        logger.info("blackbox: %d queued community share(s) accepted on retry", accepted)
    return accepted


def share_retry_stats() -> RetryStats:
    """Pending and given-up counts for the health line (never raises)."""
    try:
        return default_queue().stats()
    except Exception:  # pragma: no cover - fail open
        return RetryStats(pending=0, given_up=0)
