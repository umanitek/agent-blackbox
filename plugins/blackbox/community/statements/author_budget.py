"""One per-author budget over ALL community statements, enforced by readers (Refine R2).

Plan §05 (RATE): a hostile client simply skips its own daily cap, so the cap
that matters is the one every READER applies. It covers every statement type
— reports, disputes, retractions — per author (the verified signer key), per
READER-observed UTC day. The day is when THIS node first saw the statement,
never the sender's clock, which can be backdated to spread a flood over many
"days" (KI-105). Over budget, an author's earliest-seen statements of the day
count and the rest are held back and logged.

Joining late is not punished: everything present at this node's very first
read is a one-time BASELINE, exempt from the per-day budget (it is still
bounded by the per-author threat cap in :mod:`..aggregation`).

:class:`FirstSeenStore` is the persisted memory of when each statement was
first seen ($BLACKBOX_HOME/community_first_seen.json). It is bounded to the
statements present in the latest read and written atomically. Several
processes may share a home: the last writer wins, and a lost update only
re-dates a statement to a later first sighting (accepted, like KI-038).

Pattern: a small stateful class with one lock (the store) + a pure policy
(:class:`AuthorBudget`).

Usage::

    result = AuthorBudget(FirstSeenStore()).admit(statements)    # statements: Iterable[Statement]
    result.admitted, result.held_back, result.first_seen
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional

from ...kernel import constants, threat_ids
from ...kernel.bounded_files import read_json_object, write_json_object

logger = logging.getLogger(__name__)

#: Statements one author may add per reader-observed day. 2.5x the client's own
#: cap (100/day since 2026-10-12): an honest node never reaches it; a flooding one is held back.
MAX_STATEMENTS_PER_AUTHOR_PER_DAY = 250
#: The store keeps at most this many statements (the community pager reads 100,000 rows per type).
_MAX_TRACKED = 400_000
_STORE_FILE = "community_first_seen.json"
_DAY_SECONDS = 86_400


@dataclass(frozen=True)
class BudgetResult:
    """What :meth:`AuthorBudget.admit` decided: the ``admitted`` subjects, how
    many statements were ``held_back``, and every subject's ``first_seen``
    epoch (reader-observed)."""

    admitted: frozenset[str]
    held_back: int
    first_seen: dict[str, float]


@dataclass(frozen=True)
class Statement:
    """One signed statement as the budget sees it: its ``author`` (signer key)
    and ``subject`` (unique per statement)."""

    author: str
    subject: str


class FirstSeenStore:
    """When this node first saw each statement subject (persisted, bounded).

    ``baseline_until`` — the time of this node's first ever read: statements
    first seen then are the baseline. Keys are short subject hashes (no
    community text is stored).
    """

    def __init__(self, path: Optional[Path] = None, clock: Callable[[], float] = time.time) -> None:
        self._path = path or (constants.blackbox_home() / _STORE_FILE)
        self._clock = clock
        self._lock = threading.Lock()

    def snapshot(self) -> tuple[dict[str, float], Optional[float]]:
        """Read-only: ({subject-hash: first-seen epoch}, baseline) — never writes
        (``observe`` keeps only the subjects it is given, so it must not be used to peek)."""
        with self._lock:
            return self._load()

    def observe(self, subjects: Iterable[str]) -> tuple[dict[str, float], float]:
        """({subject: first-seen epoch}, baseline_until) for *subjects*.

        New subjects are dated now. Only the subjects passed are kept (the
        latest read IS the graph), so the file stays bounded.
        """
        with self._lock:
            seen, baseline_until = self._load()
            now = self._clock()
            if baseline_until is None:
                baseline_until = now
            keys = {subject: threat_ids.stable_hash(subject, 20) for subject in subjects}
            kept = {key: seen.get(key, now) for key in list(keys.values())[:_MAX_TRACKED]}
            self._save(kept, baseline_until)
            return {subject: kept.get(key, now) for subject, key in keys.items()}, baseline_until

    def _load(self) -> tuple[dict[str, float], Optional[float]]:
        data = read_json_object(self._path) or {}
        try:
            seen = {str(k): float(v) for k, v in dict(data["seen"]).items()}
            return seen, float(data["baseline_until"])
        except (OSError, ValueError, KeyError, TypeError):
            return {}, None   # missing or unreadable: a fresh baseline

    def _save(self, seen: dict[str, float], baseline_until: float) -> None:
        # fail-open: an unwritable home only loses first-seen memory
        write_json_object(self._path, {"baseline_until": baseline_until, "seen": seen}, what="community first-seen times")


class AuthorBudget:
    """Applies the per-author, per-reader-day budget to a read's statements."""

    def __init__(self, store: FirstSeenStore, per_day: int = MAX_STATEMENTS_PER_AUTHOR_PER_DAY) -> None:
        self._store = store
        self._per_day = per_day

    def admit(self, statements: Iterable[Statement]) -> BudgetResult:
        """Baseline statements are always admitted; each later reader-day
        admits an author's earliest-seen ``per_day`` statements."""
        statements = list(statements)
        first_seen, baseline_until = self._store.observe(s.subject for s in statements)
        by_author_day: dict[tuple[str, int], list[tuple[float, str]]] = {}
        admitted = set()
        for statement in statements:
            seen_at = first_seen[statement.subject]
            if seen_at <= baseline_until:
                admitted.add(statement.subject)
                continue
            day = int(seen_at // _DAY_SECONDS)
            by_author_day.setdefault((statement.author, day), []).append((seen_at, statement.subject))
        held_back = 0
        for (author, _day), dated in by_author_day.items():
            dated.sort()
            admitted.update(subject for _, subject in dated[: self._per_day])
            held_back += max(0, len(dated) - self._per_day)
        if held_back:
            logger.warning("blackbox: %d community statement(s) held back by the per-author daily budget", held_back)
        return BudgetResult(admitted=frozenset(admitted), held_back=held_back, first_seen=first_seen)
