"""The publish ledger — every verified-graph batch as a state machine (pattern: State).

The batch publisher spends real money (TRAC + gas) on every mint, and the
July feed stall left three assets minted on chain but never bound to the
graph (the ``/vm/publish`` route's HTTP 207). So each batch walks a closed
table of states, and every step is one append to ``<curate home>/publish_ledger.jsonl``::

    QUEUED → SEALED → SUBMITTED ─→ BOUND → SEEN
                ↑         │  └──→ MINTED (207) ─→ BOUND (the existing UAL)
                └─────────┘ definite failure  └─→ WRITTEN_OFF (cost logged)

* :class:`PublishState` / :data:`_TRANSITIONS` — the states and the only legal
  moves; anything else raises :class:`PublishLedgerError`.
* A MINTED batch is never submitted again: it is reconciled — bound to the
  UAL it already has, or written off with its cost kept on the record.
* A batch found SUBMITTED after a restart is "could not tell": move it on
  only from what the node or chain says (MINTED / BOUND), and back to SEALED
  only on a DEFINITE failure answer — never because nothing was heard.
* :func:`publish_metrics` — time since the last bound/seen batch, failures,
  207s and the monthly TRAC/bytes spend, computed from the ledger alone.

Usage::

    ledger = PublishLedger()                         # <curate home>/publish_ledger.jsonl
    ledger.queue("b-0001", [BatchEntry("npm:evil@1.0.0", "dependency")])
    ledger.advance("b-0001", PublishState.SEALED)
    ledger.advance("b-0001", PublishState.SUBMITTED)
    ledger.advance("b-0001", PublishState.MINTED, ual="did:dkg:…", cost_trac="0.42", cost_bytes=18_000)
    ledger.reconcile_minted("b-0001", readable_ual="did:dkg:…")   # or readable_ual=None, note="why"
    ledger.metrics().minted_207s
"""

from __future__ import annotations

import json
import os
import re
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, replace
from decimal import Decimal, InvalidOperation
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Callable, Dict, FrozenSet, Iterable, Iterator, List, Mapping, Optional, Sequence, Tuple

try:  # POSIX: curator nodes. Elsewhere the in-process lock below still holds.
    import fcntl
except ImportError:  # pragma: no cover - Windows
    fcntl = None  # type: ignore[assignment]

from ...kernel.bounded_files import append_line
from .. import keys
from .errors import PublishLedgerError

LEDGER_FILE = "publish_ledger.jsonl"
#: One knowledge asset per batch holds at most this many entries (§03.4, F-017).
MAX_BATCH_ENTRIES = 50
_BATCH_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_MAX_IDENTIFIER_CHARS = 512
_MAX_CATEGORY_CHARS = 64
_MAX_NOTE_CHARS = 400

TracAmount = Decimal | str | int

#: One lock per ledger FILE, shared by every PublishLedger in the process: two
#: instances on one file (the beat and a verb) must not both read SEALED and
#: both append SUBMITTED — that pays twice and leaves a line no replay accepts.
_FILE_LOCKS: dict[str, threading.Lock] = {}
_FILE_LOCKS_GUARD = threading.Lock()


def _file_lock(path: Path) -> threading.Lock:
    key = os.path.realpath(path)
    with _FILE_LOCKS_GUARD:
        return _FILE_LOCKS.setdefault(key, threading.Lock())


class PublishState(Enum):
    QUEUED = "queued"            # entries chosen, nothing written anywhere
    SEALED = "sealed"            # the batch asset is built in working memory and shared in full (KI-351)
    SUBMITTED = "submitted"      # /vm/publish was called; the answer is not recorded yet
    MINTED = "minted"            # HTTP 207: on chain (paid) but not bound to the graph
    BOUND = "bound"              # bound and read back on the node: published means readable
    SEEN = "seen"                # a bench reader has seen it
    WRITTEN_OFF = "written_off"  # a 207 that could not be bound; the money is gone, the cost logged


_TRANSITIONS: Mapping[PublishState, frozenset[PublishState]] = MappingProxyType({
    PublishState.QUEUED: frozenset({PublishState.SEALED}),
    PublishState.SEALED: frozenset({PublishState.SUBMITTED}),
    PublishState.SUBMITTED: frozenset({PublishState.MINTED, PublishState.BOUND, PublishState.SEALED}),
    PublishState.MINTED: frozenset({PublishState.BOUND, PublishState.WRITTEN_OFF}),
    PublishState.BOUND: frozenset({PublishState.SEEN}),
    PublishState.SEEN: frozenset(),
    PublishState.WRITTEN_OFF: frozenset(),
})
#: The moves where the chain took the money: the cost must be stated here, and only here.
_SPENDING = frozenset({(PublishState.SUBMITTED, PublishState.MINTED), (PublishState.SUBMITTED, PublishState.BOUND)})
#: The moves that must say why (a failed submit; a written-off mint).
_NEEDS_NOTE = frozenset({(PublishState.SUBMITTED, PublishState.SEALED), (PublishState.MINTED, PublishState.WRITTEN_OFF)})


@dataclass(frozen=True)
class BatchEntry:
    """One threat in a batch: its identifier and promotable category (one subject per threat)."""

    identifier: str
    category: str

    def __post_init__(self) -> None:
        if not isinstance(self.identifier, str) or not 0 < len(self.identifier) <= _MAX_IDENTIFIER_CHARS:
            raise PublishLedgerError("a batch entry needs an identifier of 1-512 characters")
        if not isinstance(self.category, str) or not 0 < len(self.category) <= _MAX_CATEGORY_CHARS:
            raise PublishLedgerError("a batch entry needs a category of 1-64 characters")


@dataclass(frozen=True)
class BatchRecord:
    """A batch as of one ledger line. ``ual`` is set once known and never changes;
    ``cost_trac`` / ``cost_bytes`` are set on the spending move and carried after."""

    batch_id: str
    state: PublishState
    entries: tuple[BatchEntry, ...]
    ual: Optional[str]
    cost_trac: Optional[Decimal]
    cost_bytes: Optional[int]
    at: float
    note: str


@dataclass(frozen=True)
class Transition:
    """One ledger line read back: the state it left (None for QUEUED) and the record it wrote."""

    previous: Optional[PublishState]
    record: BatchRecord


@dataclass(frozen=True)
class MonthlyCost:
    trac: Decimal
    bytes: int


@dataclass(frozen=True)
class PublishMetrics:
    """What the console and the Slack monitor show (F-035). ``monthly`` is keyed ``YYYY-MM`` (UTC)."""

    seconds_since_last_success: Optional[float]  # None: no batch was ever bound
    failures: int                                # submits that came back with a definite failure
    minted_207s: int                             # batches that reached MINTED
    monthly: Mapping[str, MonthlyCost]


def publish_metrics(transitions: Sequence[Transition], now: float) -> PublishMetrics:
    """The F-035 metrics from the ledger's transitions alone (no other state)."""
    last_success: Optional[float] = None
    failures = minted = 0
    monthly: dict[str, MonthlyCost] = {}
    for step in transitions:
        record = step.record
        if record.state in (PublishState.BOUND, PublishState.SEEN):
            last_success = record.at if last_success is None else max(last_success, record.at)
        if (step.previous, record.state) == (PublishState.SUBMITTED, PublishState.SEALED):
            failures += 1
        if record.state is PublishState.MINTED:
            minted += 1
        if (step.previous, record.state) in _SPENDING:
            month = time.strftime("%Y-%m", time.gmtime(record.at))
            spent = monthly.get(month, MonthlyCost(Decimal(0), 0))
            monthly[month] = MonthlyCost(spent.trac + (record.cost_trac or 0), spent.bytes + (record.cost_bytes or 0))
    return PublishMetrics(
        seconds_since_last_success=None if last_success is None else max(0.0, now - last_success),
        failures=failures,
        minted_207s=minted,
        monthly=MappingProxyType(monthly),
    )


def _trac(value: Optional[TracAmount]) -> Optional[Decimal]:
    if value is None:
        return None
    if isinstance(value, (float, bool)):  # money stays exact: pass a Decimal or its text
        raise PublishLedgerError("cost_trac must be a Decimal, an int or decimal text, not a float")
    try:
        amount = Decimal(value)
    except (InvalidOperation, ValueError, TypeError):
        raise PublishLedgerError(f"cost_trac is not a number: {value!r}") from None
    if not amount.is_finite() or amount < 0:
        raise PublishLedgerError("cost_trac must be a finite amount ≥ 0")
    return amount


def _byte_count(value: Optional[int]) -> Optional[int]:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise PublishLedgerError("cost_bytes must be an int ≥ 0")
    return value


def _step(
    current: Optional[BatchRecord], batch_id: str, state: PublishState, *, at: float,
    entries: tuple[BatchEntry, ...] = (), ual: Optional[str] = None,
    cost_trac: Optional[Decimal] = None, cost_bytes: Optional[int] = None, note: str = "",
) -> BatchRecord:
    """The one choke point every move passes — live and on reload alike."""
    if current is None:
        if state is not PublishState.QUEUED:
            raise PublishLedgerError(f"batch {batch_id} does not exist; it must be QUEUED first")
        if not entries or len(entries) > MAX_BATCH_ENTRIES:
            raise PublishLedgerError(f"a batch holds 1-{MAX_BATCH_ENTRIES} entries")
        if len({entry.identifier for entry in entries}) != len(entries):
            raise PublishLedgerError("a batch holds each identifier once")
        return BatchRecord(batch_id, state, entries, None, None, None, at, note[:_MAX_NOTE_CHARS])
    move = (current.state, state)
    if ual is not None and (not isinstance(ual, str) or not ual.strip()):
        raise PublishLedgerError(f"batch {batch_id}: a UAL is non-empty text")
    if state not in _TRANSITIONS[current.state]:
        raise PublishLedgerError(f"batch {batch_id}: {current.state.name} → {state.name} is not allowed")
    if ual is not None and current.ual is not None and ual != current.ual:
        raise PublishLedgerError(f"batch {batch_id} is bound to {current.ual}; a minted batch keeps its UAL")
    if state is PublishState.BOUND and (ual or current.ual) is None:
        raise PublishLedgerError(f"batch {batch_id}: BOUND needs the UAL it was bound to")
    if move in _SPENDING:
        if cost_trac is None or cost_bytes is None:
            raise PublishLedgerError(f"batch {batch_id}: {state.name} spent money; log cost_trac and cost_bytes")
    elif (cost_trac is not None and cost_trac != current.cost_trac) or (
            cost_bytes is not None and cost_bytes != current.cost_bytes):
        raise PublishLedgerError(f"batch {batch_id}: the cost is logged once, on the move that spent it")
    if move in _NEEDS_NOTE and not note.strip():
        raise PublishLedgerError(f"batch {batch_id}: {current.state.name} → {state.name} must say why")
    return replace(
        current, state=state, ual=ual or current.ual, at=at, note=note[:_MAX_NOTE_CHARS],
        cost_trac=current.cost_trac if cost_trac is None else cost_trac,
        cost_bytes=current.cost_bytes if cost_bytes is None else cost_bytes,
    )


def _to_line(record: BatchRecord) -> str:
    line = {
        "batch_id": record.batch_id, "state": record.state.value, "ual": record.ual,
        "cost_trac": None if record.cost_trac is None else str(record.cost_trac),
        "cost_bytes": record.cost_bytes, "at": record.at, "note": record.note,
    }
    if record.state is PublishState.QUEUED:  # entries are fixed at queueing; later lines carry them by replay
        line["entries"] = [[entry.identifier, entry.category] for entry in record.entries]
    return json.dumps(line, sort_keys=True)


def _replay(lines: Iterable[str], source: Path) -> list[Transition]:
    """Re-run every line through :func:`_step`; an unreadable or illegal line stops the load."""
    current: dict[str, BatchRecord] = {}
    transitions: list[Transition] = []
    for number, text in enumerate(lines, start=1):
        if not text.strip():
            continue
        try:
            raw = json.loads(text)
            batch_id = raw["batch_id"]
            record = _step(
                current.get(batch_id), batch_id, PublishState(raw["state"]), at=float(raw["at"]),
                entries=tuple(BatchEntry(identifier, category) for identifier, category in raw.get("entries") or ()),
                ual=raw.get("ual"), cost_trac=_trac(raw.get("cost_trac")),
                cost_bytes=_byte_count(raw.get("cost_bytes")), note=str(raw.get("note") or ""),
            )
        except (ValueError, KeyError, TypeError) as exc:  # PublishLedgerError is a ValueError
            raise PublishLedgerError(f"{source}:{number}: unreadable publish-ledger line ({exc})") from None
        transitions.append(Transition(current[batch_id].state if batch_id in current else None, record))
        current[batch_id] = record
    return transitions


class PublishLedger:
    """Owns ``publish_ledger.jsonl`` and its lock: the ONLY writer of batch state.

    Every call re-reads the file under the lock, so two ledgers on one file
    (the beat and the console) never act on a stale state. The lock is per
    file, not per instance — shared in-process, and an exclusive ``flock`` on
    the file across processes (POSIX) — so read-check-append is one step. Lines are appended
    and fsynced before a call returns; nothing is ever rewritten. A file that
    does not replay cleanly raises :class:`PublishLedgerError` on every call.
    """

    def __init__(self, path: Optional[Path] = None, clock: Callable[[], float] = time.time) -> None:
        self._path = path or (keys.curate_home() / LEDGER_FILE)
        self._clock = clock
        self._lock = _file_lock(self._path)

    def queue(self, batch_id: str, entries: Sequence[BatchEntry]) -> BatchRecord:
        """Start a new batch with *entries* (1-50, each identifier once)."""
        if not isinstance(batch_id, str) or not _BATCH_ID.match(batch_id):
            raise PublishLedgerError(f"not a batch id: {batch_id!r}")
        with self._exclusive():
            if batch_id in self._current():
                raise PublishLedgerError(f"batch {batch_id} is already in the ledger")
            return self._append(_step(None, batch_id, PublishState.QUEUED, at=self._clock(), entries=tuple(entries)))

    def advance(
        self, batch_id: str, state: PublishState, *, ual: Optional[str] = None,
        cost_trac: Optional[TracAmount] = None, cost_bytes: Optional[int] = None, note: str = "",
    ) -> BatchRecord:
        """Move *batch_id* to *state*; raises :class:`PublishLedgerError` on an illegal move."""
        with self._exclusive():
            record = _step(
                self._current().get(batch_id), batch_id, state, at=self._clock(), ual=ual,
                cost_trac=_trac(cost_trac), cost_bytes=_byte_count(cost_bytes), note=note,
            )
            return self._append(record)

    def reconcile_minted(self, batch_id: str, *, readable_ual: Optional[str], note: str = "") -> BatchRecord:
        """Settle a 207: BOUND to *readable_ual* when the existing asset reads back,
        otherwise WRITTEN_OFF (needs *note*) — the cost stays on the record either way."""
        current = self.get(batch_id)
        if current is None or current.state is not PublishState.MINTED:
            raise PublishLedgerError(f"batch {batch_id} is not MINTED; only a 207 is reconciled")
        if readable_ual is not None:
            return self.advance(batch_id, PublishState.BOUND, ual=readable_ual, note=note)
        return self.advance(batch_id, PublishState.WRITTEN_OFF, note=note)

    def get(self, batch_id: str) -> Optional[BatchRecord]:
        with self._exclusive():
            return self._current().get(batch_id)

    def batches(self) -> tuple[BatchRecord, ...]:
        """Every batch in its current state, in the order it was queued."""
        with self._exclusive():
            return tuple(self._current().values())

    def transitions(self) -> tuple[Transition, ...]:
        with self._exclusive():
            return tuple(self._load())

    def metrics(self, now: Optional[float] = None) -> PublishMetrics:
        return publish_metrics(self.transitions(), self._clock() if now is None else now)

    @contextmanager
    def _exclusive(self) -> Iterator[None]:
        """Hold the file's lock for one read-check-append (threads AND processes)."""
        with self._lock:
            if fcntl is None:
                yield
                return
            self._path.parent.mkdir(parents=True, exist_ok=True)
            descriptor = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                yield
            finally:
                os.close(descriptor)  # closing releases the flock

    def _load(self) -> list[Transition]:
        try:
            with self._path.open("r", encoding="utf-8-sig") as handle:
                return _replay(handle, self._path)
        except FileNotFoundError:
            return []

    def _current(self) -> dict[str, BatchRecord]:
        return {step.record.batch_id: step.record for step in self._load()}

    def _append(self, record: BatchRecord) -> BatchRecord:
        append_line(self._path, _to_line(record), mode=0o600, durable=True)
        return record
