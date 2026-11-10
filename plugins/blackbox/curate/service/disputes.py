"""The dispute lane — what a curator does with a public-page dispute (trust-and-threat-lab §03.3, SVC3).

``intake.DisputeIntake`` signs a dispute and keeps it in :class:`DisputeStore`,
where it waits in queue lane ``dispute``.
EACH curator re-runs its own source look-ups and, where the type allows, the
lab, and reaches its verdict with the same rules as any threat
(:func:`.verdicts.decide_verdict`):

* rejected (no source lists it and the lab ran clean) — the listing was
  wrong: a :class:`CorrectionRequest` for the P5 correction path
  (``blackbox curate correct``), which takes the second curator's signature;
* confirmed — the listing stands (the dispute closes "upheld");
* not proven — "could not tell" is never "wrong" (LES-028), so a person decides.

The retraction is due within :data:`RETRACT_WITHIN_SECONDS` of the
dispute; an open dispute past that is an ACTION health item
(:func:`dispute_health_items`). Closing a dispute (:func:`settle`) erases the
filer's reply address and gives each reporter of a retracted listing ONE
strike — only when a person found the report FABRICATED; an honest mistake
gets none (strikes allege bad faith, which is always a person's finding).

Pattern: pure functions over typed facts (the beat builds the facts — SVC4);
the only writes are the store's close and the ledger's strike, both in :func:`settle`.

Usage::

    facts = facts_from_lookup(result, citable_sources={"osv"}, lab=evidence)
    outcome = rerun(record, facts)
    if outcome.correction: ...   # hand it to the P5 correction verb
    settle(store, ledger, outcome, reporters=keys, fabricated=False, today=today, now=time.time())
"""

from __future__ import annotations

import json
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, UTC
from enum import Enum
from pathlib import Path
from typing import AbstractSet, Any, Iterable, Mapping, Optional

from ...community import reputation
from ...kernel import yaml_files
from ...kernel.bounded_files import read_json_object
from ...kernel.health import HealthClass, HealthItem
from .. import keys
from ..lab import Evidence
from ..queue import Lane
from ..sources import LookupItem, LookupResult
from .evidence import Lookup
from .report import DISPUTE_ROUTE
from .verdicts import Verdict, VerdictDecision, VerdictFacts, decide_verdict


#: A wrong listing is retracted within this long of the dispute (the public page states it).
RETRACT_WITHIN_SECONDS = 72 * 3600
_DISPUTES_FILE = "disputes.json"
_CONTACTS_FILE = "dispute_contacts.json"


@dataclass(frozen=True)
class DisputeRecord:
    """One dispute in lane ``dispute``: what was signed (``envelope``, the
    signed item's text) and where it stands. ``filed_at`` / ``closed_at`` are
    epoch seconds; ``outcome`` is "" while open, else e.g. "retracted" / "upheld"."""

    dispute_id: str
    identifier: str
    party: str
    reason: str
    filed_at: float
    envelope: str
    closed_at: float = 0.0
    outcome: str = ""

    @property
    def open(self) -> bool:
        return not self.outcome

    @property
    def deadline(self) -> float:
        """When the retraction is due (epoch seconds)."""
        return self.filed_at + RETRACT_WITHIN_SECONDS

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


class DisputeStore:
    """The disputes this curator holds (``<curate home>/disputes.json``) and,
    apart, the reply addresses of OPEN ones (``dispute_contacts.json``, mode
    0600). One lock, atomic writes; an unreadable file reads as empty."""

    _lock = threading.Lock()

    def __init__(self, home: Optional[Path] = None) -> None:
        home = home or keys.curate_home()
        self._path, self._contacts = home / _DISPUTES_FILE, home / _CONTACTS_FILE

    def all(self) -> list[DisputeRecord]:
        return [DisputeRecord(**entry) for entry in self._read(self._path).values()]

    def get(self, dispute_id: str) -> Optional[DisputeRecord]:
        entry = self._read(self._path).get(dispute_id)
        return DisputeRecord(**entry) if entry else None

    def open_records(self) -> list[DisputeRecord]:
        return sorted((record for record in self.all() if record.open), key=lambda record: record.filed_at)

    def open_identifiers(self) -> frozenset[str]:
        """What :func:`queue.delta_view` admits to lane ``dispute``."""
        return frozenset(record.identifier for record in self.open_records())

    def contact(self, dispute_id: str) -> str:
        """The reply address of an open dispute ("" once it closed)."""
        return str(self._read(self._contacts).get(dispute_id) or "")

    def add(self, record: DisputeRecord, reply_to: str) -> None:
        with self._lock:
            entries = self._read(self._path)
            entries[record.dispute_id] = record.as_dict()
            contacts = self._read(self._contacts)
            contacts[record.dispute_id] = reply_to
            self._write_private(self._contacts, contacts)      # the contact first: a record never lacks its reply address
            yaml_files.atomic_write(self._path, json.dumps(entries))

    def close(self, dispute_id: str, outcome: str, *, now: float) -> Optional[DisputeRecord]:
        """Close an OPEN dispute with *outcome* and erase its reply address.
        Returns the closed record; None when it is unknown or already closed
        (so whatever closing triggers happens once)."""
        if not outcome:
            raise ValueError("a dispute closes with an outcome")
        with self._lock:
            entries = self._read(self._path)
            entry = entries.get(dispute_id)
            if not entry or entry.get("outcome"):
                return None
            entry.update(outcome=outcome, closed_at=now)
            yaml_files.atomic_write(self._path, json.dumps(entries))
            contacts = self._read(self._contacts)
            if contacts.pop(dispute_id, None) is not None:
                self._write_private(self._contacts, contacts)
            return DisputeRecord(**entry)

    @staticmethod
    def _read(path: Path) -> dict[str, Any]:
        return read_json_object(path) or {}

    @staticmethod
    def _write_private(path: Path, data: Mapping[str, Any]) -> None:
        yaml_files.atomic_write(path, json.dumps(dict(data)), mode=0o600)


class DisputeAction(Enum):
    """What the re-run calls for."""

    RETRACT = "retract"      # the listing was wrong: a correction (P5 path)
    UPHOLD = "upheld"        # the listing stands
    PERSON = "person"        # could not tell: a person decides


@dataclass(frozen=True)
class CorrectionRequest:
    """What the P5 correction verb needs: the ``identifier`` to suppress, the
    ``reason`` and ``source`` (``dispute:<id>``) it records, and the ``deadline``
    (epoch seconds) by which it must be published."""

    identifier: str
    reason: str
    source: str
    deadline: float


@dataclass(frozen=True)
class DisputeOutcome:
    """This curator's re-run of one dispute: the ``action``, the verdict
    ``decision`` behind it, the ``correction`` when it retracts, and the
    ``dispute_route`` every verdict row names."""

    dispute_id: str
    identifier: str
    action: DisputeAction
    decision: VerdictDecision
    correction: Optional[CorrectionRequest] = None
    dispute_route: str = DISPUTE_ROUTE

    def row(self) -> dict:
        """The verdict row (flat str→str) — it names its dispute route."""
        return {"identifier": self.identifier, "dispute": self.dispute_id, "verdict": self.decision.verdict.value,
                "action": self.action.value, "reason": self.decision.reason, "disputeRoute": self.dispute_route}


def lookup_item(record: DisputeRecord) -> LookupItem:
    """The dispute as the look-up step sees it: lane ``dispute``, due every beat while open."""
    return LookupItem(identifier=record.identifier, lane=Lane.DISPUTE,
                      first_seen=datetime.fromtimestamp(record.filed_at, UTC).date().isoformat())


def facts_from_lookup(result: LookupResult, *, citable_sources: AbstractSet[str],
                      lab: tuple[Evidence, ...] = ()) -> VerdictFacts:
    """This curator's facts from its own source answers and lab runs.
    ``citable_listing`` — the first FOUND answer from a citable source;
    ``sources_clean`` — at least one source answered "not listed" and none
    found it or could not be asked (NOT_APPLICABLE sources say nothing)."""
    found = [verdict for verdict in result.verdicts if verdict.status is Lookup.FOUND]
    citable = next((verdict for verdict in found if verdict.source in citable_sources), None)
    statuses = {verdict.status for verdict in result.verdicts}
    clean = Lookup.CLEAN in statuses and statuses <= {Lookup.CLEAN, Lookup.NOT_APPLICABLE}
    return VerdictFacts(citable_listing=(citable.reference_id or citable.advisory) if citable else "",
                        sources_clean=clean, lab=lab)


def rerun(record: DisputeRecord, facts: VerdictFacts, never_flag: AbstractSet[str] = frozenset()) -> DisputeOutcome:
    """This curator's answer to *record* from its own *facts*."""
    decision = decide_verdict(record.identifier, facts, never_flag)
    if decision.verdict is Verdict.REJECTED:
        correction = CorrectionRequest(identifier=record.identifier, reason=f"dispute upheld: {decision.reason}",
                                       source=f"dispute:{record.dispute_id}", deadline=record.deadline)
        return DisputeOutcome(record.dispute_id, record.identifier, DisputeAction.RETRACT, decision, correction)
    action = DisputeAction.UPHOLD if decision.verdict is Verdict.CONFIRMED else DisputeAction.PERSON
    return DisputeOutcome(record.dispute_id, record.identifier, action, decision)


def settle(store: DisputeStore, ledger: reputation.ReputationLedger, outcome: DisputeOutcome, *,
           reporters: Iterable[str], fabricated: bool, today: str, now: float) -> tuple[str, ...]:
    """Close the dispute once its outcome is final (the correction published,
    or the listing upheld) and return the reporters given a strike: each
    reporter of a RETRACTED listing a person found *fabricated*, once — a
    dispute already closed strikes nobody again. Raises ValueError for an
    outcome still waiting for a person."""
    if outcome.action is DisputeAction.PERSON:
        raise ValueError("a dispute a person must decide cannot be settled from the re-run")
    if store.close(outcome.dispute_id, outcome.action.value, now=now) is None:
        return ()
    if outcome.action is not DisputeAction.RETRACT or not fabricated:
        return ()
    struck = tuple(sorted(set(reporters)))
    for key in struck:
        ledger.record(key, reputation.Outcome(today, False), strike=True)
    return struck


def overdue(store: DisputeStore, now: float) -> list[DisputeRecord]:
    """Open disputes past their retraction deadline, oldest first."""
    return [record for record in store.open_records() if now > record.deadline]


def dispute_health_items(now: float, store: Optional[DisputeStore] = None) -> list[HealthItem]:
    """One ACTION item per dispute open past the 72 h deadline (none on a node with no disputes)."""
    return [HealthItem("operator", HealthClass.ACTION,
                       f"dispute {record.dispute_id} on {record.identifier} is past its 72 h retraction deadline",
                       "re-run the look-ups on both curators and publish the correction, or close it as upheld")
            for record in overdue(store or DisputeStore(), now)]
