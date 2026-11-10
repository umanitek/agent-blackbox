"""Curator proposals and their two-key lifecycle (Refine R6).

A proposal is one curator statement waiting for its second signature: a
promotion (a threat into the verified tier), a verdict (rejection,
revocation, confirmation, deferral), a counted-author nomination, or a pause.
Its content is the signed envelope (:mod:`...kernel.signing`) — the first
curator's signature is on it when proposed; the second curator co-signs and
PUBLISHES ("whoever signs second publishes", plan §09). A proposal expires
unapproved after 7 days.

Pattern: State (:class:`ProposalState` with the allowed transitions in one
table) on an immutable record; :class:`ProposalStore` owns the files
(``$BLACKBOX_HOME/curate/proposals/<id>.json``, one lock, atomic writes).

Usage::

    store = ProposalStore()
    proposal = Proposal.new(kind, identifier, envelope, graph, checks={key: evidence})
    store.save(proposal.transition(ProposalState.PROPOSED))
    for p in store.open(): ...
"""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
import time
from dataclasses import asdict, dataclass, replace
from enum import Enum
from pathlib import Path
from typing import Dict, FrozenSet, List, Mapping, Optional

from ...kernel import signing, threat_ids
from .. import keys
from ...kernel.bounded_files import atomic_write

#: A proposal nobody approved in this long expires (plan §09 / §12).
PROPOSAL_TTL_DAYS = 7
_DAY_SECONDS = 86_400


class ProposalState(Enum):
    DRAFT = "draft"
    PROPOSED = "proposed"
    APPROVED = "approved"
    PUBLISHED = "published"
    EXPIRED = "expired"
    REJECTED = "rejected"


#: The only moves the lifecycle allows (State pattern, as a table).
_TRANSITIONS: dict[ProposalState, frozenset[ProposalState]] = {
    ProposalState.DRAFT: frozenset({ProposalState.PROPOSED, ProposalState.REJECTED}),
    ProposalState.PROPOSED: frozenset({ProposalState.APPROVED, ProposalState.EXPIRED, ProposalState.REJECTED}),
    ProposalState.APPROVED: frozenset({ProposalState.PUBLISHED, ProposalState.REJECTED}),
    ProposalState.PUBLISHED: frozenset(),
    ProposalState.EXPIRED: frozenset(),
    ProposalState.REJECTED: frozenset(),
}


class ProposalError(ValueError):
    """A move the lifecycle does not allow, or a malformed proposal."""


@dataclass(frozen=True)
class Proposal:
    """One curator proposal.

    ``id`` — sha256 prefix of the first envelope; ``kind`` — the statement type
    (``blackbox.promotion``, ``blackbox.revocation``, …); ``identifier`` — the
    threat (or ``author:<key>``, ``curator``); ``graph`` — where it publishes;
    ``envelope`` — the signed envelope text (1 signature when proposed, 2+
    when approved); ``checks`` — per curator key, the item-1 evidence that key
    recorded (``{key_hex: "advisory:MAL-…"}``); ``created`` / ``updated`` —
    epoch seconds; ``state``; ``note`` — a closed-vocabulary note, never the
    reporter's text.
    """

    id: str
    kind: str
    identifier: str
    graph: str
    envelope: str
    checks: Mapping[str, str]
    created: float
    updated: float
    state: ProposalState = ProposalState.DRAFT
    note: str = ""

    @classmethod
    def new(cls, kind: str, identifier: str, envelope: signing.SignedEnvelope, graph: str, *,
            checks: Mapping[str, str], now: Optional[float] = None) -> Proposal:
        text = envelope.to_text()
        when = now if now is not None else time.time()
        return cls(id=threat_ids.stable_hash(text, 16), kind=kind, identifier=identifier, graph=graph,
                   envelope=text, checks=dict(checks), created=when, updated=when)

    def parsed(self) -> Optional[signing.SignedEnvelope]:
        return signing.from_text(self.envelope)

    def transition(self, to: ProposalState, *, now: Optional[float] = None, note: str = "") -> Proposal:
        if to not in _TRANSITIONS[self.state]:
            raise ProposalError(f"a {self.state.value} proposal cannot become {to.value}")
        return replace(self, state=to, updated=now if now is not None else time.time(), note=note or self.note)

    def with_envelope(self, envelope: signing.SignedEnvelope, checks: Mapping[str, str]) -> Proposal:
        """The proposal after another signature (and that key's check)."""
        return replace(self, envelope=envelope.to_text(), checks={**self.checks, **checks})

    def expired(self, now: float) -> bool:
        return self.state is ProposalState.PROPOSED and now - self.created > PROPOSAL_TTL_DAYS * _DAY_SECONDS

    def to_json(self) -> str:
        data = asdict(self)
        data["state"] = self.state.value
        return json.dumps(data, sort_keys=True)

    @classmethod
    def from_json(cls, text: str) -> Proposal:
        try:
            data = json.loads(text)
            data["state"] = ProposalState(data["state"])
            data["checks"] = dict(data.get("checks") or {})
            return cls(**data)
        except (ValueError, TypeError, KeyError) as exc:
            raise ProposalError(f"malformed proposal: {exc}") from exc


#: What :meth:`Proposal.new` produces: ``threat_ids.stable_hash(envelope, 16)``.
_PROPOSAL_ID = re.compile(r"[0-9a-f]{16}")


class ProposalStore:
    """The curator's private proposals, one JSON file each. One lock; atomic writes."""

    def __init__(self, directory: Optional[Path] = None) -> None:
        self._dir = directory or (keys.curate_home() / "proposals")
        self._lock = threading.Lock()

    def _path(self, proposal_id: str) -> Optional[Path]:
        """The file for *proposal_id*, or None when it is not an id (16 hex characters). The id
        becomes a file name and can arrive from another node: nothing else may name a path (KI-494)."""
        if not isinstance(proposal_id, str) or not _PROPOSAL_ID.fullmatch(proposal_id):
            return None
        return self._dir / f"{proposal_id}.json"

    def save(self, proposal: Proposal) -> None:
        target = self._path(proposal.id)
        if target is None:
            raise ProposalError("a proposal id is 16 hex characters; not saved")
        with self._lock:
            self._dir.mkdir(parents=True, exist_ok=True)
            atomic_write(target, proposal.to_json())

    def get(self, proposal_id: str) -> Optional[Proposal]:
        path = self._path(proposal_id)
        if path is None or not path.is_file():
            return None
        return Proposal.from_json(path.read_text(encoding="utf-8-sig"))

    def all(self) -> list[Proposal]:
        if not self._dir.is_dir():
            return []
        proposals = []
        for path in sorted(self._dir.glob("*.json")):
            try:
                proposals.append(Proposal.from_json(path.read_text(encoding="utf-8-sig")))
            except (OSError, ProposalError):
                continue
        return proposals

    def open(self, now: Optional[float] = None) -> list[Proposal]:
        """Proposals still in play (DRAFT, PROPOSED, APPROVED), expiring stale ones first."""
        when = now if now is not None else time.time()
        out = []
        for proposal in self.all():
            if proposal.expired(when):
                proposal = proposal.transition(ProposalState.EXPIRED, now=when, note="7-day proposal expiry")
                self.save(proposal)
            if proposal.state in (ProposalState.DRAFT, ProposalState.PROPOSED, ProposalState.APPROVED):
                out.append(proposal)
        return out

    def for_identifier(self, identifier: str) -> list[Proposal]:
        """Prior decisions about one threat (the dossier shows them)."""
        return [p for p in self.all() if p.identifier == identifier]
