"""The batch publisher — beat step 8 on the wallet node (trust-and-threat-lab §03.4, D27).

Quorum-signed promotions wait as APPROVED proposals; :class:`BatchPublisher`
turns them into ONE verified-graph knowledge asset per batch (≤ 50 entries,
each written the way its payload says — :mod:`.strategies`: by default the
verified rule made from the report at ``threat_uri(identifier)``, carrying its
own 2-of-N envelope) and walks it through the :class:`PublishLedger`. A
member-asset promotion's report is its reporter's own asset, published first
on its own ledger record (:mod:`.reports`): such an entry joins a batch once
its report reads back from Verified Memory. Pattern: Builder.

When a batch goes (D15, F-017), whichever comes first: :data:`BATCH_ENTRIES`
entries wait; the oldest has waited :data:`BATCH_SECONDS` (6 h); a block-tier
entry (``dep:``; ``skill:``, the artifact fingerprint ``skill:artifact:…``
included) with ≥ :data:`FAST_LANE_REPORTERS` verified reporters (the community
tier's count) has waited :data:`FAST_LANE_HOLD_SECONDS` — half an hour for
others to join, inside the hour the proposal promises. Revocations and
corrections are never batched: they go at once through :func:`.publish.publish`
(asymmetric safety, F-032).

Fail-closed rules (F-035, LES-011):

* Before a new batch, every earlier unsettled batch is settled first. A SEALED
  batch (a definite refusal) is re-submitted — the same batch, never a new one.
  A SUBMITTED batch found after a crash moves on only from what the node says
  (its UAL). A MINTED batch (HTTP 207: paid, not readable) is NEVER submitted
  again: it is reconciled by reading it back, or written off by the operator.
  While any batch is unsettled no new batch is queued.
* The pre-check (:func:`.precheck.precheck`) runs right before the paid
  publishes with :func:`strict_verified_subset`, which RAISES when the store
  cannot tell. A member-asset entry joins a batch only once its report reads
  back from Verified Memory; until then it waits outside every batch.

Usage (the beat wiring is SVC4)::

    publisher = BatchPublisher()          # ProposalStore() + PublishLedger() in the curate home
    report = publisher.run(ctx)           # one step; report.action says what happened
    publisher.metrics(ctx)                # the F-035 record for the console and Slack
"""

from __future__ import annotations

import json
import logging
import secrets
import time
from dataclasses import dataclass
from decimal import Decimal
from types import MappingProxyType
from typing import Any, Callable, Iterable, Mapping, Optional, Sequence

from ...kernel import constants, signing
from ...kernel.signing import promotion_statement as statement
from ..context import CurateContext
from ..proposal import Proposal, ProposalError, ProposalState, ProposalStore
from . import strategies
from .ledger import BatchEntry, BatchRecord, PublishLedger, PublishState
from .precheck import VerifiedSubset, precheck, strict_verified_subset
from .node_writers import NodeBatchWriter, NodeReportWriter, SubmitReply, definite_refusal
from .publish import has_quorum
from .reports import READY, PendingReport, ReportPublisher, is_report_record

logger = logging.getLogger(__name__)

BATCH_ENTRIES = 50
BATCH_SECONDS = 6 * 3600
FAST_LANE_REPORTERS = 3
FAST_LANE_HOLD_SECONDS = 30 * 60
#: Block-tier categories (package, skill; the fingerprint is a ``skill:artifact:`` identifier).
BLOCK_TIER_CATEGORIES = frozenset({"dep", "skill"})
#: A proposal waiting for its co-sign longer than this many beats is reported (F-035).
COSIGN_STALL_BEATS = 3
#: ``blackbox curate run``'s default beat interval (curate/parser.py).
DEFAULT_BEAT_SECONDS = 300.0
FAST_LANE = "fast"
BATCH_LANE = "batched"
_UNSETTLED = frozenset({PublishState.QUEUED, PublishState.SEALED, PublishState.SUBMITTED, PublishState.MINTED})


@dataclass(frozen=True)
class Candidate:
    """One APPROVED promotion ready for a batch: its proposal, the threat, the
    envelope, the rows of its asset (built now, so a promotion that cannot be
    written never reaches a batch), when it was approved, how many verified
    reporters the community tier counts for its threat, and — member-asset
    only — the report published before it may join a batch."""

    proposal_id: str
    identifier: str
    envelope: signing.SignedEnvelope
    quads: tuple[dict[str, str], ...]
    approved_at: float
    reporters: int
    report_first: Optional[PendingReport] = None

    @property
    def category(self) -> str:
        return self.identifier.split(":", 1)[0]

    @property
    def fast(self) -> bool:
        return self.category in BLOCK_TIER_CATEGORIES and self.reporters >= FAST_LANE_REPORTERS


@dataclass(frozen=True)
class BatchRunReport:
    """What one :meth:`BatchPublisher.run` did. ``action``: ``waiting`` (no trigger
    yet), ``published`` (a batch was bound and read back), ``minted`` (paid, not yet
    readable), ``held`` (an earlier batch is unsettled), ``failed`` (definite
    refusal; the batch stays SEALED and is retried), ``could-not-tell`` (nothing
    decided)."""

    action: str
    batch_id: Optional[str] = None
    entries: int = 0
    dropped: int = 0
    note: str = ""


@dataclass(frozen=True)
class BatchMetrics:
    """The publisher's F-035 record (console + Slack monitor). Optional fields are
    None when unknown — never a guessed 0."""

    waiting_per_lane: Mapping[str, int]
    oldest_waiting_seconds: Optional[float]
    proposals_awaiting_cosign: int          # PROPOSED for more than COSIGN_STALL_BEATS beats
    unsettled_batches: int
    held_back: int                          # APPROVED promotions no row builder can write
    failures: int
    minted_207s: int
    seconds_since_last_batch: Optional[float]
    wallet_trac: Optional[Decimal]
    wallet_floor_trac: Optional[Decimal]    # two batches at the dearest recorded cost
    below_wallet_floor: Optional[bool]


class BatchPublisher:
    """Owns beat step 8. ``store`` / ``ledger`` default to the curate home's;
    ``writer`` / ``report_writer`` — the node side (default
    :class:`.node_writers.NodeBatchWriter` / :class:`.node_writers.NodeReportWriter`
    on the context's client); ``verified_subset`` — the pre-check lookup (default
    :func:`strict_verified_subset` over ``ctx.compiled``); ``wallet_balance`` — the
    wallet's TRAC, None when unknown; ``beat_seconds`` — the beat interval."""

    def __init__(self, store: Optional[ProposalStore] = None, ledger: Optional[PublishLedger] = None, *,
                 writer: Optional[NodeBatchWriter] = None, report_writer: Optional[NodeReportWriter] = None,
                 verified_subset: Optional[VerifiedSubset] = None,
                 wallet_balance: Callable[[], Optional[Decimal]] = lambda: None,
                 beat_seconds: float = DEFAULT_BEAT_SECONDS, clock: Callable[[], float] = time.time) -> None:
        self._store = store or ProposalStore()
        self._ledger = ledger or PublishLedger(clock=clock)
        self._writer, self._report_writer = writer, report_writer
        self._reports = ReportPublisher(self._ledger)
        self._verified_subset = verified_subset
        self._wallet_balance = wallet_balance
        self._beat_seconds = beat_seconds
        self._clock = clock

    # ------------------------------------------------------------ the step

    def run(self, ctx: CurateContext) -> BatchRunReport:
        """Settle earlier batches, then publish at most ONE new batch when a trigger fired."""
        writer = self._writer or NodeBatchWriter(ctx.client, ctx.verified_graph)
        reports = self._report_writer or NodeReportWriter(ctx.client, ctx.verified_graph)
        candidates, _ = self._candidates(ctx)
        settled: Optional[BatchRunReport] = None
        for record in [record for record in self._batches() if record.state in _UNSETTLED]:
            settled = self._settle(record, candidates, writer)
            if settled.action != "published":
                return settled
        for record in self._batches():
            if record.state in (PublishState.BOUND, PublishState.SEEN):
                self._mark_published(record, candidates)
        waiting = self._waiting(candidates)
        if not self._due(waiting):
            return settled or BatchRunReport("waiting", entries=len(waiting))
        chosen = sorted(waiting, key=lambda c: (not c.fast, c.approved_at))[:BATCH_ENTRIES]
        try:
            checked = precheck(chosen, self._verified_subset or strict_verified_subset(ctx.compiled))
        except Exception as exc:   # LES-011: no answer, no paid publish
            logger.warning("blackbox: batch pre-check could not tell (%s); nothing published", exc)
            return BatchRunReport("could-not-tell", entries=len(chosen), note=str(exc))
        self._close_dropped(checked.dropped)
        kept, waits = self._ready(ctx, reports, checked.kept)
        if not kept:   # nothing to batch until a member-asset report reads back from Verified Memory
            action, note = next(((a, f"the report of {p.identifier}: {n}") for p, a, n in waits), ("waiting", ""))
            return BatchRunReport(action, dropped=len(checked.dropped), note=note or "every chosen entry is already listed")
        batch_id = f"b-{int(self._clock())}-{secrets.token_hex(4)}"
        record = self._ledger.queue(batch_id, [BatchEntry(c.identifier, c.category) for c in kept])
        report = self._settle(record, candidates, writer)
        return BatchRunReport(report.action, batch_id, len(kept), len(checked.dropped), report.note)

    # ------------------------------------------------------------ collecting

    def _candidates(self, ctx: CurateContext) -> tuple[dict[str, Candidate], int]:
        """APPROVED, quorum-signed promotions for the verified graph, by identifier;
        plus how many of them cannot be written (held back, logged)."""
        out: dict[str, Candidate] = {}
        held_back = 0
        for proposal in self._store.all():
            if (proposal.state is not ProposalState.APPROVED or proposal.kind != statement.PROMOTION_STATEMENT
                    or proposal.graph != ctx.verified_graph):
                continue
            envelope = proposal.parsed()
            if envelope is None or not has_quorum(ctx, proposal, envelope):
                continue
            try:
                candidate = _candidate(ctx, proposal, envelope)
            except ValueError as exc:   # a promotion of a report by neither way, or past the store's literal cap
                held_back += 1
                logger.warning("blackbox: promotion %s cannot be batched: %s", proposal.id, exc)
                continue
            out.setdefault(candidate.identifier, candidate)
        return out, held_back

    def _ready(self, ctx: CurateContext, writer: NodeReportWriter, chosen: Sequence[Candidate]
               ) -> tuple[list[Candidate], list[tuple[PendingReport, str, str]]]:
        """The *chosen* entries that may join a batch now — every curator-asset
        one, and a member-asset one once its report reads back — and the
        member-asset reports still waiting, with why."""
        settled = self._reports.settle(ctx, writer, [c.report_first for c in chosen if c.report_first is not None])
        ready = {pending.identifier for pending, action, _note in settled if action == READY}
        waits = [outcome for outcome in settled if outcome[1] != READY]
        return [c for c in chosen if c.report_first is None or c.identifier in ready], waits

    def _batches(self) -> list[BatchRecord]:
        """The statement batches in the ledger (a report's own publish has its own record, :mod:`.reports`)."""
        return [record for record in self._ledger.batches() if not is_report_record(record)]

    def _waiting(self, candidates: Mapping[str, Candidate]) -> list[Candidate]:
        """Candidates in no batch yet (a written-off batch's entries wait again)."""
        taken = {entry.identifier for record in self._batches()
                 if record.state is not PublishState.WRITTEN_OFF for entry in record.entries}
        return [candidate for identifier, candidate in candidates.items() if identifier not in taken]

    def _due(self, waiting: Sequence[Candidate]) -> bool:
        now = self._clock()
        return (len(waiting) >= BATCH_ENTRIES
                or any(now - c.approved_at >= BATCH_SECONDS for c in waiting)
                or any(c.fast and now - c.approved_at >= FAST_LANE_HOLD_SECONDS for c in waiting))

    def _close_dropped(self, dropped: Iterable[Any]) -> None:
        """A promotion the verified graph already covers is closed, so it is not re-checked every beat."""
        for drop in dropped:
            self._transition(drop.entry.proposal_id, ProposalState.REJECTED, f"not published: {drop.reason} ({drop.covered_by})")

    # ------------------------------------------------------------ the ledger steps

    def _settle(self, record: BatchRecord, candidates: Mapping[str, Candidate],
                writer: NodeBatchWriter) -> BatchRunReport:
        """Move *record* as far as the node's answers allow (see the module doc)."""
        rows = [candidates.get(entry.identifier) for entry in record.entries]
        if any(row is None for row in rows):   # a promotion left APPROVED: the asset cannot be rebuilt
            return BatchRunReport("held", record.batch_id, note="a batch entry is no longer an approved promotion")
        batch = [row for row in rows if row is not None]
        name = asset_name(record.batch_id)
        if record.state is PublishState.QUEUED:
            try:
                writer.seal(name, [quad for c in batch for quad in c.quads])
            except Exception as exc:   # nothing was spent; the next run seals the same batch again
                return BatchRunReport("failed", record.batch_id, note=f"working-memory write failed: {exc}")
            record = self._ledger.advance(record.batch_id, PublishState.SEALED)
        if record.state is PublishState.SEALED:
            return self._submit(record, batch, name, writer)
        if record.state is PublishState.SUBMITTED:
            ual = writer.asset_ual(name)
            if ual is None:
                return BatchRunReport("held", record.batch_id, note="submitted; the node has not named a UAL yet")
            return self._minted(record, batch, SubmitReply(ual), writer, "found after a restart")
        return self._reconcile(record, batch, writer)

    def _submit(self, record: BatchRecord, batch: Sequence[Candidate], name: str,
                writer: NodeBatchWriter) -> BatchRunReport:
        # SUBMITTED is written BEFORE the call: a crash mid-call must read as "could not tell".
        self._ledger.advance(record.batch_id, PublishState.SUBMITTED)
        try:
            reply = writer.submit(name)
        except Exception as exc:
            if definite_refusal(exc):
                self._ledger.advance(record.batch_id, PublishState.SEALED, note=f"refused: {exc}"[:400])
                return BatchRunReport("failed", record.batch_id, note=str(exc))
            return BatchRunReport("could-not-tell", record.batch_id, note=str(exc))
        if reply.ual is None:
            return BatchRunReport("could-not-tell", record.batch_id, note="the node named no UAL")
        return self._minted(record, batch, reply, writer, f"tx {reply.tx_hash or 'not reported'}")

    def _minted(self, record: BatchRecord, batch: Sequence[Candidate], reply: SubmitReply,
                writer: NodeBatchWriter, how: str) -> BatchRunReport:
        """SUBMITTED → BOUND when the rows read back, else MINTED (a 207). The node's
        reply carries no TRAC figure, so the bytes are logged and the TRAC is 0 with
        the transaction named — the wallet watch compares it with the chain."""
        readable = writer.readable(_signed_rows(batch))
        state = PublishState.BOUND if readable else PublishState.MINTED
        record = self._ledger.advance(record.batch_id, state, ual=reply.ual, cost_trac="0",
                                      cost_bytes=_byte_size(batch), note=f"TRAC not in the reply; {how}")
        if state is PublishState.MINTED:
            logger.warning("blackbox: batch %s minted as %s but not readable (207); reconciled next beat",
                           record.batch_id, reply.ual)
            return BatchRunReport("minted", record.batch_id, len(batch))
        self._mark_published(record, {c.identifier: c for c in batch})
        return BatchRunReport("published", record.batch_id, len(batch))

    def _reconcile(self, record: BatchRecord, batch: Sequence[Candidate], writer: NodeBatchWriter) -> BatchRunReport:
        """A MINTED batch is read back, never re-minted; written off only by the operator."""
        if writer.readable(_signed_rows(batch)) is not True:
            return BatchRunReport("held", record.batch_id, note="minted (207), not readable yet; not re-submitted")
        record = self._ledger.reconcile_minted(record.batch_id, readable_ual=record.ual, note="read back after a 207")
        self._mark_published(record, {c.identifier: c for c in batch})
        return BatchRunReport("published", record.batch_id, len(batch))

    def _mark_published(self, record: BatchRecord, candidates: Mapping[str, Candidate]) -> None:
        for entry in record.entries:
            if entry.identifier in candidates:
                self._transition(candidates[entry.identifier].proposal_id, ProposalState.PUBLISHED,
                                 f"published in batch {record.batch_id} as {record.ual}")

    def _transition(self, proposal_id: str, state: ProposalState, note: str) -> None:
        proposal = self._store.get(proposal_id)
        if proposal is None or proposal.state is not ProposalState.APPROVED:
            return
        try:
            self._store.save(proposal.transition(state, now=self._clock(), note=note))
        except ProposalError as exc:   # pragma: no cover - APPROVED allows both moves
            logger.warning("blackbox: could not close proposal %s: %s", proposal_id, exc)

    # ------------------------------------------------------------ F-035

    def metrics(self, ctx: CurateContext) -> BatchMetrics:
        now = self._clock()
        candidates, held_back = self._candidates(ctx)
        waiting = self._waiting(candidates)
        lanes = {FAST_LANE: sum(c.fast for c in waiting), BATCH_LANE: sum(not c.fast for c in waiting)}
        stalled = sum(1 for p in self._store.all() if p.state is ProposalState.PROPOSED
                      and now - p.created > COSIGN_STALL_BEATS * self._beat_seconds)
        batches = self._ledger.batches()
        ledger = self._ledger.metrics(now)
        costs = [record.cost_trac for record in batches if record.cost_trac]
        floor = 2 * max(costs) if costs else None
        balance = self._wallet_balance()
        return BatchMetrics(
            waiting_per_lane=MappingProxyType(lanes),
            oldest_waiting_seconds=max((now - c.approved_at for c in waiting), default=None),
            proposals_awaiting_cosign=stalled,
            unsettled_batches=sum(record.state in _UNSETTLED for record in batches),
            held_back=held_back,
            failures=ledger.failures,
            minted_207s=ledger.minted_207s,
            seconds_since_last_batch=ledger.seconds_since_last_success,
            wallet_trac=balance,
            wallet_floor_trac=floor,
            below_wallet_floor=None if balance is None or floor is None else balance < floor,
        )


def asset_name(batch_id: str) -> str:
    """The knowledge-asset name of a batch (deterministic, so a retry writes the same asset)."""
    return f"verified-batch-{batch_id}"


def _reporters(ctx: CurateContext, identifier: str) -> int:
    """How many verified reporters this node's community tier counts for *identifier* (0 when unknown)."""
    rule = getattr(ctx.compiled, "community", {}).get(identifier) if ctx.compiled is not None else None
    return int((rule or {}).get("reporterCount") or 0)


def _candidate(ctx: CurateContext, proposal: Proposal, envelope: signing.SignedEnvelope) -> Candidate:
    """*proposal* as a batch entry, written the way its payload says; raises
    ``ValueError`` when it is a promotion of a report by neither way."""
    strategy = strategies.strategy_for(envelope)
    ref = strategy.reference(envelope) if strategy is not None else None
    if strategy is None or ref is None:
        raise ValueError(strategies.refusal(envelope))
    _name, quads = strategy.asset(envelope, strategies.evidence_of(proposal))
    return Candidate(proposal.id, ref.identifier, envelope, tuple(quads), proposal.updated,
                     _reporters(ctx, ref.identifier),
                     PendingReport(ref.identifier, ref) if strategy.publishes_report else None)


def _signed_rows(batch: Sequence[Candidate]) -> dict[str, str]:
    """Each signed subject of the batch → the envelope it must read back with."""
    return {quad["subject"]: c.envelope.to_text() for c in batch for quad in c.quads
            if quad["predicate"] == constants.SIGNED_STATEMENT_PRED}


def _byte_size(batch: Sequence[Candidate]) -> int:
    """The batch's quads as the node receives them (JSON), in bytes."""
    return len(json.dumps([quad for c in batch for quad in c.quads]).encode("utf-8"))
