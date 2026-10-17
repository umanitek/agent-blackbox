"""A member-asset promotion's report reaches Verified Memory before its batch (§03.4, ``strategies``).

A batch publishes the curators' promotions as ONE asset. A member-asset
promotion is a statement pointing at a report, and the report is its
reporter's own asset, published on its own
(:class:`.node_writers.NodeReportWriter`). Such a promotion enters a batch
only once its report reads back from Verified Memory: no statement is paid
for while its report cannot be published, and a report that cannot be keeps
only its own promotion waiting, never a batch. (A curator-asset promotion —
the copy a curator node older than DKG 10.0.25 takes — publishes nothing of
the reporter's and never comes here.)

Each report publish is paid, so it walks the publish ledger like a batch,
under its own record — ``report:<sub-graph>:<author>:<asset name>`` (the
asset it publishes), one entry: the promoted identifier, category ``report``
— with the batch's fail-closed rules (F-035, LES-011): SEALED means the
asset holding the report was found here as a complete share; SUBMITTED is
written before the call; a definite refusal goes back to SEALED and is
retried; a MINTED report (a 207) is never submitted again, only read back; a
SUBMITTED one found after a restart moves on only from what the node says; a
written-off one waits for a person. A report Verified Memory already holds is
never paid for, whoever published it.

Usage (``batch.BatchPublisher``, for the entries a due batch chose)::

    reports = ReportPublisher(ledger)
    for pending, action, note in reports.settle(ctx, writer, pendings):
        ...   # action == READY: its report reads back from Verified Memory; it may enter the batch
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional, Sequence

from ...kernel.dkg_client import DkgError
from ...kernel.signing import promotion_statement as statement
from .. import promotion
from ..context import CurateContext
from .ledger import BatchEntry, BatchRecord, PublishLedger, PublishState
from .node_writers import NodeReportWriter, ReportAsset, SubmitReply, definite_refusal

logger = logging.getLogger(__name__)

#: The ledger record of a report's own publish.
REPORT_RECORD = "report:"
_ROOT = "-"
#: What :meth:`ReportPublisher.settle` answers once every report reads back.
READY = "ready"
#: Report publishes one run submits at most (each waits for the chain).
MAX_SUBMITS_PER_RUN = 5


@dataclass(frozen=True)
class PendingReport:
    """One member-asset promotion in a batch: its ``identifier`` and the report
    (:class:`statement.ReportRef`) its signed payload names, re-checked before
    paying."""

    identifier: str
    ref: statement.ReportRef


def is_report_record(record: BatchRecord) -> bool:
    return record.batch_id.startswith(REPORT_RECORD)


class ReportPublisher:
    """Drives the ``report:`` records of the publish ledger (see the module doc)."""

    def __init__(self, ledger: PublishLedger, *, max_submits: int = MAX_SUBMITS_PER_RUN) -> None:
        self._ledger = ledger
        self._max_submits = max_submits
        self._submits_left = max_submits

    def settle(self, ctx: CurateContext, writer: NodeReportWriter,
               pendings: Sequence[PendingReport]) -> list[tuple[PendingReport, str, str]]:
        """Move the report each of *pendings* points at as far as the node
        allows: ``(pending, action, note)`` — READY once it reads back from
        Verified Memory, else ``held`` / ``failed`` / ``could-not-tell`` /
        ``minted`` and why (logged)."""
        self._submits_left = self._max_submits
        outcomes = []
        for pending in pendings:
            action, note = self._settle_one(ctx, writer, pending)
            if action != READY:
                logger.log(logging.INFO if action == "held" else logging.WARNING,
                           "blackbox: the promotion of %s waits for its report (%s): %s", pending.identifier, action, note)
            outcomes.append((pending, action, note))
        return outcomes

    # ------------------------------------------------------------ one report

    def _settle_one(self, ctx: CurateContext, writer: NodeReportWriter, pending: PendingReport) -> tuple[str, str]:
        record = self._record(pending.identifier)
        if record is None:
            return self._start(ctx, writer, pending)
        asset = _asset_of(record)
        if record.state in (PublishState.BOUND, PublishState.SEEN):
            return READY, ""
        if record.state is PublishState.SEALED:
            return self._submit(record, writer, pending, asset)
        if record.state is PublishState.SUBMITTED:
            ual = writer.asset_ual(asset)
            if ual is None:
                return "held", "submitted; the node has not named a UAL yet"
            return self._minted(record, writer, pending, SubmitReply(ual), "found after a restart")
        if record.state is PublishState.MINTED:
            if writer.readable(pending.ref) is not True:
                return "held", "minted (207), not readable yet; not re-submitted"
            self._ledger.reconcile_minted(record.batch_id, readable_ual=record.ual, note="read back after a 207")
            return READY, ""
        return "held", "its publish was written off; a person decides"

    def _start(self, ctx: CurateContext, writer: NodeReportWriter, pending: PendingReport) -> tuple[str, str]:
        """No record yet: Verified Memory may hold the report already (nothing
        to pay); else it is re-checked, its asset found and its record started."""
        asset, why = self._find(ctx, writer, pending)
        if why:
            return ("could-not-tell" if why == _COULD_NOT_TELL else "held"), why
        if asset is None:
            return READY, ""
        record = self._ledger.queue(_record_id(asset), [BatchEntry(pending.identifier, "report")])
        record = self._ledger.advance(record.batch_id, PublishState.SEALED, note="found here as a complete share")
        return self._submit(record, writer, pending, asset)

    def _find(self, ctx: CurateContext, writer: NodeReportWriter,
              pending: PendingReport) -> tuple[Optional[ReportAsset], str]:
        """``(None, "")`` — Verified Memory holds the report; ``(asset, "")`` —
        the shared asset to publish; ``(None, why)`` — neither (yet)."""
        readable = writer.readable(pending.ref)
        if readable is None:
            return None, _COULD_NOT_TELL
        if readable:
            return None, ""
        try:
            promotion.checked_report(ctx, pending.ref)
            asset = writer.locate(pending.ref)
        except (promotion.PromotionError, DkgError) as exc:
            return None, str(exc)
        if asset is None:
            return None, "this node holds no shared copy of the report with its author's seal"
        return (None, "") if asset.verified else (asset, "")

    def _submit(self, record: BatchRecord, writer: NodeReportWriter, pending: PendingReport,
                asset: ReportAsset) -> tuple[str, str]:
        if self._submits_left <= 0:
            return "held", "waiting for its turn (report publishes per run are capped)"
        self._submits_left -= 1
        # SUBMITTED is written BEFORE the call: a crash mid-call must read as "could not tell".
        self._ledger.advance(record.batch_id, PublishState.SUBMITTED)
        try:
            reply = writer.submit(asset)
        except DkgError as exc:   # the client wraps every transport failure too
            if definite_refusal(exc):
                self._ledger.advance(record.batch_id, PublishState.SEALED, note=f"refused: {exc}"[:400])
                return "failed", f"refused: {exc}"
            return "could-not-tell", str(exc)
        if reply.ual is None:
            return "could-not-tell", "the node named no UAL"
        return self._minted(record, writer, pending, reply, f"tx {reply.tx_hash or 'not reported'}")

    def _minted(self, record: BatchRecord, writer: NodeReportWriter, pending: PendingReport, reply: SubmitReply,
                how: str) -> tuple[str, str]:
        """SUBMITTED → BOUND when the report reads back, else MINTED (a 207). The
        reply carries no TRAC figure: 0 is logged with the transaction named."""
        state = PublishState.BOUND if writer.readable(pending.ref) else PublishState.MINTED
        self._ledger.advance(record.batch_id, state, ual=reply.ual, cost_trac="0", cost_bytes=0,
                             note=f"TRAC not in the reply; {how}")
        if state is PublishState.MINTED:
            return "minted", f"minted as {reply.ual} but not readable (207); reconciled next run"
        return READY, ""

    def _record(self, identifier: str) -> Optional[BatchRecord]:
        """The newest report record for *identifier* (a written-off one included: it waits for a person)."""
        records = [record for record in self._ledger.batches()
                   if is_report_record(record) and record.entries[0].identifier == identifier]
        return records[-1] if records else None


_COULD_NOT_TELL = "this node's store could not be read"


def _record_id(asset: ReportAsset) -> str:
    return f"{REPORT_RECORD}{asset.sub_graph or _ROOT}:{asset.author}:{asset.name}"


def _asset_of(record: BatchRecord) -> ReportAsset:
    """The asset a report record publishes (its id names it)."""
    sub_graph, author, name = record.batch_id[len(REPORT_RECORD):].split(":", 2)
    return ReportAsset(name, author, "" if sub_graph == _ROOT else sub_graph)
