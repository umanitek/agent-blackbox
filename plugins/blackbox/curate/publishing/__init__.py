"""Publishing — the last step of every curator verb: number it, check its
signatures, take consent, write it where it lives.

* :func:`publish` (+ :func:`summary`, :class:`PublishOutcome`) — an APPROVED proposal into the
  graph it was signed for, then read back: published means readable.
* :func:`next_sequence` — the sequence number the next statement takes.
* :data:`ROW_BUILDERS` (+ :class:`RowBuilder`, :class:`ConfirmedEntry`, :func:`promotion_payload`,
  :class:`RowBuildError`) — a Strategy per promotable category: a promotion made from a community report
  as signed verified-graph quads, the report as its provenance; also the signed correction rows.
* ``strategies`` — how a promotion reaches Verified Memory: the reporter's own asset with the curators'
  pointer beside it (``reports``; the default, DKG 10.0.25) or, on an older curator node, the curators'
  own asset made from the report.
* :class:`BatchPublisher` (+ :class:`BatchRunReport`, :class:`BatchMetrics`) — beat step 8: quorum-signed
  promotions as ONE verified asset per batch (50 entries or 6 h; block-tier with ≥ 3 reporters within the
  hour), driven through the :class:`PublishLedger`; a 207 is reconciled, never re-minted.
* :func:`precheck` (+ :class:`PrecheckResult`) — the last look at the verified graph before a paid publish;
  :func:`strict_verified_subset` is the lookup to pass it (it raises when the store cannot tell).
  ``publishing.precheck`` is therefore the FUNCTION; reach the module with
  ``importlib.import_module("plugins.blackbox.curate.publishing.precheck")``.
* :class:`VerbError` — what a verb raises when it refuses (printed, never a traceback).
"""

from __future__ import annotations

from .batch import BatchMetrics, BatchPublisher, BatchRunReport
from .errors import VerbError
from .ledger import PublishLedger
from .precheck import PrecheckResult, PrecheckUnavailable, precheck, strict_verified_subset
from .publish import MANIFEST_KIND, PublishOutcome, publish, summary
from .row_builders import ROW_BUILDERS, ConfirmedEntry, RowBuildError, RowBuilder, promotion_payload
from .sequences import next_sequence

__all__ = ["MANIFEST_KIND", "ROW_BUILDERS", "BatchMetrics", "BatchPublisher", "BatchRunReport", "ConfirmedEntry",
           "PrecheckResult", "PrecheckUnavailable", "PublishLedger", "PublishOutcome", "RowBuildError", "RowBuilder",
           "VerbError", "next_sequence", "precheck", "promotion_payload", "publish", "strict_verified_subset", "summary"]
