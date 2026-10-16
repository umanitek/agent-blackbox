"""The keep-alive publish step and the two hooks that feed it (R5).

* :func:`remember_accepted_share` — every share path calls it the moment a
  REPORT is ACCEPTED (the hook share, ``blackbox report``, the retry drain).
  Only reports are kept alive: disputes, retractions and digests are either
  final or period-named and need no copies.
* :func:`forget_retracted` — a retraction ends keep-alive for the identifier.
* :func:`publish_due_copies` — the publish step on the refresh cycle: for every
  live report whose newest copy is from an older epoch, send the same signed
  quads under the epoch's copy name. ACCEPTED is ledgered as ``kept-alive``
  (never as a new contribution); an "already shared" answer means the copy
  exists; the first FAILED answer ends the beat (the node is refusing writes —
  the next refresh tries again, no backoff state needed because the beat is
  periodic and a window is days wide).

The curator never re-shares others' reports: the only way into the store is
this node's own ACCEPTED share, so the publisher can only ever copy what this
node signed. Everything here is fail-open and does nothing while sharing is
off or ``community_keepalive_epoch_days`` is 0.

Usage::

    keep_alive.remember_accepted_share(cfg, name=..., identifier=..., subject=..., severity=..., quads=...)
    keep_alive.forget_retracted(identifier)
    sent = keep_alive.publish_due_copies(client, cfg)      # from the refresh cycle
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, Iterable, Optional

from ... import audit
from ...kernel import threat_ids
from ...kernel.dkg_client import DkgClient
from .epochs import copy_name, current_epoch
from .store import LiveReportStore

logger = logging.getLogger(__name__)

#: Ledger outcome of an accepted keep-alive copy (community.ShareOutcome has the live ones).
OUTCOME_KEPT_ALIVE = "kept-alive"
#: Most copies one beat sends — a node with hundreds of live reports spreads
#: them over a few refreshes instead of one burst at the window edge.
MAX_COPIES_PER_BEAT = 25


def _epoch_days(cfg: Any) -> float:
    return float(getattr(cfg, "community_keepalive_epoch_days", 0) or 0)


def remember_accepted_share(cfg: Any, *, name: str, identifier: str, subject: str, severity: str,
                            quads: Iterable[dict[str, str]], store: Optional[LiveReportStore] = None,
                            now: Optional[float] = None) -> None:
    """Remember a report this node just got ACCEPTED, so it is kept alive. Fail-open."""
    days = _epoch_days(cfg)
    if days <= 0:
        return
    when = time.time() if now is None else now
    try:
        (store or LiveReportStore()).remember(graph=str(cfg.context_graph_id), name=name, identifier=identifier,
                                              subject=subject, severity=severity, quads=quads,
                                              epoch=current_epoch(when, days))
    except Exception as exc:  # pragma: no cover - never fail a share over its memory
        logger.debug("blackbox: keep-alive memory skipped: %s", exc)


def forget_retracted(identifier: str, store: Optional[LiveReportStore] = None) -> int:
    """A retracted report is never copied again; returns how many entries ended."""
    try:
        return (store or LiveReportStore()).forget_identifier(identifier)
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: keep-alive forget skipped: %s", exc)
        return 0


def publish_due_copies(client: DkgClient, cfg: Any, store: Optional[LiveReportStore] = None,
                       now: Optional[float] = None) -> int:
    """Send this epoch's copy of every live report that lacks one; returns how
    many were accepted. Does nothing while sharing is off or keep-alive is 0."""
    from .. import sharing   # the one send path (sharing imports this package at load time)

    from .. import consent   # round 4: withdrawal must stop keep-alive copies too

    days = _epoch_days(cfg)
    if days <= 0 or not getattr(cfg, "community_enabled", False) or not consent.in_force():
        return 0
    when = time.time() if now is None else now
    epoch = current_epoch(when, days)
    live = store or LiveReportStore()
    accepted = 0
    for report in live.due(epoch, when)[:MAX_COPIES_PER_BEAT]:
        outcome, detail = sharing.send_report(client, report.graph, copy_name(report.name, epoch), list(report.quads))
        if outcome is sharing.ShareOutcome.FAILED:
            logger.info("blackbox: keep-alive copy refused this beat (%s); retrying on the next refresh",
                        audit.sanitize_text(detail, 120))
            break
        live.mark_published(report.name, epoch)
        if outcome is sharing.ShareOutcome.ACCEPTED:
            accepted += 1
            audit.record_share_outcome(identifier=report.identifier, category=threat_ids.category_for(report.identifier),
                                       severity=report.severity, subject=report.subject,
                                       asset_name=copy_name(report.name, epoch), ok=True, error="",
                                       outcome=OUTCOME_KEPT_ALIVE)
    if accepted:
        logger.info("blackbox: %d community report(s) kept alive for epoch %d", accepted, int(epoch))
    return accepted
