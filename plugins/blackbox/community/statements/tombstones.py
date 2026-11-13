"""Pending tombstones — withdrawals whose target this reader has not seen (Refine R2).

A retraction can arrive before (or without) the report it withdraws. Plan §05:
such tombstones are kept only for the target's lifetime + 7 days, in a
BOUNDED per-author buffer, so a storm of retractions for reports that do not
exist can neither grow without limit nor hold memory forever. A retraction
only ever withdraws its own signer's report (:mod:`.retractions`), so the
buffer bounds cost, not who can be silenced.

Usage (from the reader)::

    applicable, pending = tombstones.applicable_withdrawals(retractions, reports, first_seen, now)
"""

from __future__ import annotations

from typing import Iterable, Mapping

from ..verification import VerifiedReport
from .lifetimes import TOMBSTONE_GRACE_DAYS, lifetime_days
from .retractions import VerifiedRetraction, Withdrawal

#: Most pending tombstones kept per author (the newest-seen are kept).
MAX_PENDING_PER_AUTHOR = 100
_DAY_SECONDS = 86_400


def applicable_withdrawals(retractions: Iterable[VerifiedRetraction], reports: Iterable[VerifiedReport],
                           first_seen: Mapping[str, float], now: float) -> tuple[frozenset[Withdrawal], int]:
    """(withdrawals to apply, number of pending tombstones kept).

    A retraction whose target report is present applies. One whose target is
    absent is PENDING: kept while younger than its target's lifetime + 7 days
    (reader-observed), at most :data:`MAX_PENDING_PER_AUTHOR` per author;
    older or excess ones are forgotten.
    """
    present = {(report.author, report.identifier) for report in reports}
    applicable = set()
    pending: dict[str, list[tuple[float, Withdrawal]]] = {}
    for retraction in retractions:
        withdrawal = (retraction.author, retraction.identifier)
        if withdrawal in present:
            applicable.add(withdrawal)
            continue
        seen_at = first_seen.get(retraction.subject, now)
        if now - seen_at <= (lifetime_days(retraction.identifier) + TOMBSTONE_GRACE_DAYS) * _DAY_SECONDS:
            pending.setdefault(retraction.author, []).append((seen_at, withdrawal))
    kept = 0
    for dated in pending.values():
        dated.sort(reverse=True)
        newest = dated[:MAX_PENDING_PER_AUTHOR]
        applicable.update(withdrawal for _, withdrawal in newest)
        kept += len(newest)
    return frozenset(applicable), kept
