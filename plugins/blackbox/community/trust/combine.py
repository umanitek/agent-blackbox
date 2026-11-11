"""Two authorities' views in, the one view readers act on out (Community Curation).

Each authority's statements are verified against its OWN manifest and ordered
in its OWN sequence (``statements.curator_view.build_view``), so a statement
from one authority can never outnumber a statement from the other. This module
is the only place the two meet, and the rule is one line:

    between the two authorities, the MOST RESTRICTIVE current word wins.

* Counted authors — listed by either authority, unless either delisted them.
  When both list a reporter, the verified authority's entry is the one shown.
* Verdict per threat — a terminal verdict (rejection, revocation) from either
  wins; else a deferral still inside its 30 days from either; else a
  confirmation from either; else a notice. The verified authority's record
  wins a tie.
* Stage attestation per threat — the one that enforces less.
* Pause — in force when either authority's pause is.
* ``unavailable`` — when either read failed (readers keep last good).

The result's ``manifest`` and health fields stay the VERIFIED authority's
(the kill list and verified rules depend on them); the community authority's
own view rides along as ``view.community`` for health, the dashboard and the
curators' tooling.

Pattern: pure function over two Value Objects.

Usage::

    view = combine(verified_view, community_view, today="2026-10-03")
    view.is_counted(key); view.verdict(identifier); view.community.manifest
"""

from __future__ import annotations

from dataclasses import replace
from datetime import date
from typing import Dict, Optional

from ...kernel.signing import CuratorStatement, statement_order
from ..statements.curator_statements import CuratorRecord
from ..statements.curator_view import STAGE_ENFORCEMENT_RANK, CountedAuthor, CuratorView

#: A curator DEFERRAL holds a threat down for this many days after its signed
#: day (plan §12 clocks; the stage machine applies the same clock).
DEFERRAL_HOLD_DAYS = statement_order.DEFERRAL_LAPSE_DAYS   # one clock for readers and curators


def combine(verified: CuratorView, community: CuratorView, *, today: str) -> CuratorView:
    """The view readers act on: *verified* with the community authority's
    statements merged in under the most-restrictive-wins rule."""
    delisted = verified.delisted | community.delisted
    counted: dict[str, CountedAuthor] = {**community.counted, **verified.counted}
    for key in delisted:
        counted.pop(key, None)
    return replace(
        verified,
        counted=counted,
        delisted=delisted,
        verdicts=_verdicts(verified, community, today),
        attestations=_attestations(verified, community),
        pause_until=max(verified.pause_until, community.pause_until),
        unavailable=verified.unavailable or community.unavailable,
        community=community,
    )


def _holds_down(record: CuratorRecord, today: str) -> int:
    """How much *record* decides about its threat today, for choosing between
    the two authorities: a terminal verdict (3) > a deferral inside its 30 days
    (2) > a confirmation (1) > a notice (0 — in-review, deferral-lapsed, or a
    deferral past its 30 days: an acknowledgement, not a decision, so it never
    cancels the other authority's confirmation)."""
    if record.kind.terminal:
        return 3
    if record.kind is CuratorStatement.DEFERRAL and statement_order.deferral_in_force(_days_since(record.day, today)):
        return 2
    return 1 if record.kind is CuratorStatement.CONFIRMATION else 0


def _days_since(day: str, today: str) -> int:
    try:
        return (date.fromisoformat(today) - date.fromisoformat(day)).days
    except ValueError:
        return 0   # an unreadable day never ends a hold early


def _verdicts(verified: CuratorView, community: CuratorView, today: str) -> dict[str, CuratorRecord]:
    merged: dict[str, CuratorRecord] = dict(community.verdicts)
    for identifier, record in verified.verdicts.items():
        other: Optional[CuratorRecord] = merged.get(identifier)
        if other is None or _holds_down(record, today) >= _holds_down(other, today):
            merged[identifier] = record   # the verified authority wins a tie
    return merged


def _attestations(verified: CuratorView, community: CuratorView) -> dict[str, CuratorRecord]:
    merged: dict[str, CuratorRecord] = dict(community.attestations)
    for identifier, record in verified.attestations.items():
        other = merged.get(identifier)
        if other is None or _enforces(record) <= _enforces(other):
            merged[identifier] = record   # the verified authority wins a tie
    return merged


def _enforces(record: CuratorRecord) -> int:
    return STAGE_ENFORCEMENT_RANK.get(record.field("stage"), 0)
