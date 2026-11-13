"""Reading sighting digests and estimating heat (Refine R2b).

A digest (:mod:`..digest`) says which VERIFIED threats one reporter met in one
ISO week, as buckets. This module verifies digests (signed ``blackbox.digest``
for this network and graph; the subject is the signer's own (reporter, week)
subject; entries well-formed) and turns them into a per-threat HEAT estimate:
the sum of bucket midpoints over COUNTED authors (plan §05). Rules:

* counted authors only — a digest from an unlisted author is kept for display
  ("new reporter") and weighs 0;
* at most one digest per author per week — the first this node observed
  wins, later ones for the same week are ignored and logged (an author
  cannot inflate heat by publishing twice);
* a digest is one statement against the per-author budget (the reader
  applies the budget before calling :func:`heat_for_week`).

Usage (from the reader)::

    found = digests.verified_digests(rows, environment, graph)
    heat = digests.heat_for_week(found, view, first_seen, week)
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import date
from typing import Any, Iterable, Mapping, Optional

from ...kernel import sparql_text
from ...kernel import threat_ids
from ...kernel.health import today_utc
from ..digest import DigestEntry, digest_subject, iso_week, parse_entries
from ..report_signer import DIGEST_STATEMENT
from ..verification import shown_as_signed, signed_by, verified_rows
from .curator_view import CuratorView


logger = logging.getLogger(__name__)

_PAGE_SIZE = 5000


@dataclass(frozen=True)
class VerifiedDigest:
    """One verified digest: ``subject``, ``author`` (signer key — the identity),
    ``reporter`` (claimed address, display), ``week`` (ISO), ``entries``."""

    subject: str
    author: str
    reporter: str
    week: str
    entries: tuple[DigestEntry, ...]


@dataclass(frozen=True)
class HeatEstimate:
    """How many agents met one threat in one week, estimated from counted
    digests: ``agents`` = Σ bucket midpoints, over ``digests`` digests."""

    identifier: str
    week: str
    agents: int
    digests: int


def digests_sparql(after: str) -> str:
    """One page of SightingDigest rows after the subject cursor *after*."""
    cursor = sparql_text.cursor_filter(after)
    return f"""
{sparql_text.GUARDIAN_PREFIX}
SELECT ?r ?reporter ?isoWeek ?signedStatement WHERE {{
  ?r a g:SightingDigest ;
     g:reporter ?reporter ;
     g:isoWeek ?isoWeek .
  OPTIONAL {{ ?r g:signedStatement ?signedStatement }}
  {cursor}
}} ORDER BY STR(?r) LIMIT {_PAGE_SIZE}
"""


#: An ISO week as :func:`..digest.iso_week` writes it: ``2026-W40`` (weeks 01-53).
_ISO_WEEK = re.compile(r"\d{4}-W(?:0[1-9]|[1-4]\d|5[0-3])")


def _week_is_readable(week: str) -> bool:
    """Whether a digest's signed ``week`` is an ISO week no later than this reader's own.

    Heat is shown for :func:`latest_week`, the maximum over every admitted digest — so one
    self-signed digest for a far-future (or malformed, higher-sorting) week moved everyone's
    "latest" to a week no real digest covers and emptied the heat map (KI-498). Weeks are
    fixed-width, so text order is date order."""
    if not isinstance(week, str) or not _ISO_WEEK.fullmatch(week):
        return False
    return week <= iso_week(date.fromisoformat(today_utc()))


def _verified(row: Mapping[str, Any], environment: str, graph: str) -> Optional[VerifiedDigest]:
    signed = signed_by(row, DIGEST_STATEMENT, environment, graph)
    if signed is None:
        return None
    author, payload = signed
    reporter, week = payload.get("reporter", ""), payload.get("week", "")
    entries = parse_entries(payload.get("entries", ""))
    if not threat_ids.is_agent_address(reporter) or not _week_is_readable(week) or entries is None:
        return None
    subject = digest_subject(reporter, week)
    if payload.get("subject") != subject or not shown_as_signed(row, {"r": subject, "reporter": reporter, "isoWeek": week}):
        return None
    return VerifiedDigest(subject=subject, author=author, reporter=reporter, week=week, entries=entries)


def verified_digests(rows: Iterable[Mapping[str, Any]], environment: str, graph: str) -> list[VerifiedDigest]:
    """Every digest row that verifies; the rest are dropped and counted in the log."""
    return verified_rows(rows, lambda row: _verified(row, environment, graph), "digest")[0]


def one_per_author_week(digests: Iterable[VerifiedDigest], first_seen: Mapping[str, float]) -> list[VerifiedDigest]:
    """At most one digest per (author, week): the first this node observed."""
    chosen: dict[tuple[str, str], VerifiedDigest] = {}
    ignored = 0
    for digest in sorted(digests, key=lambda d: (first_seen.get(d.subject, float("inf")), d.subject)):
        if chosen.setdefault((digest.author, digest.week), digest) is not digest:
            ignored += 1
    if ignored:
        logger.warning("blackbox: %d duplicate sighting digest(s) for an author's week ignored", ignored)
    return list(chosen.values())


def latest_week(digests: Iterable[VerifiedDigest]) -> str:
    """The most recent ISO week any digest covers ("" when none)."""
    return max((d.week for d in digests), default="")


def heat_for_week(digests: Iterable[VerifiedDigest], view: CuratorView, week: str) -> dict[str, HeatEstimate]:
    """Per threat, the heat estimate for *week* from COUNTED authors' digests
    (already reduced to one per author and week)."""
    agents: dict[str, int] = {}
    count: dict[str, int] = {}
    for digest in digests:
        if digest.week != week or not view.is_counted(digest.author):
            continue
        for entry in digest.entries:
            agents[entry.identifier] = agents.get(entry.identifier, 0) + entry.bucket.midpoint
            count[entry.identifier] = count.get(entry.identifier, 0) + 1
    return {identifier: HeatEstimate(identifier=identifier, week=week, agents=agents[identifier],
                                     digests=count[identifier]) for identifier in agents}
