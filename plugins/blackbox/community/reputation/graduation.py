"""Automated graduation and demotion → counted-author statements (R4).

The reputation machinery never changes a reader directly: a reporter moves
stages only through the curator's 2-of-3 counted-author list. This module
turns a standing into the ``COUNTED_AUTHORS`` payload the curate verbs sign
(``curate propose --nominate``): a graduation lists the key as ESTABLISHED
for twelve months; a demotion delists it (the denylist); a partner grant
lists it as PARTNER under its organisation; a collapse puts established keys
under one shared ``org`` so every reader counts them once.

Usage::

    fields = nomination_fields(standing, address="0x…", today="2026-10-02")   # or None when nothing changes
    verbs.propose_statement(ctx, store, kind=CuratorStatement.COUNTED_AUTHORS,
                            identifier=f"author:{standing.key}", fields=fields)
"""

from __future__ import annotations

from datetime import date, timedelta
from typing import Optional

from .bands import ReporterStanding, ReputationBand
from .scoring import demotion, graduates

#: A listing (graduation or partner grant) runs this long before it must be renewed.
LISTING_DAYS = 365


def _listing(standing: ReporterStanding, address: str, author_class: str, org: str, today: str,
             days: int = LISTING_DAYS) -> dict[str, str]:
    expires = (date.fromisoformat(today) + timedelta(days=days)).isoformat()
    return {"listed": "yes", "class": author_class, "org": org, "expires": expires, "address": address.lower()}


def _delisting(address: str, today: str) -> dict[str, str]:
    return {"listed": "no", "class": "established", "org": "", "expires": today, "address": address.lower()}


def renewal_fields(standing: ReporterStanding, *, address: str, today: str,
                   listing_days: int = LISTING_DAYS) -> dict[str, str]:
    """The counted-author payload that renews a plain ESTABLISHED listing in
    good standing for another term (no organisation, no cluster — renewing a
    partner or a collapsed group is a person's decision)."""
    return _listing(standing, address, "established", "", today, listing_days)


def nomination_fields(standing: ReporterStanding, *, address: str, today: str,
                      reputation: Optional[float] = None, cluster: str = "",
                      listing_days: int = LISTING_DAYS) -> Optional[dict[str, str]]:
    """The counted-author payload a standing calls for today, or None.

    * PROBATION that :func:`graduates` → listed ESTABLISHED (``org`` = the
      collapse *cluster* when the curator assigned one, so readers count a
      collapsed group once).
    * ESTABLISHED / PARTNER that :func:`demotion` demotes (given *reputation*)
      → delisted.
    * PARTNER in good standing → listed PARTNER under its organisation.
    """
    if standing.band is ReputationBand.PROBATION:
        return _listing(standing, address, "established", cluster, today, listing_days) if graduates(standing, today) else None
    if reputation is not None and demotion(standing, reputation, today) is not None:
        return _delisting(address, today)
    if standing.band is ReputationBand.PARTNER and standing.org:
        return _listing(standing, address, "partner", standing.org, today, listing_days)
    if cluster:
        return _listing(standing, address, "established", cluster, today, listing_days)
    return None
