"""PARTNER organisations: grants, partner reputation, suspension, sponsorship (R4, plan §05).

A partner is an organisation, not a key: all of its keys share ONE cluster
(``"2 PARTNER"`` means two organisations), its weight is 1.0 × the
organisation's reputation so rejections bite, two rejections in 30 days
suspend the grant pending curator review, and every grant is per key and
expires within :data:`GRANT_MAX_DAYS`. An organisation may SPONSOR its own
new nodes: they weigh ≤ 0.5 and share the organisation's strikes.

Pure functions over frozen grants; the ledger holds the outcomes.

Usage::

    grant = PartnerGrant(org="acme", key="…", granted_day="2026-10-02", expires_day="2027-10-02")
    partner_weight(grant, reputation=0.9, rejections_last_30d=1, today="2026-10-10")   # 0.9
    partner_weight(grant, reputation=0.9, rejections_last_30d=2, today="2026-10-10")   # 0.0 (suspended)
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta
from typing import Iterable

from .bands import SPONSOR_WEIGHT_CAP

#: Grants expire within twelve months of being granted.
GRANT_MAX_DAYS = 365
#: Two rejections inside this window suspend the grant pending review.
SUSPENSION_REJECTIONS = 2
SUSPENSION_WINDOW_DAYS = 30


@dataclass(frozen=True)
class PartnerGrant:
    """One organisation's grant for one key: ``org`` (lower-case slug —
    the cluster), ``key`` (reporter key hex), ``granted_day`` / ``expires_day``
    (UTC days), ``sponsored`` — a node the organisation vouches for rather
    than operates (weight ≤ 0.5, shared strikes)."""

    org: str
    key: str
    granted_day: str
    expires_day: str
    sponsored: bool = False

    def valid(self, today: str) -> bool:
        """In force today: not expired, and never longer than GRANT_MAX_DAYS."""
        try:
            granted, expires = date.fromisoformat(self.granted_day), date.fromisoformat(self.expires_day)
        except ValueError:
            return False
        cap = granted + timedelta(days=GRANT_MAX_DAYS)
        return today < min(expires, cap).isoformat()


def partner_weight(grant: PartnerGrant, reputation: float, rejections_last_30d: int, today: str) -> float:
    """The weight this key lends its organisation's cluster: 0 when the grant
    is invalid or suspended; ≤ 0.5 × reputation for a sponsored node; else
    1.0 × the organisation's reputation."""
    if not grant.valid(today) or rejections_last_30d >= SUSPENSION_REJECTIONS:
        return 0.0
    base = min(1.0, max(0.0, reputation))
    return min(SPONSOR_WEIGHT_CAP, base * SPONSOR_WEIGHT_CAP) if grant.sponsored else base


def org_clusters(grants: Iterable[PartnerGrant], today: str) -> dict[str, tuple[str, ...]]:
    """``{org: (keys…)}`` for the grants in force today — however many keys
    an organisation runs, it is one cluster."""
    clusters: dict[str, list] = {}
    for grant in grants:
        if grant.valid(today):
            clusters.setdefault(grant.org, []).append(grant.key)
    return {org: tuple(sorted(keys)) for org, keys in clusters.items()}
