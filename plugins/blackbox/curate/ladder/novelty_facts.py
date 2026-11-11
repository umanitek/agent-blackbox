"""Gathering the facts the novelty rule judges (Community Curation C6).

``community.reputation.novelty_credit`` is a pure judge; it needs facts. Until
now a curator had to establish them by hand, so the rule never ran outside its
unit tests (KI-253). This module gathers what the PUBLIC record can establish,
the same way on every curator node:

* ``first_cluster`` — the reporter's report carries the earliest signed day of
  any report of that threat (reports are dated by day, so reporters who share
  the earliest day are all first);
* ``absent_everywhere`` — the threat was not already in the verified tier and,
  for a dependency, the public advisory database does not already list it
  (front-running a feed earns nothing);
* ``corroborated_in_the_wild`` — a counted reporter from ANOTHER cluster also
  reported it;
* ``publisher`` — for a dependency, its ecosystem and package name (the
  closest public stand-in for "the upstream publisher"); at most one novelty
  credit is ever granted per publisher.

What the public record cannot establish is left unknown and judged as such:
the artifact's publication time (the self-dealing window) needs registry
metadata this build does not fetch.

Usage::

    facts = gather(report, same_threat_reports, counted=view.counted, verified=verified_ids,
                   osv_lookup=osv.lookup, publisher_credits=ledger.publisher_credits)
    reputation.novelty_credit(facts).credit
"""

from __future__ import annotations

from typing import AbstractSet, Any, Callable, Iterable, Mapping, Optional

from ...community import reputation
from ...kernel import threat_ids

OsvLookup = Callable[[str, str, str], Optional[Mapping[str, str]]]


def dependency_parts(identifier: str) -> Optional[tuple[str, str, str]]:
    """``(ecosystem, name, version)`` of a ``dep:eco:name@version`` identifier, else None."""
    return threat_ids.parse_dependency_identifier(identifier)


def _cluster(author: str, counted: Mapping[str, Any]) -> str:
    """The cluster a reporter key counts in: its organisation when listed with one, else itself."""
    entry = counted.get(author)
    return (getattr(entry, "org", "") or author) if entry is not None else author


def gather(report: Any, same_threat: Iterable[Any], *, counted: Mapping[str, Any], verified: AbstractSet[str],
           osv_lookup: Optional[OsvLookup], publisher_credits: Callable[[str], int]) -> reputation.NoveltyFacts:
    """The novelty facts for one verified *report*, given every verified report
    of the same threat (*same_threat*), the counted authors, the verified
    tier's identifiers and an advisory lookup."""
    others = [other for other in same_threat if other.author != report.author]
    earliest = min([report.day, *(other.day for other in others)])
    mine = _cluster(report.author, counted)
    corroborated = any(other.author in counted and _cluster(other.author, counted) != mine for other in others)
    parts = dependency_parts(report.identifier)
    known_to_a_feed = False
    if parts is not None and osv_lookup is not None:
        try:
            known_to_a_feed = osv_lookup(*parts) is not None
        except Exception:   # a failed lookup proves nothing: no credit is granted on an unknown
            known_to_a_feed = True
    publisher = f"{parts[0]}:{parts[1]}" if parts is not None else ""
    return reputation.NoveltyFacts(
        first_cluster=report.day == earliest,
        absent_everywhere=report.identifier not in verified and not known_to_a_feed,
        corroborated_in_the_wild=corroborated,
        publisher=publisher,
        publisher_credits_used=publisher_credits(publisher) if publisher else 0,
        artifact_age_hours=None,
    )
