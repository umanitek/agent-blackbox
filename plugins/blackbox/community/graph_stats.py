"""Statistics over the community's reports — the dashboard's read model.

Pure functions over VERIFIED reports (:func:`.reader.read_verified_reports`):
how many distinct agents have reported, what each reporting agent contributed
(the "Community graph — connected agents" section), and which threats the most
distinct agents reported. Every count keys on the report's verified SIGNER
(``VerifiedReport.author``), never on the self-described ``g:reporter``
string, which is display-only (LES-014, KI-067/110) — so one node posing as
ten addresses is one agent here, exactly as in the ruleset.

The dashboard owns HTTP, caching and sanitization; strings returned here are
unsanitized community data that the caller escapes.

Usage (through the package)::

    from .. import community
    reports = community.read_verified_reports(client, cfg) or []
    count = community.contributing_agent_count(reports)
    agents = community.community_agents(reports, own_author)
    threats = community.most_reported_threats(reports, limit=50)
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Sequence, Set, TypedDict

from ..kernel import constants
from .verification import VerifiedReport


class CommunityAgent(TypedDict):
    """One signer among the community's reports and what it reported.

    ``author`` — the verified signer key (the identity); ``address`` — the
    reporter address it most often claims (display only); ``frameworks`` —
    sorted, distinct; ``reports`` — report subjects it signed; ``is_self`` —
    the signer is this node's own reporter key.
    """

    author: str
    address: str
    frameworks: list[str]
    reports: int
    is_self: bool


class ReportedThreat(TypedDict):
    """One threat identifier and how many distinct signers reported it.

    ``matched_by`` — how the reporters' nodes matched it (``verified`` /
    ``built-in`` / ``advisory``), sorted, distinct; ``blackbox_versions`` —
    the releases that built those reports, sorted, distinct. A report signed
    before these fields existed adds nothing to either list (§03.6).
    """

    identifier: str
    reporters: int
    severity: str   # the highest severity any verified report gave it
    matched_by: list[str]
    blackbox_versions: list[str]


def contributing_agent_count(reports: Iterable[VerifiedReport]) -> int:
    """Distinct verified signers across all reports."""
    return len({report.author for report in reports})


@dataclass
class _SignerTally:
    """What one signer contributed, accumulated while folding reports."""

    addresses: Counter[str] = field(default_factory=Counter)
    frameworks: set[str] = field(default_factory=set)
    subjects: set[str] = field(default_factory=set)


def community_agents(reports: Iterable[VerifiedReport], own_author: str = "") -> list[CommunityAgent]:
    """One entry per verified signer.

    Ordered: this node first, then most reports, then signer key — stable
    across refreshes so the section does not reshuffle on every poll.
    """
    tallies: dict[str, _SignerTally] = {}
    for report in reports:
        tally = tallies.setdefault(report.author, _SignerTally())
        tally.addresses[report.reporter] += 1
        if report.framework:
            tally.frameworks.add(report.framework.lower())
        tally.subjects.add(report.subject)
    agents: list[CommunityAgent] = [
        {
            "author": author,
            "address": tally.addresses.most_common(1)[0][0],
            "frameworks": sorted(tally.frameworks),
            "reports": len(tally.subjects),
            "is_self": bool(own_author) and author == own_author,
        }
        for author, tally in tallies.items()
    ]
    return sorted(agents, key=lambda a: (not a["is_self"], -a["reports"], a["author"]))


def most_reported_threats(reports: Sequence[VerifiedReport], limit: int) -> list[ReportedThreat]:
    """The *limit* threats with the most distinct verified signers."""
    authors: dict[str, set[str]] = {}
    severity: dict[str, str] = {}
    matched_by: dict[str, set[str]] = {}
    versions: dict[str, set[str]] = {}
    for report in reports:
        authors.setdefault(report.identifier, set()).add(report.author)
        fields = dict(report.fields)
        matched_by.setdefault(report.identifier, set()).update(filter(None, [fields.get("matchedBy")]))
        versions.setdefault(report.identifier, set()).update(filter(None, [fields.get("blackboxVersion")]))
        current = severity.get(report.identifier, "info")
        if constants.SEVERITY_RANK.get(report.severity, 0) > constants.SEVERITY_RANK.get(current, 0):
            current = report.severity
        severity[report.identifier] = current
    ranked = sorted(authors, key=lambda ident: (-len(authors[ident]), ident))[: max(0, int(limit))]
    return [{"identifier": ident, "reporters": len(authors[ident]), "severity": severity[ident],
             "matched_by": sorted(matched_by[ident]), "blackbox_versions": sorted(versions[ident])}
            for ident in ranked]


def reports_signed_by(reports: Iterable[VerifiedReport], author: str) -> int:
    """How many report subjects *author* signed (``blackbox report --status``)."""
    if not author:
        return 0
    return len({report.subject for report in reports if report.author == author})
