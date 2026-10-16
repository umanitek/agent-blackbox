"""Crediting reporters from the public record (Community Curation C6).

When the acting authority's verdict on a threat is published — a confirmation
or a rejection — every reporter of that threat is credited with the outcome in
this curator node's PRIVATE ledger, once (``ReputationLedger.record_once``).
A confirmed report that the novelty rule accepts earns the credit that counts
toward graduation.

Nothing here needs the machine that published the verdict: it reads the
community graph's verified reports and the authority's current verdicts, so
ANY curator node can run :func:`credit_verdicts` over the whole record, on
every beat, and reach the same ledger. That is what lets a second curator
check a graduation against its own numbers before co-signing it.

:func:`sync_bands` keeps the ledger's bands in step with the PUBLISHED
trusted-reporter list: a band changes when a listing or delisting is
published, never when it is merely proposed (KI-255).

Strikes are not derivable from the public record (bad faith is a human
judgement) and stay a manual command.

Pattern: Observer on publish + an idempotent sync.

Usage::

    report = outcomes.credit_verdicts(ctx)                # CreditReport(credited=3, novel=1, available=True)
    outcomes.sync_bands(ctx.own_view, ledger, today)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, replace
from datetime import datetime, timezone, UTC
from typing import Any, Dict, Iterable, List, Optional

from ... import community
from ...community import reputation
from ...detection import osv
from ...kernel.signing.authority import Authority
from ...kernel.signing.statement_order import CuratorStatement
from ..context import CurateContext, verified_identifiers
from . import novelty_facts

logger = logging.getLogger(__name__)

_CREDITING = (CuratorStatement.CONFIRMATION, CuratorStatement.REJECTION)


@dataclass(frozen=True)
class CreditReport:
    """What one sync did: how many (reporter, threat) outcomes were newly
    ``credited``, how many of them were ``novel`` credits, and whether the
    community graph could be read (``available``)."""

    credited: int = 0
    novel: int = 0
    available: bool = True


def _today() -> str:
    return datetime.now(UTC).date().isoformat()


def credit_verdicts(ctx: CurateContext, *, osv_lookup: Optional[novelty_facts.OsvLookup] = None,
                    ledger: Optional[reputation.ReputationLedger] = None, also: Iterable[str] = ()) -> CreditReport:
    """Credit every reporter of every threat the acting authority has confirmed
    or rejected — idempotent, so it is safe on every beat and on every curator
    node. Also brings the ledger's bands in step with the published list.
    *osv_lookup* — the public advisory lookup used to refuse front-running
    (default: ``detection.osv.lookup``). *also* — identifiers to look the
    curators' statements up for besides the reporters and threats in the graph
    (the statement just published, whose reporter may not have reported yet)."""
    osv_lookup = osv_lookup or osv.lookup
    rows = community.fetch_community_report_rows(ctx.client, ctx.cfg)
    if rows is None:
        return CreditReport(available=False)
    reports, _ = community.verify_report_rows(rows, community.ReportVerifier(ctx.environment, ctx.verified_graph))
    by_threat: dict[str, list[Any]] = {}
    first_day: dict[str, str] = {}
    for report in reports:
        by_threat.setdefault(report.identifier, []).append(report)
        first_day[report.author] = min(first_day.get(report.author, report.day), report.day)
    book = ledger or reputation.ReputationLedger()
    interest = [*also, *by_threat, *(f"author:{author}" for author in first_day), *(f"author:{key}" for key in book.keys())]
    view = community.read_curator_view(ctx.client, ctx.cfg, ctx.environment, interest=interest)
    own = view.community if ctx.authority is Authority.COMMUNITY else view
    if own is None or view.unavailable:
        return CreditReport(available=False)
    verified = verified_identifiers(ctx.compiled, by_threat)
    credited = novel = 0
    for identifier, record in own.verdicts.items():
        if record.kind not in _CREDITING:
            continue
        confirmed = record.kind is CuratorStatement.CONFIRMATION
        same_threat = by_threat.get(identifier, [])
        for report in same_threat:
            facts = novelty_facts.gather(report, same_threat, counted=view.counted, verified=verified,
                                         osv_lookup=osv_lookup, publisher_credits=book.publisher_credits)
            earns = confirmed and reputation.novelty_credit(facts).credit is reputation.NoveltyCredit.CREDIT
            if book.record_once(report.author, reputation.Outcome(record.day, confirmed), threat=identifier,
                                novel=earns, first_seen_day=first_day[report.author],
                                publisher=facts.publisher if earns else ""):
                credited += 1
                novel += 1 if earns else 0
    sync_bands(own, book, _today())
    if credited:
        logger.info("blackbox: credited %d reporter outcome(s) from published verdicts (%d novel)", credited, novel)
    return CreditReport(credited=credited, novel=novel)


def sync_bands(own_view: Any, ledger: reputation.ReputationLedger, today: str) -> int:
    """Make the ledger's bands match the acting authority's PUBLISHED list:
    a listed key takes its listed class (and organisation); an explicitly
    delisted key that the ledger still holds above probation is demoted with
    its lockout. Returns how many standings changed."""
    changed = 0
    for key, entry in own_view.counted.items():
        standing = ledger.standing(key)
        band = reputation.ReputationBand.PARTNER if entry.author_class == "partner" else reputation.ReputationBand.ESTABLISHED
        if standing.band is not band or standing.org != entry.org:
            ledger.set_standing(replace(standing, band=band, org=entry.org, first_seen_day=standing.first_seen_day or today))
            changed += 1
    for key in own_view.delisted:
        standing = ledger.standing(key)
        if standing.band is not reputation.ReputationBand.PROBATION:
            demoted = reputation.demotion(standing, ledger.reputation(key, today), today)
            ledger.set_standing(demoted if demoted is not None else replace(standing, band=reputation.ReputationBand.PROBATION))
            changed += 1
    return changed


def overlap_rings(ctx: CurateContext) -> list[frozenset]:
    """Groups of reporter keys whose reports overlap almost entirely — likely
    one operator behind several keys (``community.reputation.rings``). A
    DETECTOR for the curator's eyes: nothing is collapsed until a curator
    lists the keys under one cluster. Empty when the graph cannot be read."""
    rows = community.fetch_community_report_rows(ctx.client, ctx.cfg)
    if rows is None:
        return []
    reports, _ = community.verify_report_rows(rows, community.ReportVerifier(ctx.environment, ctx.verified_graph))
    by_key: dict[str, set] = {}
    for report in reports:
        by_key.setdefault(report.author, set()).add(report.identifier)
    return reputation.rings(by_key)
