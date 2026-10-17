"""How a promotion reaches Verified Memory — one Strategy per way (the one-graph flow).

A promotion is the verified authority's two-key decision about ONE community
report, read from the graph's shared memory. Whatever the way, its payload
names that report — subject, digest, reporter key
(``kernel.signing.promotion_statement``) — and every key re-reads it on its
own node before signing (``promotion.checked_report``). The ways differ in what
is signed and what is published:

* :data:`MEMBER_ASSET` — the default. The curators sign a pointer
  (``promotion_statement.promotion_payload``) and publish the reporter's own
  asset from shared memory as it is, natively (``node_writers.NodeReportWriter``;
  in a batch, ``reports.ReportPublisher``), then the pointer beside it;
  readers serve it (``ruleset/live/promoted.py``). A curator node publishes a
  member's asset from DKG 10.0.25 on: the share carries its author's seal, which
  the graph's curator node keeps (OriginTrail/dkg#3307, fixing #3294). A report
  shared from an older node carries none: its publish is refused, nothing is
  paid, and the promotion waits for a keep-alive copy from an updated node.
* :data:`CURATOR_ASSET` — the copy, for a curator node older than DKG 10.0.25,
  which refuses to publish a member's asset (409: it never holds the member's
  seal). The curators sign the verified rule made from the report
  (``row_builders``: identifier, severity, kind, package fields, and the report
  as its provenance) and publish it as their OWN asset in the graph's Verified
  Memory, which the readers' envelope tier serves
  (``ruleset/live/envelope_tier.py``).

:func:`active` is the one place that picks the way NEW promotions take, by the
DKG version of the node the proposing curator works through
(:data:`NATIVE_PROMOTION_DKG`); a signed promotion is published the way its
own payload says (:func:`strategy_for`), whichever way that node would pick.

Pattern: Strategy — two classes behind :class:`PromotionStrategy`, chosen by
payload shape.

Usage::

    payload = strategies.active(ctx.dkg_version).payload(report, severity="critical", advisory="MAL-2026-1",
                                                         display_name="")
    strategy = strategies.strategy_for(envelope)       # None: not a promotion of a report
    name, quads = strategy.asset(envelope, evidence)   # the curators' own asset
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from types import MappingProxyType
from typing import Mapping, Optional, Protocol

from ... import community
from ...kernel import constants, rdf_terms, signing, threat_ids
from ...kernel.signing import promotion_statement as statement
from .. import promotion
from ..proposal import Proposal
from . import row_builders

CURATOR_ASSET = "curator-asset"
MEMBER_ASSET = "member-asset"
#: The first DKG release whose curator node publishes a member's own asset: from it on, a
#: share carries its author's seal (OriginTrail/dkg#3307). An older node takes the copy.
NATIVE_PROMOTION_DKG = (10, 0, 25)
#: The verified rule's kind per promoted category: a dependency report signs its
#: own (malware, the only one promoted); the others carry none.
_RULE_KINDS = MappingProxyType({"ioc": constants.KIND_MALWARE, "skill": constants.KIND_MALWARE,
                                "fileaccess": "exfiltration"})


class PromotionStrategy(Protocol):
    """One way a promotion reaches Verified Memory. ``publishes_report`` —
    True when the reporter's own asset is published before the curators'."""

    name: str
    publishes_report: bool

    def payload(self, report: community.VerifiedReport, *, severity: str, advisory: str,
                display_name: str) -> dict[str, str]:
        """What the curators sign to promote *report* (*advisory* — an advisory
        id or ""; *display_name* — "" for the default); raises ``promotion.PromotionError``."""
        ...

    def reference(self, envelope: Optional[signing.SignedEnvelope]) -> Optional[statement.ReportRef]:
        """The report *envelope* names when it is a promotion of this way, else None."""
        ...

    def asset(self, envelope: signing.SignedEnvelope, evidence: str) -> tuple[str, list[rdf_terms.Quad]]:
        """``(asset name, quads)`` of the curators' own asset for *envelope*;
        raises ``ValueError`` when it cannot be written."""
        ...


class CuratorAsset:
    """The curators' own verified-rule asset, made from the report (the default)."""

    name = CURATOR_ASSET
    publishes_report = False

    def payload(self, report: community.VerifiedReport, *, severity: str, advisory: str,
                display_name: str) -> dict[str, str]:
        ref = promotion.report_reference(report)
        category = report.identifier.split(":", 1)[0]
        kind = dict(report.fields).get("kind", "") if category == "dep" else _RULE_KINDS.get(category, "")
        try:
            entry = row_builders.ConfirmedEntry(report.identifier, severity.strip().lower(), kind, ref,
                                                name=display_name or _default_name(report.identifier), advisory_id=advisory)
        except row_builders.RowBuildError as exc:
            raise promotion.PromotionError(str(exc)) from exc
        return row_builders.promotion_payload(entry)

    def reference(self, envelope: Optional[signing.SignedEnvelope]) -> Optional[statement.ReportRef]:
        try:
            return signed_entry(envelope).report
        except row_builders.RowBuildError:
            return None

    def asset(self, envelope: signing.SignedEnvelope, evidence: str) -> tuple[str, list[rdf_terms.Quad]]:
        entry = signed_entry(envelope, evidence)
        name = f"threat-{threat_ids.stable_hash(entry.identifier, 16)}-{envelope.sequence}"
        return name, row_builders.ROW_BUILDERS[entry.category].quads(entry, envelope)


class MemberAsset:
    """The reporter's own asset, published as it is, with the curators' pointer beside it."""

    name = MEMBER_ASSET
    publishes_report = True

    def payload(self, report: community.VerifiedReport, *, severity: str, advisory: str,
                display_name: str) -> dict[str, str]:
        ref = promotion.report_reference(report)
        try:
            return statement.promotion_payload(ref.identifier, report=ref.report, report_digest=ref.report_digest,
                                               reporter_key=ref.reporter_key, severity=severity.strip().lower(),
                                               day=datetime.now(UTC).date().isoformat())
        except ValueError as exc:
            raise promotion.PromotionError(str(exc)) from exc

    def reference(self, envelope: Optional[signing.SignedEnvelope]) -> Optional[statement.ReportRef]:
        return statement.parse(envelope)

    def asset(self, envelope: signing.SignedEnvelope, evidence: str) -> tuple[str, list[rdf_terms.Quad]]:
        found = statement.parse(envelope)
        if found is None:
            raise ValueError("not a member-asset promotion")
        return (f"promotion-{threat_ids.stable_hash(found.identifier, 16)}-{found.sequence}",
                statement.statement_quads(envelope))


#: Every way, by name. Frozen: a way is added here, in code review.
STRATEGIES: Mapping[str, PromotionStrategy] = MappingProxyType({
    strategy.name: strategy for strategy in (CuratorAsset(), MemberAsset())
})


def active(dkg_version: str) -> PromotionStrategy:
    """The way new promotions take on a node that runs DKG *dkg_version* (its status's
    ``version``): MEMBER_ASSET from :data:`NATIVE_PROMOTION_DKG` on, CURATOR_ASSET on an
    older node and when the version does not parse (the copy publishes on every release)."""
    return STRATEGIES[MEMBER_ASSET if _release(dkg_version) >= NATIVE_PROMOTION_DKG else CURATOR_ASSET]


def _release(version: str) -> tuple[int, ...]:
    """``10.0.25`` (also ``10.0.25-…``) as ``(10, 0, 25)``; ``(0, 0, 0)`` for anything else."""
    found = re.match(r"(\d+)\.(\d+)\.(\d+)", str(version or "").strip())
    return tuple(int(part) for part in found.groups()) if found else (0, 0, 0)


def strategy_for(envelope: Optional[signing.SignedEnvelope]) -> Optional[PromotionStrategy]:
    """The way a signed promotion is published: the one whose payload shape
    *envelope* has; None when it is a promotion of a report by neither (an
    earlier shape included — it is proposed again from its report)."""
    return next((strategy for strategy in STRATEGIES.values() if strategy.reference(envelope) is not None), None)


def refusal(envelope: Optional[signing.SignedEnvelope]) -> str:
    """Why *envelope* is a promotion of a report by neither way ("" when it is one)."""
    if strategy_for(envelope) is not None:
        return ""
    if envelope is not None and set(envelope.payload) == row_builders.PAYLOAD_KEYS:
        try:
            signed_entry(envelope)
        except row_builders.RowBuildError as exc:
            return str(exc)
    return "the payload is not a well-formed promotion of a report"


def evidence_of(proposal: Proposal) -> str:
    """The keys' item-1 evidence, written beside a curator-asset rule (capped by the row builder)."""
    return "; ".join(proposal.checks[key] for key in sorted(proposal.checks))


def signed_entry(envelope: Optional[signing.SignedEnvelope], evidence: str = "") -> row_builders.ConfirmedEntry:
    """The entry a signed curator-asset promotion names — refused
    (:class:`.row_builders.RowBuildError`) unless its payload is exactly what
    ``row_builders.promotion_payload`` makes of that entry: the closed key
    set, a promotable report of the identifier, package fields that match the
    identifier, a dependency only as malware (KI-195: the second key and the
    publisher check what the first key's client signed)."""
    if envelope is None or envelope.statement_type != row_builders.PROMOTION_STATEMENT:
        raise row_builders.RowBuildError(f"not a {row_builders.PROMOTION_STATEMENT} envelope")
    payload = envelope.payload
    if set(payload) != row_builders.PAYLOAD_KEYS:
        raise row_builders.RowBuildError(f"a curator-asset promotion holds exactly {sorted(row_builders.PAYLOAD_KEYS)}")
    ref = statement.reference(payload)
    if ref is None:
        raise row_builders.RowBuildError(f"the promotion names no report: {statement.reference_refusal(payload)}")
    entry = row_builders.ConfirmedEntry(payload["identifier"], payload["severity"], payload["kind"], ref,
                                        evidence=evidence, name=payload["name"], advisory_id=payload["advisoryId"])
    if row_builders.promotion_payload(entry) != dict(payload):
        raise row_builders.RowBuildError("the signed payload's package fields or name do not match its identifier")
    return entry


def _default_name(identifier: str) -> str:
    """A dependency's name as promotions have always written it; else the identifier."""
    parts = threat_ids.parse_dependency_identifier(identifier)
    if parts is None:
        return identifier
    ecosystem, package, version = parts
    return f"{package}@{version} (malicious {ecosystem} package)"
