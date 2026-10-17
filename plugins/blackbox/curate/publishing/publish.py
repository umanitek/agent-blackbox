"""Publishing an APPROVED curator proposal: quorum check, consent, the write, the read-back.

A proposal is written where its kind lives (``CurateContext.home_of``, from
the acting authority's table in ``kernel.signing.authority``): an enforcement
statement is published to the graph's Verified Memory, an advisory one is
shared into its shared memory, beside the community's reports. One graph since
2026-10-16, so the home decides, never the graph id the proposal was signed
for (which must be this node's graph).

"Published" means the statement can be READ BACK from that graph (KI-246): a
node reply that only says "accepted", "already there" or "partly failed" is
not proof. A write that cannot be read back leaves the proposal APPROVED, is
reported as not published, and gives the consent back so the operator can run
`publish` again (KI-249).

Every outward write sits behind content-bound consent and is ledgered.

A revocation or a correction (P5) is published at once, never batched, and
once it reads back the verified authority also posts its ADVISORY TWIN in the
graph's shared memory (:func:`advisory_twin`, D26) so readers' 20 s pulse
withdraws the rule instead of waiting for a full refresh. A correction publishes only
under an EFFECTIVE manifest (:func:`require_effective_manifest`).

A promotion is published the way its payload says (:mod:`.strategies`,
:func:`_write_promotion`): by default (DKG 10.0.25) the reporter's own asset
from shared memory first, then the curators' statement beside it; the copy an
older curator node takes is the curators' own verified-rule asset made from
the report. Every key and the publisher first re-check the report on their
own node (:func:`checked_promotion`); published means everything reads back.

Usage::

    proposal, outcome = publish(ctx, store, proposal_id, typed_code=code, yes=False)
    outcome.startswith("published")      # True only after the read-back

The batch publisher (``batch.py``) writes promotions in batches through the
same node, split into its ledger's steps (``node_writers.NodeBatchWriter``);
:func:`has_quorum` is the quorum check both paths share.
"""

from __future__ import annotations

import logging
from enum import Enum
from typing import Optional

from ... import audit, community, killlist
from ...kernel import constants, node_routes, rdf_terms, signing, sparql_text, threat_ids
from ...kernel.dkg_client import DkgError
from ...kernel.signing import key_manifest
from ...kernel.signing import promotion_statement as statement
from ...kernel.signing.authority import COMMUNITY_GRAPH, VERIFIED_GRAPH
from ...kernel.signing.statement_order import CuratorStatement
from .. import consent, promotion
from ..ladder import outcomes
from ..upkeep import published
from ..context import CORRECTION_STATEMENT, CurateContext
from ..proposal import Proposal, ProposalState, ProposalStore
from . import row_builders, strategies
from .errors import VerbError
from .node_writers import NodeReportWriter, definite_refusal

logger = logging.getLogger(__name__)

MANIFEST_KIND = key_manifest.KEY_MANIFEST_STATEMENT


class PublishOutcome(Enum):
    """What a write achieved, observed by reading it back."""

    PUBLISHED = "published"          # written now, and readable
    ALREADY_THERE = "already-there"  # the node already held it, and it is readable
    UNCONFIRMED = "unconfirmed"      # the node accepted the write but it cannot be read back


def publish(ctx: CurateContext, store: ProposalStore, proposal_id: str, *, typed_code: Optional[str], yes: bool,
            standing: str = "") -> tuple[Proposal, str]:
    """Write an APPROVED proposal to its graph, behind content-bound consent.
    Returns (proposal, what happened); the text starts with "published" only
    when the statement was read back from the graph. *standing* — set ONLY by
    the curator service, after its policy allowed this statement and the
    operator's standing consent was checked (``curate.service``): the policy's
    reason, recorded in the consent ledger in place of a typed code."""
    proposal = store.get(proposal_id)
    if proposal is None or proposal.state is not ProposalState.APPROVED:
        raise VerbError("no APPROVED proposal with that id")
    envelope = proposal.parsed()
    if proposal.kind == CORRECTION_STATEMENT:
        require_effective_manifest(ctx)
    if envelope is None or not has_quorum(ctx, proposal, envelope):
        raise VerbError("the proposal does not carry enough curator signatures to publish")
    ledger = consent.ConsentLedger()
    code = ledger.show(proposal.envelope, summary(proposal))
    ok, why = (ledger.standing(proposal.envelope, standing) if standing
               else ledger.consent(proposal.envelope, typed=typed_code, sandbox=ctx.sandbox, yes=yes))
    if not ok:
        return proposal, f"not published — {why}. Confirmation code: {code}"
    try:
        name, graph, outcome = _write(ctx, proposal, envelope)
    except VerbError:
        ledger.release(proposal.envelope, "the write was refused")
        raise
    except Exception as exc:   # the node refused or failed: nothing was published, the operator may retry
        ledger.release(proposal.envelope, str(exc))
        raise VerbError(f"the write failed, nothing was published: {exc}") from exc
    if outcome is PublishOutcome.UNCONFIRMED:
        ledger.release(proposal.envelope, "written but not readable")
        return proposal, (f"not published — written to {graph} as {name}, but it cannot be read back yet. "
                          f"Run `blackbox curate publish {proposal.id}` again to re-check.")
    audit.record_share_outcome(identifier=proposal.identifier, category=f"curator:{proposal.kind.split('.', 1)[-1]}",
                               severity="info", subject=proposal.id, asset_name=name, ok=True, outcome="accepted")
    store.save(proposal.transition(ProposalState.PUBLISHED, note=f"published to {graph} as {name}"))
    if ctx.home_of(proposal.kind) == COMMUNITY_GRAPH:   # shared memory forgets: this node keeps its statement alive
        published.remember(ctx.cfg, graph=graph, name=name, quads=_asset(proposal, envelope)[1])
    _credit_reporters(ctx, proposal)
    already = " (the node already held it)" if outcome is PublishOutcome.ALREADY_THERE else ""
    twin = f" · {post_advisory_twin(ctx, envelope)}" if proposal.kind in TWINNED_STATEMENTS else ""
    return proposal, f"published to {graph} as {name}{already}{twin}"


def require_effective_manifest(ctx: CurateContext) -> None:
    """Refuse unless the acting authority's trusted manifest is in force: a
    correction signed under none, or under one still inside its
    time-lock, is envelope-less to every reader and ignored."""
    if ctx.manifest is None:
        raise VerbError("no trusted key manifest is in force yet; a correction would be ignored by every reader")
    if ctx.view.manifest_state == "pending":
        raise VerbError(f"the trusted key manifest takes effect on {ctx.view.manifest_state_day}; "
                        "a correction signed before then would be ignored by every reader")


# ---------------------------------------------------------------- the advisory twin (D26)

#: The statements whose advisory twin the verified authority posts in the graph's shared memory.
TWINNED_STATEMENTS = frozenset({CuratorStatement.REVOCATION.value, CORRECTION_STATEMENT})


def advisory_twin(envelope: signing.SignedEnvelope) -> tuple[str, list[dict[str, str]]]:
    """``(asset name, quads)`` of a revocation's or correction's advisory twin:
    the same signed text under a ``g:CuratorStatement`` subject, which changes
    the shared memory's pulse fingerprint (``community.pulse``), so the pulse
    re-applies the curator tier within ~20 s (R4).

    It says nothing by itself: the envelope is bound to the verified graph and
    the subject carries no ``g:identifier``, so every community statement read
    skips it — and, unlike a new verdict, it can never outrank the revocation."""
    if envelope.statement_type not in TWINNED_STATEMENTS:
        raise VerbError(f"only {sorted(TWINNED_STATEMENTS)} have an advisory twin")
    kind, digest = envelope.statement_type.split(".", 1)[1], threat_ids.stable_hash(envelope.to_text(), 24)
    subject = f"urn:guardian:curator:twin:{kind}:{digest}"
    return f"curator-twin-{kind}-{digest[:16]}", [
        rdf_terms.make_quad(subject, constants.RDF_TYPE, rdf_terms.iri(constants.CURATOR_STATEMENT_TYPE_IRI)),
        rdf_terms.make_quad(subject, constants.SIGNED_STATEMENT_PRED, rdf_terms.literal(envelope.to_text())),
    ]


def post_advisory_twin(ctx: CurateContext, envelope: signing.SignedEnvelope) -> str:
    """Share *envelope*'s advisory twin into the graph's shared memory, AFTER
    the Verified Memory asset reads back (the pulse then re-reads Verified
    Memory: a twin that synced first would find nothing). Best effort — readers
    still withdraw the rule on their next full refresh — so it reports, never raises."""
    graph = ctx.verified_graph
    name, quads = advisory_twin(envelope)
    try:
        _share(ctx, graph, name, quads)
    except Exception as exc:
        logger.warning("blackbox: advisory twin %s not posted (%s); readers act on their next full refresh", name, exc)
        return f"advisory twin NOT posted ({exc}); readers act on their next full refresh"
    return f"advisory twin posted to {graph} as {name}"


#: Statements whose publication changes what reporters are credited with, or their band.
_LADDER_KINDS = frozenset({CuratorStatement.CONFIRMATION.value, CuratorStatement.REJECTION.value,
                           CuratorStatement.COUNTED_AUTHORS.value})


def _credit_reporters(ctx: CurateContext, proposal: Proposal) -> None:
    """A published verdict credits the threat's reporters, and a published
    listing moves its reporter's band, in this node's private ledger — at
    once, without anyone typing it (KI-252). Best effort: the ledger can
    always be rebuilt from the public record, so a failure here never undoes
    a publish."""
    if proposal.kind not in _LADDER_KINDS:
        return
    try:
        outcomes.credit_verdicts(ctx, also=[proposal.identifier])
    except Exception as exc:
        logger.warning("blackbox: could not credit reporters after publishing (%s); `curate graduate` re-syncs", exc)


def has_quorum(ctx: CurateContext, proposal: Proposal, envelope: signing.SignedEnvelope) -> bool:
    """True when *envelope* carries the signatures its kind needs under ``ctx.manifest``."""
    if proposal.kind == MANIFEST_KIND:
        return True   # root-signed; verified by readers against the pinned roots
    if ctx.manifest is None:
        return False
    if proposal.kind == killlist.KILL_LIST_STATEMENT:
        return ctx.manifest.has_quorum(envelope, statement_type=killlist.KILL_LIST_STATEMENT, graph=proposal.graph)
    if proposal.kind in (CuratorStatement.PROMOTION.value, CORRECTION_STATEMENT):   # one key per operator, like every reader
        return ctx.manifest.has_quorum(envelope, statement_type=proposal.kind, graph=proposal.graph)
    kind = CuratorStatement(proposal.kind)
    needed = ctx.manifest.threshold if kind.needs_quorum else 1
    return len(ctx.manifest.curator_signers(envelope, statement_type=kind.value, graph=proposal.graph)) >= needed


def _write(ctx: CurateContext, proposal: Proposal, envelope: signing.SignedEnvelope) -> tuple[str, str, PublishOutcome]:
    """Build the quads, write them where the proposal's kind lives (Verified
    Memory or the graph's shared memory) and read them back; (asset name, graph, outcome)."""
    graph, home = proposal.graph, ctx.home_of(proposal.kind)
    if not graph or graph != ctx.verified_graph or home is None:
        raise VerbError(f"the proposal was signed for {graph or 'no graph'}, where this node does not publish "
                        f"{proposal.kind} statements")
    if proposal.kind == CuratorStatement.PROMOTION.value:
        return _write_promotion(ctx, proposal, envelope)
    name, quads = _asset(proposal, envelope)
    if home == VERIFIED_GRAPH:
        node_routes.publish_to_verified_memory(ctx.client, graph, name, quads)
        already, view = False, constants.VIEW_VERIFIABLE_MEMORY
    else:
        already, view = _share(ctx, graph, name, quads), constants.VIEW_SHARED_WORKING_MEMORY
    if not _readable(ctx, graph, view, quads):
        return name, graph, PublishOutcome.UNCONFIRMED
    return name, graph, PublishOutcome.ALREADY_THERE if already else PublishOutcome.PUBLISHED


def _write_promotion(ctx: CurateContext, proposal: Proposal,
                     envelope: signing.SignedEnvelope) -> tuple[str, str, PublishOutcome]:
    """The promotion, the way its payload says: for a member-asset promotion
    the reporter's own asset first (from shared memory, unless Verified Memory
    holds it already), then the curators' own asset. Published means
    everything reads back."""
    strategy, _report = checked_promotion(ctx, envelope)
    ref, graph = strategy.reference(envelope), proposal.graph
    writer = _publish_report(ctx, ref) if strategy.publishes_report else None
    try:
        name, quads = strategy.asset(envelope, strategies.evidence_of(proposal))
    except ValueError as exc:
        raise VerbError(f"the promotion is not acceptable: {exc}") from exc
    already = _readable(ctx, graph, constants.VIEW_VERIFIABLE_MEMORY, quads)
    if not already:
        try:
            node_routes.publish_to_verified_memory(ctx.client, graph, name, quads)
        except DkgError as exc:
            if writer is None:
                raise
            raise VerbError(f"the report is published, its promotion statement is not ({exc}); "
                            "run publish again") from exc
    if not (already or _readable(ctx, graph, constants.VIEW_VERIFIABLE_MEMORY, quads)) or (
            writer is not None and not writer.readable(ref)):
        return name, graph, PublishOutcome.UNCONFIRMED
    return name, graph, PublishOutcome.ALREADY_THERE if already else PublishOutcome.PUBLISHED


def _publish_report(ctx: CurateContext, ref: statement.ReportRef) -> NodeReportWriter:
    """A member-asset promotion's report: its reporter's own asset, published
    from shared memory unless Verified Memory holds it already."""
    writer = NodeReportWriter(ctx.client, ctx.verified_graph)
    asset = writer.locate(ref)
    if asset is None:
        raise VerbError("this node holds no copy of the report the promotion points at with its author's seal "
                        "(a copy shared from a node older than DKG 10.0.25, or one this node only pulled, has "
                        "none); nothing was published")
    if not asset.verified:
        try:
            writer.submit(asset)
        except DkgError as exc:
            raise VerbError(f"the node refused to publish the report ({exc}); nothing was paid" if definite_refusal(exc)
                            else f"the report's publish could not tell whether it was paid ({exc}); "
                                 "it is looked up again before any retry") from exc
    return writer


def checked_promotion(ctx: CurateContext, envelope: Optional[signing.SignedEnvelope]
                      ) -> tuple[strategies.PromotionStrategy, community.VerifiedReport]:
    """The way a promotion is published and the report it names, re-read and
    checked on THIS node (:func:`.promotion.checked_report`, KI-195) —
    refused as a :class:`VerbError`."""
    strategy = strategies.strategy_for(envelope)
    try:
        if strategy is None:
            raise promotion.PromotionError(strategies.refusal(envelope))
        return strategy, promotion.checked_report(ctx, strategy.reference(envelope))
    except promotion.PromotionError as exc:
        raise VerbError(f"the promotion is not acceptable: {exc}") from exc


def _asset(proposal: Proposal, envelope: signing.SignedEnvelope) -> tuple[str, list[dict[str, str]]]:
    """(asset name, quads) for a proposal, by its kind (a promotion: :func:`_write_promotion`)."""
    if proposal.kind == killlist.KILL_LIST_STATEMENT:
        return f"kill-list-{envelope.sequence}", killlist.kill_list_quads(envelope)
    if proposal.kind == CORRECTION_STATEMENT:
        try:
            quads = row_builders.correction_quads(envelope)
        except row_builders.RowBuildError as exc:
            raise VerbError(f"the correction is not acceptable: {exc}") from exc
        return f"correction-{threat_ids.stable_hash(proposal.identifier, 12)}-{envelope.sequence}", quads
    if proposal.kind == MANIFEST_KIND:
        return f"key-manifest-{envelope.root_epoch}-{envelope.sequence}", community.key_manifest_quads(envelope)
    kind = CuratorStatement(proposal.kind)
    name = f"curator-{kind.value.split('.', 1)[1]}-{threat_ids.stable_hash(proposal.identifier, 12)}-{envelope.sequence}"
    return name, community.curator_statement_quads(envelope)


def _share(ctx: CurateContext, graph: str, name: str, quads: list[dict[str, str]]) -> bool:
    """Share into the graph's shared memory; True when the node already held
    this asset (an earlier attempt got it there). Any other failure is raised."""
    try:
        community.ensure_report_lane(ctx.client, graph)
        result = ctx.client.share_knowledge_asset(graph, name, quads)
    except Exception as exc:
        if community.ALREADY_SEALED_REPLY in str(exc).lower():
            return True
        raise
    return bool(isinstance(result, dict) and result.get("idempotent"))


def _readable(ctx: CurateContext, graph: str, view: str, quads: list[dict[str, str]]) -> bool:
    """True when the signed statement just written can be read from *graph*:
    an exact lookup of its subject AND its signed text (so another node's
    statement under the same subject does not count). Quads that carry no
    signed statement have nothing to read back and count as readable."""
    signed = next((q for q in quads if q["predicate"] == constants.SIGNED_STATEMENT_PRED), None)
    if signed is None:
        return True
    sparql = (f"SELECT ?r WHERE {{ VALUES ?r {{ <{signed['subject']}> }} "
              f"?r <{constants.SIGNED_STATEMENT_PRED}> {signed['object']} }} LIMIT 1")
    return bool(sparql_text.query_rows(ctx.client, sparql, graph, view))


def summary(proposal: Proposal) -> str:
    """What the operator is asked to consent to (graph, kind, subject, signers);
    a promotion names the report it makes permanent and the severity it gets,
    and a whole-package one says so in words, so the second signer cannot miss
    whose report it promotes or its scope."""
    envelope = proposal.parsed()
    signers = ", ".join(s[:12] + "…" for s in envelope.signers) if envelope else "?"
    strategy = strategies.strategy_for(envelope)
    ref = strategy.reference(envelope) if strategy is not None else None
    scope = ""
    if strategy is not None and ref is not None:
        scope = (f" · PROMOTES THE REPORT {ref.report} (permanent; names its reporter) · severity "
                 f"{envelope.payload.get('severity', '')}" + (" · publishes the reporter's own asset"
                                                             if strategy.publishes_report else ""))
        if ref.identifier.endswith("@*"):
            scope += " · WHOLE PACKAGE (every version)"
    if envelope and proposal.kind == CORRECTION_STATEMENT:
        scope = f" · SUPPRESSES {len(str(envelope.payload.get('targetSubjects', '')).split())} subject(s)"
    return f"{proposal.kind} · {proposal.identifier}{scope} · graph {proposal.graph} · seq {envelope.sequence if envelope else '?'} · keys {signers}"
