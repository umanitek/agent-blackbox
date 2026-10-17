"""The curator's write verbs: propose, approve, publish, nominate, manifest (Refine R6).

Each verb is one Command over a :class:`.context.CurateContext`. The two-key
flow (plan §09 TRANSPORT): machine A ``propose`` — the checklist must pass,
the first curator key signs, the proposal is stored and sent by private
message; machine B ``inbox`` then ``approve`` — the envelope's first signer
must be one of the manifest's curator keys and not B's own, B records its own
item-1 check, co-signs, gives consent bound to the content, and PUBLISHES
("whoever signs second publishes"). Nothing reaches a shared graph before
approval. Every outward write is ledgered.

Numbering, the quorum check, consent and the write itself live in
:mod:`.publishing`.
"""

from __future__ import annotations

import logging
from datetime import date, datetime, timedelta, timezone, UTC
from typing import Any, Dict, Iterable, List, Mapping, Optional, Tuple

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .. import community, killlist
from ..kernel import health, signing
from ..kernel.signing import key_manifest
from ..kernel.signing.authority import Authority
from ..kernel.signing.statement_order import CuratorStatement
from . import dossier, keys, promotion, transport
from .context import CurateContext, KillListDraft, ManifestDraft, PromotionDraft, StatementDraft
from .proposal import Proposal, ProposalState, ProposalStore
from .publishing import MANIFEST_KIND, VerbError, next_sequence, publish, strategies
from .publishing.publish import checked_promotion
from ..community import reputation

logger = logging.getLogger(__name__)


# -- propose -----------------------------------------------------------------


def propose_promotion(ctx: CurateContext, store: ProposalStore, *, report: community.VerifiedReport, severity: str,
                      evidence: str, reason: str, name: str = "") -> Proposal:
    """A promotion proposal: ONE community report into the verified tier
    (:mod:`.promotion`), signed the way new promotions take on this curator's
    node (``publishing.strategies.active``) — checklist, first signature,
    stored. *name* — the rule's display name ("" for the default; only the
    curators' own copy carries one)."""
    _require_manifest(ctx)
    _require_verified_authority(ctx, "promote into the verified graph")
    items = dossier.checklist(report.identifier, kind="malware", evidence=evidence, reason=reason)
    if not dossier.passes(items):
        raise VerbError("checklist failed: " + "; ".join(f"{i.item}. {i.note}" for i in items if not i.ok))
    advisory = evidence[len("advisory:"):] if evidence.startswith("advisory:") else ""
    try:
        payload = strategies.active(ctx.dkg_version).payload(report, severity=severity, advisory=advisory,
                                                             display_name=name)
    except promotion.PromotionError as exc:
        raise VerbError(str(exc)) from exc
    key = keys.curator_key_store().load_or_create()
    envelope = ctx.sign(PromotionDraft(payload, sequence=next_sequence(ctx, store, report.identifier)), key)
    return _stored(store, CuratorStatement.PROMOTION.value, report.identifier, envelope, ctx.verified_graph,
                   {signing.public_key_hex(key): evidence})


def propose_statement(ctx: CurateContext, store: ProposalStore, *, kind: CuratorStatement, identifier: str,
                      fields: Mapping[str, str], evidence: str = "") -> Proposal:
    """A verdict / notice / counted-author / pause proposal, first signature on
    it — signed for the graph where the ACTING authority publishes that kind.
    Refused when that authority may not sign the kind at all."""
    _require_manifest(ctx)
    fields = _with_confirmation_evidence(ctx, kind, fields, evidence)
    graph = ctx.graph_for(kind)
    if not graph:
        raise VerbError(f"the {ctx.authority.value} authority may not sign a {kind.value.split('.', 1)[1]} statement"
                        if graph is None else "no community graph is configured on this node")
    key = keys.curator_key_store().load_or_create()
    try:
        envelope = ctx.sign(StatementDraft(kind, identifier, fields, sequence=next_sequence(ctx, store, identifier),
                                           graph=graph), key)
    except ValueError as exc:
        raise VerbError(str(exc)) from exc
    return _stored(store, kind.value, identifier, envelope, graph, {signing.public_key_hex(key): evidence or "n/a"})


_EVIDENCE_HELP = "advisory:<id> | registry-action:<url> | reproduced:<sha256>"


def _with_confirmation_evidence(ctx: CurateContext, kind: CuratorStatement, fields: Mapping[str, str],
                                evidence: str) -> Mapping[str, str]:
    """A confirmation signs the evidence its curators checked (plan §08). The
    COMMUNITY authority's must: without evidence the honest statement is a
    deferral. The verified authority's signs it whenever one is given — the
    curator service always gives one, and its co-signer checks it (one graph:
    the verified curators confirm the community's threats) — and stays valid
    without, as people have always signed it."""
    cited = evidence.strip()
    if kind is not CuratorStatement.CONFIRMATION or (ctx.authority is not Authority.COMMUNITY and not cited):
        return fields
    if not community.EVIDENCE_REFERENCE.fullmatch(cited):
        raise VerbError(f"a confirmation's evidence is {_EVIDENCE_HELP}" if ctx.authority is not Authority.COMMUNITY else
                        f"a community confirmation needs --evidence {_EVIDENCE_HELP}; without evidence, propose a deferral")
    return {**fields, "evidence": cited}


def record_outcome(key: str, *, confirmed: bool, day: str, novel: bool = False, strike: bool = False,
                   first_seen_day: str = "", ledger: Optional[reputation.ReputationLedger] = None) -> reputation.ReporterStanding:
    """R4: one curator decision about one of *key*'s reports goes into the
    curator-PRIVATE ledger (never published). A strike is confirmed bad faith;
    novelty is judged by :func:`community.reputation.novelty_credit` first."""
    if len(key) != 64:
        raise VerbError("a reporter KEY (64 hex) is the identity, never an address")
    return (ledger or reputation.ReputationLedger()).record(key.lower(), reputation.Outcome(day, confirmed), novel=novel,
                                                              strike=strike, first_seen_day=first_seen_day)


def graduation_candidates(today: str, ledger: Optional[reputation.ReputationLedger] = None
                          ) -> list[tuple[reputation.ReporterStanding, float, str]]:
    """R4: every ledgered reporter with its reputation and what today calls for:
    'graduate', 'demote', or '' (nothing). Read-only."""
    book = ledger or reputation.ReputationLedger()
    rows = []
    for key in book.keys():
        standing, score = book.standing(key), book.reputation(key, today)
        action = ("graduate" if reputation.graduates(standing, today)
                  else "demote" if reputation.demotion(standing, score, today) is not None else "")
        rows.append((standing, score, action))
    return rows


def propose_graduation(ctx: CurateContext, store: ProposalStore, *, key: str, address: str, today: str,
                       cluster: str = "", ledger: Optional[reputation.ReputationLedger] = None) -> Proposal:
    """R4: turn a standing into the counted-author proposal it calls for
    (graduation lists, demotion delists, a collapse shares an org) — the same
    2-of-3 flow as every nomination; readers never see the ledger. The ledger's
    band changes when the listing is PUBLISHED (``ladder.outcomes.sync_bands``),
    never here: a proposal nobody co-signs changes nothing (KI-255)."""
    book = ledger or reputation.ReputationLedger()
    standing = book.standing(key.lower())
    fields = reputation.nomination_fields(standing, address=address, today=today,
                                          reputation=book.reputation(key.lower(), today), cluster=cluster,
                                          listing_days=listing_days(ctx))
    if fields is None:
        raise VerbError(f"nothing to propose for this reporter today (band {standing.band.value}, "
                        f"{standing.novel_credits} novel credit(s), {standing.strikes} strike(s))")
    identifier = f"author:{key.lower()}"
    waiting = [p for p in store.open() if p.identifier == identifier]
    if waiting:   # the band only moves on publish, so a second proposal would duplicate the first
        raise VerbError(f"a proposal for this reporter is already waiting ({waiting[0].id}, {waiting[0].state.value})")
    return propose_statement(ctx, store, kind=CuratorStatement.COUNTED_AUTHORS, identifier=identifier,
                             fields=fields, evidence=f"reputation ledger {today}")


def curator_alarms(ctx: CurateContext, compiled: Optional[Any], *, today: str, now: float,
                   ledger: Optional[reputation.ReputationLedger] = None) -> list[health.HealthItem]:
    """R10b: the curator-audience alarms from this node's own facts — the queue
    (depth and lane ages against the SLA), the private ledger (drift), the
    reader's first-seen trail (report velocity), the share retries and the
    counted list's expiries. Never shown to operators."""
    from . import queue as queue_mod
    from .context import verified_identifiers
    lane_depth: dict[int, int] = {}
    lane_over: dict[int, int] = {}
    if compiled is not None:
        view = queue_mod.delta_view(compiled.community, verified_identifiers(compiled, compiled.community))
        for item in view.new:
            lane_depth[item.lane.value] = lane_depth.get(item.lane.value, 0) + 1
            first_seen = float((compiled.community.get(item.identifier) or {}).get("firstSeen") or now)
            if now - first_seen > health.LANE_SLA_DAYS.get(item.lane.value, 14) * 86_400:
                lane_over[item.lane.value] = lane_over.get(item.lane.value, 0) + 1
    book = ledger or reputation.ReputationLedger()
    established = [k for k in book.keys() if book.standing(k).band is reputation.ReputationBand.ESTABLISHED]
    below = sum(1 for k in established if book.reputation(k, today) < reputation.REPUTATION_FLOOR)
    today_count, mean, sigma = _report_velocity(now)
    expiring = sum(1 for entry in ctx.view.counted.values()
                   if 0 <= _days_until(entry.expires, today) <= 30)
    inputs = health.CuratorInputs(lane_depth=lane_depth, lane_over_sla=lane_over, established_below_floor=below,
                                  established_total=len(established), reports_today=today_count, velocity_mean=mean,
                                  velocity_sigma=sigma, shares_given_up=community.share_retry_stats().given_up,
                                  expiring_keys=expiring)
    return health.curator_health(inputs)


def _days_until(day: str, today: str) -> int:
    try:
        return (date.fromisoformat(day) - date.fromisoformat(today)).days
    except ValueError:
        return 10**6


def _report_velocity(now: float, days: int = 14) -> tuple[int, float, float]:
    """(statements first seen today, mean per day, σ) over the last *days* days,
    from the reader's first-seen trail (``community_first_seen.json``)."""
    first_seen, _ = community.first_seen_trail()
    buckets = [0] * days
    for seen_at in first_seen.values():
        age = int((now - float(seen_at)) // 86_400)
        if 0 <= age < days:
            buckets[age] += 1
    history = buckets[1:]
    mean = sum(history) / len(history) if history else 0.0
    sigma = (sum((x - mean) ** 2 for x in history) / len(history)) ** 0.5 if history else 0.0
    return buckets[0], mean, sigma


def _stored(store: ProposalStore, kind: str, identifier: str, envelope: signing.SignedEnvelope, graph: str,
            checks: Mapping[str, str]) -> Proposal:
    proposal = Proposal.new(kind, identifier, envelope, graph, checks=checks).transition(ProposalState.PROPOSED)
    store.save(proposal)
    return proposal


def send(ctx: CurateContext, proposal: Proposal, peer: str) -> dict[str, object]:
    return transport.send_proposal(ctx.client, peer, proposal)


# -- approve (second key) ----------------------------------------------------------


def propose_kill_list(ctx: CurateContext, store: ProposalStore, *, entries: list[dict[str, str]]) -> Proposal:
    """R14: first signature on a kill list (the next version); wide or popular
    kills still need the root to co-sign at approval (`approve --root`)."""
    _require_manifest(ctx)
    _require_verified_authority(ctx, "sign a kill list")
    parsed = [killlist.KillEntry.from_json(item) for item in entries]
    if not parsed or any(e is None for e in parsed):
        raise VerbError("every kill-list entry needs registry (skill|mcp), identifier, action (disable|warn) and a closed reason")
    version = next_sequence(ctx, store, "kill-list")
    kill_list = killlist.KillList(version=version, day=datetime.now(UTC).date().isoformat(),
                                  entries=tuple(e for e in parsed if e is not None))
    key = keys.curator_key_store().load_or_create()
    try:
        envelope = ctx.sign(KillListDraft(kill_list, ctx.verified_graph), key)
    except ValueError as exc:
        raise VerbError(str(exc)) from exc
    return _stored(store, killlist.KILL_LIST_STATEMENT, "kill-list", envelope, ctx.verified_graph,
                   {signing.public_key_hex(key): f"{len(kill_list.entries)} entries, {len(kill_list.disables)} disables"})


def approve(ctx: CurateContext, store: ProposalStore, proposal_id: str, *, evidence: str,
            typed_code: Optional[str], yes: bool, root: bool = False, standing: str = "") -> tuple[Proposal, str]:
    """Second signature + consent + publish. Returns (proposal, what happened).
    *root* (SANDBOX, kill lists): also add the root key's signature — the third
    signature a wide or popular kill needs (R14). *standing* — the curator
    service's standing consent (see ``publishing.publish``)."""
    if root and not ctx.sandbox:   # KI-256: a locally held root exists only in a development setup
        raise VerbError("this network has a pinned root; the root signature comes from the offline root, never from this machine")
    _require_manifest(ctx)
    proposal = store.get(proposal_id)
    if proposal is None or proposal.state is not ProposalState.PROPOSED:
        raise VerbError("no PROPOSED proposal with that id")
    envelope = proposal.parsed()
    if envelope is None:
        raise VerbError("the proposal's envelope is malformed")
    my_key = keys.curator_key_store().load_or_create()
    _check_first_signer(ctx, envelope, proposal, signing.public_key_hex(my_key))
    if proposal.kind == CuratorStatement.PROMOTION.value:
        if not evidence:
            raise VerbError("a promotion needs your own item-1 evidence (--evidence advisory:<id> …); each key checks the truth itself")
        checked_promotion(ctx, envelope)   # KI-195: never cosign a report you did not check yourself
    if envelope.payload.get("evidence") and not community.EVIDENCE_REFERENCE.fullmatch(evidence.strip()):
        raise VerbError(f"this confirmation cites evidence; co-sign it only after your own check of it "
                        f"(--evidence {_EVIDENCE_HELP}) — each key checks the truth itself")
    try:
        cosigned = ctx.cosign(envelope, my_key)
        if root and proposal.kind == killlist.KILL_LIST_STATEMENT:
            cosigned = ctx.cosign(cosigned, keys.root_key_store().load_or_create())
    except ValueError as exc:   # round 4: a third signature can outgrow the 4 KB envelope
        raise VerbError(f"cannot add this signature: {exc} — split the list into smaller versions") from exc
    proposal = proposal.with_envelope(cosigned, {signing.public_key_hex(my_key): evidence or "n/a"})
    proposal = proposal.transition(ProposalState.APPROVED)
    store.save(proposal)
    return publish(ctx, store, proposal.id, typed_code=typed_code, yes=yes, standing=standing)


def _check_first_signer(ctx: CurateContext, envelope: signing.SignedEnvelope, proposal: Proposal, my_key: str) -> None:
    signers = ctx.manifest.curator_signers(envelope, statement_type=envelope.statement_type, graph=proposal.graph) \
        if proposal.kind != CuratorStatement.PROMOTION.value else \
        signing.verified_signers(envelope, statement_type=envelope.statement_type, environment=ctx.manifest.environment,
                                 graph=proposal.graph, chain=ctx.manifest.chain, root_epoch=ctx.manifest.root_epoch) \
        & frozenset(ctx.manifest.curator_keys)
    if not signers:
        raise VerbError("the proposal is not signed by a curator key in the trusted manifest")
    if my_key in signers:
        raise VerbError("you already signed this proposal; the SECOND signature must come from another curator")


# -- manifest (sandbox) --------------------------------------------------------


def manifest_proposal(ctx: CurateContext, store: ProposalStore, *, curator_keys: list[str],
                      curator_operators: list[str], threshold: int, promotion_author: str, root_epoch: int, version: int, legacy_uals: Iterable[str],
                      issued_day: str = "") -> Proposal:
    """SANDBOX: a root-signed key manifest for the ACTING authority, bound to
    the graph that authority's manifest lives in (the community graph for the
    community authority), stored APPROVED (one root signature is the whole
    quorum) for `curate publish`. On a pinned network or graph the root is
    offline; its manifest arrives as a file, not from this verb (R7b).
    *issued_day* dates it (60-day validity; acted on at once — no time-lock); "" = no clock.
    *curator_operators* names the organisation running each key, in the same order."""
    if not ctx.sandbox:   # KI-256
        raise VerbError("this network has a pinned root; manifests come from the offline root (R7b)")
    graph = ctx.manifest_graph
    if not graph:
        raise VerbError("no community graph is configured on this node")
    if len(curator_operators) != len(curator_keys) or len(set(curator_keys)) != len(curator_keys):
        raise VerbError("give each distinct curator key exactly one operator, in the same order")
    community_authority = ctx.authority is Authority.COMMUNITY
    manifest = key_manifest.KeyManifest(
        environment=ctx.environment, graph=graph, chain="", root_epoch=root_epoch, version=version,
        **key_manifest.roster(dict(zip(curator_keys, curator_operators))), threshold=threshold,
        promotion_author=key_manifest.NO_PROMOTION_AUTHOR if community_authority else promotion_author,
        legacy_assets_hash=key_manifest.legacy_assets_hash(() if community_authority else legacy_uals),
        issued_day=issued_day)
    root: Ed25519PrivateKey = keys.root_key_store(ctx.authority).load_or_create()
    envelope = ctx.sign(ManifestDraft(manifest), root)
    proposal = Proposal.new(MANIFEST_KIND, "curator", envelope, graph,
                            checks={signing.public_key_hex(root): "root"})
    proposal = proposal.transition(ProposalState.PROPOSED).transition(ProposalState.APPROVED)
    store.save(proposal)
    return proposal


#: A community-authority listing runs this long unless an expiry is given (decision 6).
COMMUNITY_LISTING_DAYS = 90


def listing_days(ctx: CurateContext) -> int:
    """How long a listing the acting authority proposes runs."""
    return COMMUNITY_LISTING_DAYS if ctx.authority is Authority.COMMUNITY else reputation.LISTING_DAYS


def default_expiry(ctx: CurateContext, today: Optional[date] = None) -> str:
    """The expiry day a new listing gets when none is given."""
    return ((today or datetime.now(UTC).date()) + timedelta(days=listing_days(ctx))).isoformat()


def _require_manifest(ctx: CurateContext) -> None:
    if ctx.manifest is None:
        root_env = "BLACKBOX_COMMUNITY_ROOT_KEYS" if ctx.authority is Authority.COMMUNITY else "BLACKBOX_CURATOR_ROOT_KEYS"
        raise VerbError(f"no trusted key manifest for the {ctx.authority.value} authority — publish one first "
                        f"(sandbox: `curate manifest`), and make sure {root_env} names its root")


def _require_verified_authority(ctx: CurateContext, what: str) -> None:
    if ctx.authority is not Authority.VERIFIED:
        raise VerbError(f"the community authority may not {what}; that belongs to the verified graph's curators")
