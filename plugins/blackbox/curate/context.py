"""What every `blackbox curate` verb needs resolved once (Refine R6, Community Curation C4).

:class:`CurateContext` holds the config, the node client, the network id, the
trusted curator view (both authorities, combined), the AUTHORITY this machine
acts for, whether that authority is in a development setup (``sandbox`` — no
pinned root, so consent by ``--yes`` and a locally held root are allowed), and
the compiled ruleset the composition root injected (the ruleset depends on
this package, never the reverse).

A curator machine acts for exactly one authority (``kernel.signing.authority``):
the VERIFIED one publishes its manifest and enforcement statements in the
verified graph's Verified Memory and its advisory statements in the same
graph's shared memory, beside the community's reports (one graph since
2026-10-16); the COMMUNITY one may only ever cause FLAG, and it is dormant: it
may never share the verified authority's graph, and there is no other. Which
one is decided once, in :func:`acting_authority`, and every verb routes by it.
Both homes are in one graph, so a statement is routed by its HOME
(:meth:`CurateContext.home_of`), never by comparing graph ids.

It is also the SIGNING CHOKE POINT: :meth:`CurateContext.sign` and
:meth:`CurateContext.cosign` are the only places code under ``curate/`` makes a
signature, and each signature appends one row to the node's
:class:`.watch.SigningLog` (what the signature reconciler compares published
statements against). ``tests/plugins/test_blackbox_curate_signing_path.py``
fails on any other signing call under ``curate/``.

Pattern: a Facade over the kernel + community pieces the verbs use; the
signing choke point takes a Command-style draft (:data:`Draft`) naming what to sign.

Usage::

    ctx = build_context(compiled_ruleset, authority="community", interest=["author:<key>"])
    ctx.manifest                      # the acting authority's key manifest (None: publish one first)
    ctx.graph_for(CuratorStatement.COUNTED_AUTHORS)   # the graph that kind is signed for (None: may not sign it)
    ctx.home_of("blackbox.rejection")                 # "community": the graph's shared memory
    envelope = ctx.sign(PromotionDraft(payload, sequence=3), curator_key)   # first signature, logged
    envelope = ctx.cosign(envelope, my_key)                                  # one more, logged
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .. import community, killlist
from ..kernel import constants, signing
from ..kernel.config import BlackboxConfig, load_blackbox_config
from ..kernel.dkg_client import DkgClient
from ..kernel.signing import key_manifest, trust_anchors
from ..kernel.signing.authority import VERIFIED_GRAPH, Authority, RootStatement, home_graph
from ..kernel.signing.key_manifest import KeyManifest
from ..kernel.signing.statement_order import CuratorStatement
from . import keys
from .watch import SigningLog

#: cfg -> the compiled Ruleset (injected by cli.py).
CompiledRuleset = Callable[[Any], Any]


# -- what the choke point may sign (one draft per statement family) -----------


@dataclass(frozen=True)
class PromotionDraft:
    """A promotion payload (``publishing.strategies``: the way new promotions
    take), bound to the acting authority's manifest graph at *sequence*."""

    payload: Mapping[str, str]
    sequence: int


@dataclass(frozen=True)
class CorrectionDraft:
    """A correction payload (``publishing.row_builders.correction_payload``) at
    *sequence*, bound like a promotion to the acting authority's manifest graph
    (the reader checks it with ``has_quorum`` against that manifest)."""

    payload: Mapping[str, str]
    sequence: int


@dataclass(frozen=True)
class StatementDraft:
    """A curator statement (verdict, notice, counted author, pause …) for *graph*."""

    kind: CuratorStatement
    identifier: str
    fields: Mapping[str, str]
    sequence: int
    graph: str


@dataclass(frozen=True)
class KillListDraft:
    """A kill list (its version is the sequence) for *graph*."""

    kill_list: killlist.KillList
    graph: str


@dataclass(frozen=True)
class ManifestDraft:
    """A key manifest — signed by a ROOT key, so it needs no trusted manifest yet."""

    manifest: KeyManifest


#: The statement type of a signed lab-evidence envelope (proposal §03.5, F-024).
LAB_EVIDENCE_STATEMENT = "lab-evidence"


@dataclass(frozen=True)
class EvidenceDraft:
    """Lab evidence (``lab.controller.evidence_payload``) — signed by the LAB
    CONTROLLER's own key, never a curator key, so it needs no trusted manifest.
    The envelope is bound to this node's environment and to no graph: lab
    evidence is kept on the curator node, never published."""

    payload: Mapping[str, str]


#: The statement type of a signed dispute queue item (proposal §03.3, SVC3) —
#: distinct from a reporting node's community ``blackbox.dispute``.
DISPUTE_INTAKE_STATEMENT = "blackbox.dispute-intake"


@dataclass(frozen=True)
class DisputeDraft:
    """A dispute a listed party filed on the public page (``intake.DisputeIntake``),
    signed by this node's CURATOR key so the other curator can tell the queue
    item came from a curator's intake. Bound to this node's environment and to
    no graph: a dispute item travels between curators, it is never published."""

    payload: Mapping[str, str]


Draft = PromotionDraft | CorrectionDraft | StatementDraft | KillListDraft | ManifestDraft | EvidenceDraft | DisputeDraft
#: The statement type of a signed correction (trust-and-threat-lab P5; a reduction, K2).
CORRECTION_STATEMENT = "blackbox.correction"


@dataclass(frozen=True)
class CurateContext:
    """*signing_log* — where :meth:`sign` / :meth:`cosign` record; None = the
    node's own ``<curate home>/signing_log.jsonl``, resolved at signing time.
    *dkg_version* — the DKG release the node reports ("" = not read): it picks
    the way new promotions take (``publishing.strategies.active``)."""

    cfg: BlackboxConfig
    client: DkgClient
    environment: str
    view: community.CuratorView
    sandbox: bool
    compiled: Optional[Any]
    authority: Authority = Authority.VERIFIED
    signing_log: Optional[SigningLog] = field(default=None, compare=False)
    dkg_version: str = ""

    @property
    def manifest(self) -> Optional[KeyManifest]:
        """The ACTING authority's trusted key manifest (None: none published yet)."""
        if self.authority is Authority.COMMUNITY:
            return self.view.community.manifest if self.view.community is not None else None
        return self.view.manifest

    @property
    def own_view(self) -> community.CuratorView:
        """The acting authority's own view (its statements only, its own sequence order)."""
        if self.authority is Authority.COMMUNITY:
            return self.view.community if self.view.community is not None else community.CuratorView()
        return self.view

    @property
    def verified_graph(self) -> str:
        """The one context graph: Verified Memory holds the verified tier, shared
        memory the community's reports and the advisory statements."""
        return self.cfg.context_graph_id

    @property
    def manifest_graph(self) -> str:
        """The graph the acting authority's manifest is bound to and published in
        (the one graph; the community authority is dormant)."""
        return self.verified_graph

    def graph_for(self, kind: CuratorStatement) -> Optional[str]:
        """The graph id a *kind* statement of the acting authority is signed for,
        or None when it may not sign that kind at all."""
        return self.verified_graph if self.home_of(kind.value) is not None else None

    def home_of(self, statement_type: str) -> Optional[str]:
        """Where the acting authority publishes a *statement_type* statement:
        ``"verified"`` (the graph's Verified Memory), ``"community"`` (its shared
        memory) or None when it may not sign it. Corrections and kill lists act
        on the verified tier, so only the verified authority signs them."""
        if statement_type in (CORRECTION_STATEMENT, killlist.KILL_LIST_STATEMENT):
            return VERIFIED_GRAPH if self.authority is Authority.VERIFIED else None
        if statement_type == key_manifest.KEY_MANIFEST_STATEMENT:
            return home_graph(self.authority, RootStatement.KEY_MANIFEST)
        try:
            return home_graph(self.authority, CuratorStatement(statement_type))
        except ValueError:
            return None

    def sign(self, draft: Draft, key: Ed25519PrivateKey) -> signing.SignedEnvelope:
        """The FIRST signature on *draft* by *key*, recorded in the signing log.

        Promotions, corrections, statements and kill lists are bound to the acting
        authority's manifest (environment, chain, root epoch); manifests
        (root-signed), lab evidence (lab-controller-signed) and dispute queue
        items (kept between curators, never published) need none. Raises
        ``ValueError`` when there is no such manifest, or when the draft is
        not a valid statement of its kind (the domain module's own checks).
        """
        if isinstance(draft, ManifestDraft):
            envelope = key_manifest.sign_manifest(draft.manifest, key)
        elif isinstance(draft, EvidenceDraft):
            envelope = signing.sign(key, statement_type=LAB_EVIDENCE_STATEMENT, environment=self.environment,
                                    graph="", payload=dict(draft.payload))
        elif isinstance(draft, DisputeDraft):
            envelope = signing.sign(key, statement_type=DISPUTE_INTAKE_STATEMENT, environment=self.environment,
                                    graph="", payload=dict(draft.payload))
        elif self.manifest is None:
            raise ValueError(f"the {self.authority.value} authority has no trusted key manifest yet; publish one first")
        elif isinstance(draft, (PromotionDraft, CorrectionDraft)):
            manifest = self.manifest
            statement_type = CuratorStatement.PROMOTION.value if isinstance(draft, PromotionDraft) else CORRECTION_STATEMENT
            envelope = signing.sign(key, statement_type=statement_type,
                                    environment=manifest.environment, graph=manifest.graph,
                                    payload=dict(draft.payload), chain=manifest.chain,
                                    root_epoch=manifest.root_epoch, sequence=draft.sequence)
        elif isinstance(draft, StatementDraft):
            envelope = community.sign_curator_statement(draft.kind, draft.identifier, sequence=draft.sequence,
                                                         fields=draft.fields, key=key, manifest=self.manifest,
                                                         graph=draft.graph)
        else:
            envelope = killlist.sign_kill_list(draft.kill_list, key, self.manifest, draft.graph)
        self._signing_log().record(envelope, key, action="sign")
        return envelope

    def cosign(self, envelope: signing.SignedEnvelope, key: Ed25519PrivateKey) -> signing.SignedEnvelope:
        """*envelope* with *key*'s signature added, recorded in the signing log.
        Raises ``ValueError`` as ``signing.cosign`` does (already signed, too
        many signatures, envelope too large) — nothing is logged then."""
        cosigned = signing.cosign(envelope, key)
        self._signing_log().record(cosigned, key, action="cosign")
        return cosigned

    def _signing_log(self) -> SigningLog:
        return self.signing_log if self.signing_log is not None else SigningLog()


def acting_authority(cfg: BlackboxConfig, environment: str, view: community.CuratorView,
                     requested: Optional[str] = None) -> Authority:
    """Which authority this curator machine acts for. An explicit *requested*
    value wins; else COMMUNITY when the community manifest lists this
    machine's curator key; else VERIFIED. Under one graph the community
    authority is dormant (no reader builds its view), so a machine trusting
    only a community root no longer defaults to it: *cfg* and *environment*
    decided that case and wait with it."""
    if requested:
        return Authority(requested)
    my_key = keys.curator_key_store().public_key_hex()
    if view.community is not None and view.community.manifest is not None and my_key in view.community.manifest.curator_keys:
        return Authority.COMMUNITY
    return Authority.VERIFIED


def is_sandbox(authority: Authority, cfg: BlackboxConfig, environment: str) -> bool:
    """True when *authority* has no pinned root here (a development setup)."""
    if authority is Authority.COMMUNITY:
        return not trust_anchors.community_root_pinned(cfg.context_graph_id)
    return not constants.CURATOR_ROOT_KEYS.get(environment)


def build_context(compiled_ruleset: Optional[CompiledRuleset], *, authority: Optional[str] = None,
                  interest: Iterable[str] = ()) -> CurateContext:
    """Resolve the context from the live node. The node must be reachable.
    *interest* — identifiers the verb is about (their statements are looked up)."""
    cfg = load_blackbox_config()
    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    status = client.status()
    environment = community.network_environment(status)
    view = community.read_curator_view(client, cfg, environment, interest=interest)
    acting = acting_authority(cfg, environment, view, authority)
    compiled = compiled_ruleset(cfg) if compiled_ruleset is not None else None
    return CurateContext(cfg=cfg, client=client, environment=environment, view=view,
                         sandbox=is_sandbox(acting, cfg, environment), compiled=compiled, authority=acting,
                         dkg_version=str((status or {}).get("version") or ""))


def verified_identifiers(compiled: Any, among: Iterable[str]) -> set:
    """Which of *among* the verified tier already lists (the delta view's "already
    verified"). Asked for a known set — the community store's identifiers, a
    read's reports — because the verified tier is looked up live, never listed."""
    if compiled is None:
        return set()
    subset = getattr(compiled, "verified_subset", None)
    if callable(subset):
        return set(subset(among))
    wanted = {str(identifier) for identifier in among}   # a plain compiled object: scan its public rules
    return {str(rule.get("identifier") or "") for _category, rule in compiled.iter_rules()
            if rule.get("source") == "public" and str(rule.get("identifier") or "") in wanted}
