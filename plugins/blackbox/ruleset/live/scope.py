"""The verified scope: what a live lookup is allowed to believe.

A lookup against the store sees every named graph the node holds — the open
community graph, foreign owners' assets, tentative assets not yet confirmed.
Only rows from Umanitek's confirmed assets may become public (blockable)
rules, so the KI-106 owner pin lives here as a SET the lookup checks in O(1)
instead of a per-lookup join (which cost 0.5–3 s on the bench).

Once the authority names a successor graph and readers follow it
(trust-and-threat-lab R5 — :func:`community.active_verified_graph`), the
scope applies its cut-off: the configured graph's legacy assets and the assets
it dated BEFORE the migration's ``from_day`` keep their tier, every later asset
of the configured graph is out of scope entirely (not even flag), and new
assets come only from the successor graph — tiered the same way, their
envelopes bound to the successor. The legacy list and its hash do not change.

Pattern: Memento — one frozen snapshot per refresh, persisted inside
``ruleset.json`` and handed to every process; rebuilt by :func:`refresh_scope`.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterable, Mapping, Optional, Sequence, Tuple

from ...kernel import threat_ids
from ...kernel.config import BlackboxConfig
from ...kernel.dkg_client import DkgClient, DkgError
from ...kernel.signing import GraphMigration
from ...kernel.store import StoreClient, loopback_store_url
from .asset_facts import (ECOSYSTEM_COUNT_PREFIX, AssetFacts, AssetTier,
                          read_new_asset_facts, tier_assets, totals)
from .envelope_tier import decide_by_envelope, rule_disagrees
from ... import community
from .. import anchors, fetching, graph_queries, row_adapters

logger = logging.getLogger(__name__)

#: The rule source a FLAG-tier asset's rules carry: the one non-blocking tier the
#: detectors know (``confirmed`` False, never auto-shared). A FLAG-tier row is a
#: wallet publish without a curator envelope — no more trusted than a community row.
FLAG_ONLY_SOURCE = row_adapters.FLAG_ONLY_SOURCE


@dataclass(frozen=True)
class VerifiedScope:
    """One refresh's view of the verified graph, for the lookup to filter by.

    ``store_url`` — the node's local store endpoint (loopback only; empty when
    the node did not report one). ``assertion_graphs`` — the confirmed,
    owner-pinned VM assertion graphs: a row from any other graph is ignored.
    ``suppressed_subjects`` — threats a public CorrectionSignal withdrew.
    ``revoked_identifiers`` — rules the curator revoked (reduction: always applies).
    ``package_aliases`` — ``"eco:canonical-name"`` → the spellings the graph
    actually stores (117 npm names carry capitals; the compiler lowercased
    them, so the lookup must ask for every spelling). ``verified_counts`` — rules
    per live tier (``dependency``, ``ioc``) for status, health and the dashboard.
    ``legacy_refused`` — why the shipped legacy asset list was refused at the
    last refresh that could check it ("" = fine; a SECURITY alarm — the asset
    tiers then stay as they were). ``built_at`` — epoch seconds.
    """

    context_graph_id: str = ""
    store_url: str = ""
    assertion_graphs: frozenset[str] = frozenset()
    suppressed_subjects: frozenset[str] = frozenset()
    revoked_identifiers: frozenset[str] = frozenset()
    package_aliases: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    #: How many verified rules the live tiers hold (``dependency``, ``ioc``) — the
    #: counts the compile used to produce, now three aggregate queries per refresh.
    verified_counts: Mapping[str, int] = field(default_factory=dict)
    #: The operator's fallback mode at refresh time (``off`` | ``index``), so the hot
    #: path never reads config.
    fallback: str = "off"
    #: Per-asset facts (counts, spellings) read ONCE per immutable asset
    #: (:mod:`.asset_facts`); ``verified_counts`` / ``package_aliases`` are their totals.
    asset_facts: Mapping[str, AssetFacts] = field(default_factory=dict)
    legacy_refused: str = ""
    built_at: float = 0.0

    @property
    def ready(self) -> bool:
        """True when lookups can run: a store to ask and assets to trust."""
        return bool(self.store_url and self.assertion_graphs)

    def spellings(self, ecosystem: str, name: str) -> tuple[str, ...]:
        """Every spelling of *name* the graph may store: the canonical one plus
        the aliases recorded for it."""
        canonical = threat_ids.canonical_package_name(ecosystem, name)
        return (canonical, *self.package_aliases.get(f"{ecosystem.strip().lower()}:{canonical}", ()))

    def tier_of(self, graph: str) -> Optional[AssetTier]:
        """*graph*'s asset tier — one dict lookup, the hot path's only cost."""
        fact = self.asset_facts.get(graph)
        return fact.tier if fact is not None else None

    def as_tier_allows(self, graph: str, category: str, key: str, rule: dict[str, Any]) -> Optional[dict[str, Any]]:
        """*rule* (built from a row of *graph*, as ``row_adapters._row_to_rule``
        returned ``(category, key, rule)``) as its asset's tier allows — dict
        lookups only, the hot path's whole cost:

        * undecided, or BLOCK by the legacy list: unchanged;
        * FLAG: capped at flag (:data:`FLAG_ONLY_SOURCE`);
        * BLOCK by envelope (R2): served from the SIGNED payload; a row of that
          asset without a quorum envelope is capped at flag;
        * None — never served: a row whose shown rule disagrees with its
          signature (a transplanted envelope)."""
        fact = self.asset_facts.get(graph)
        if fact is None or fact.tier is None:
            return rule
        subject = rule.get("subject")
        if subject in fact.ignored:
            return None
        if fact.tier is AssetTier.FLAG:
            return row_adapters.capped_at_flag(rule)
        if not fact.signed:
            return rule
        signed = fact.signed.get(subject)
        if signed is None:
            return row_adapters.capped_at_flag(rule)
        return None if rule_disagrees(category, key, rule, signed) else signed.served(rule)

    @property
    def refused_envelope_rows(self) -> tuple[str, ...]:
        """SECURITY alarm input (R2): ``"<asset graph> <subject>"`` for every
        verified row ignored because its shown rule disagrees with its signed
        envelope — someone holding the publishing wallet copied a valid
        envelope onto another row. Empty = nothing to alarm on."""
        return tuple(sorted(f"{graph} {subject}" for graph, fact in self.asset_facts.items() for subject in fact.ignored))

    def to_json(self) -> dict[str, Any]:
        return {
            "context_graph_id": self.context_graph_id,
            "store_url": self.store_url,
            "assertion_graphs": sorted(self.assertion_graphs),
            "suppressed_subjects": sorted(self.suppressed_subjects),
            "revoked_identifiers": sorted(self.revoked_identifiers),
            "package_aliases": {key: list(values) for key, values in sorted(self.package_aliases.items())},
            "verified_counts": dict(self.verified_counts),
            "fallback": self.fallback,
            "asset_facts": {graph: fact.to_json() for graph, fact in sorted(self.asset_facts.items())},
            "legacy_refused": self.legacy_refused,
            "built_at": self.built_at,
        }

    @classmethod
    def from_json(cls, data: Any) -> VerifiedScope:
        """A scope from :meth:`to_json` output; anything malformed is an empty scope."""
        if not isinstance(data, dict):
            return cls()
        aliases = data.get("package_aliases")
        return cls(
            context_graph_id=str(data.get("context_graph_id") or ""),
            store_url=str(data.get("store_url") or ""),
            assertion_graphs=_strings(data.get("assertion_graphs")),
            suppressed_subjects=_strings(data.get("suppressed_subjects")),
            revoked_identifiers=_strings(data.get("revoked_identifiers")),
            package_aliases={str(k): tuple(str(v) for v in vs) for k, vs in aliases.items()
                             if isinstance(vs, list)} if isinstance(aliases, dict) else {},
            verified_counts={str(k): int(v) for k, v in counts.items() if isinstance(v, (int, float))}
            if isinstance(counts := data.get("verified_counts"), dict) else {},
            fallback=str(data.get("fallback") or "off"),
            asset_facts={str(graph): fact for graph, raw in facts.items() if (fact := AssetFacts.from_json(raw))}
            if isinstance(facts := data.get("asset_facts"), dict) else {},
            legacy_refused=str(data.get("legacy_refused") or ""),
            built_at=float(data.get("built_at") or 0.0),
        )


def _strings(value: Any) -> frozenset[str]:
    return frozenset(str(item) for item in value) if isinstance(value, list) else frozenset()


def refresh_scope(
    client: DkgClient,
    context_graph_id: str,
    *,
    previous: Optional[VerifiedScope],
    confirmed: Optional[Sequence[str]],
    suppressed: Optional[Iterable[str]],
    revoked: Iterable[str],
    store: Optional[StoreClient] = None,
    fallback: str = "off",
    legacy_assets_hash: Optional[str] = None,
    migration: Optional[GraphMigration] = None,
    successor_confirmed: Optional[Sequence[str]] = None,
) -> VerifiedScope:
    """The next scope. Every part that could not be read this time keeps the
    previous scope's value (fail-open, but never "could not read" → "nothing").

    *confirmed* / *suppressed* are None when the refresh could not read them
    (a last-good generation being reused); *revoked* always applies.
    *legacy_assets_hash* — the trusted manifest's legacy pin ("" = no trusted
    manifest; None = the curator read could not tell, the last verdict stands):
    the shipped legacy list is loaded and checked against it once per refresh;
    while it is verified, undecided assets are tiered (:func:`_tier_new_assets`).
    *migration* — the graph migration followed (None: no successor, scoped as
    before R5); *successor_confirmed* — the successor's confirmed assets (None =
    not read: the last ones stay). *confirmed* always lists the configured graph.
    """
    previous = previous or VerifiedScope()
    store_url = _store_url(client) or previous.store_url
    old_graphs, new_graphs = _listed_assets(previous, confirmed, migration, successor_confirmed)
    legacy = anchors.verified_legacy_assets(legacy_assets_hash) if legacy_assets_hash is not None else None
    graphs, facts = _scoped_assets(client, context_graph_id, (store or StoreClient(store_url)) if store_url else None,
                                   old_graphs, new_graphs, dict(previous.asset_facts),
                                   legacy.uals if legacy is not None else None, migration)
    counts, aliases = totals(facts, graphs)
    if not facts:                                         # nothing read yet: keep what the last scope said
        counts, aliases = dict(previous.verified_counts), dict(previous.package_aliases)
    return VerifiedScope(
        context_graph_id=context_graph_id,
        store_url=store_url,
        assertion_graphs=graphs,
        suppressed_subjects=frozenset(suppressed) if suppressed is not None else previous.suppressed_subjects,
        revoked_identifiers=frozenset(revoked),
        package_aliases=aliases,
        verified_counts=counts,
        fallback=fallback,
        asset_facts=facts,
        legacy_refused=legacy.refused if legacy is not None else previous.legacy_refused,
        built_at=time.time(),
    )


def _scoped_assets(client: DkgClient, context_graph_id: str, store: Optional[StoreClient],
                   old_graphs: frozenset[str], new_graphs: frozenset[str], facts: dict[str, AssetFacts],
                   legacy_uals: Optional[frozenset[str]],
                   migration: Optional[GraphMigration]) -> tuple[frozenset[str], dict[str, AssetFacts]]:
    """(the assets in scope, the facts carried) for this refresh: the facts of
    the configured graph's *old_graphs* and the successor's *new_graphs* read
    (when a *store* is known), the cut-off applied (with a *migration*), and
    the assets in scope tiered while a verified legacy list is in force
    (*legacy_uals* not None)."""
    graphs = old_graphs | new_graphs
    if store is not None and graphs:
        facts = read_new_asset_facts(store, wanted=graphs, known=facts)
        if migration is not None:                         # the cut-off needs every asset's day
            facts = tier_assets(store, facts, legacy=legacy_uals or frozenset())
    if migration is not None:
        graphs = _before_cut(old_graphs, facts, migration.from_day, legacy_uals or frozenset()) | new_graphs
    if store is not None and graphs and legacy_uals is not None:  # a verified list: the pin is in force
        in_scope = {graph: fact for graph, fact in facts.items() if graph in graphs}
        successor = migration.to_graph if migration is not None else ""
        facts.update(_tier_new_assets(client, context_graph_id, store, in_scope, legacy_uals, successor))
    return graphs, facts


def _listed_assets(previous: VerifiedScope, confirmed: Optional[Sequence[str]], migration: Optional[GraphMigration],
                   successor_confirmed: Optional[Sequence[str]]) -> tuple[frozenset[str], frozenset[str]]:
    """(the configured graph's listed assets, the successor's). A listing that
    could not be read (None) takes what the previous scope knew of: its
    in-scope assets — and, with a migration, also those it held facts for
    (assets left out by the cut-off), so their facts are carried, not re-read."""
    known = previous.assertion_graphs | (frozenset(previous.asset_facts) if migration is not None else frozenset())
    old_graphs, new_graphs = _by_graph(known, migration.to_graph if migration is not None else "")
    return (frozenset(confirmed) if confirmed is not None else old_graphs,
            frozenset(successor_confirmed) if successor_confirmed is not None else new_graphs)


def _by_graph(assets: frozenset[str], successor: str) -> tuple[frozenset[str], frozenset[str]]:
    """*assets* split into (the configured graph's, the *successor*'s) by IRI prefix."""
    prefix = graph_queries.verifiable_memory_prefix(successor) if successor else ""
    in_successor = frozenset(asset for asset in assets if prefix and asset.startswith(prefix))
    return assets - in_successor, in_successor


def _before_cut(assets: frozenset[str], facts: Mapping[str, AssetFacts], from_day: str,
                legacy_uals: frozenset[str]) -> frozenset[str]:
    """The configured graph's *assets* still in scope once a successor is in
    effect: those in the verified legacy list, and those whose day is before
    *from_day*. Staying in scope needs a definite earlier day: an asset whose
    UAL or day is not known (yet) is left out — the action here is believing
    a row, so "could not tell" never counts as "before" (LES-011)."""
    kept = frozenset(asset for asset in assets
                     if (fact := facts.get(asset)) is not None
                     and ((fact.ual and fact.ual in legacy_uals) or (fact.day and fact.day < from_day)))
    if len(kept) < len(assets):
        logger.info("blackbox: successor graph in effect — %d asset(s) of the configured graph dated from %s "
                    "(or undated) are out of the verified scope", len(assets) - len(kept), from_day)
    return kept


def _tier_new_assets(client: DkgClient, context_graph_id: str, store: StoreClient,
                     facts: dict[str, AssetFacts], legacy_uals: frozenset[str],
                     successor: str = "") -> dict[str, AssetFacts]:
    """Decide every undecided asset once (§03.4): BLOCK when it is in the
    verified legacy list (R1), else from its signed envelopes against the
    manifest in force on its day (R2). The manifest history is read only when
    an asset is still undecided — zero cost on the recurring path — and when
    it cannot be read, or holds no list, envelopes decide nothing (LES-011).

    The envelope must name the graph its asset lives in: the configured graph,
    or the *successor* (R5) for the successor's assets. The manifests are the
    configured graph's either way — the migration moves where rows are
    published, not who curates them."""
    history = _manifest_history(client, context_graph_id) if any(f.tier is None for f in facts.values()) else None
    if legacy_uals or history:                            # an empty list and no history: no _meta read
        facts = tier_assets(store, facts, legacy=legacy_uals)
    if history:
        old_assets, new_assets = _by_graph(frozenset(facts), successor)
        for verified_graph, assets in ((context_graph_id, old_assets), (successor, new_assets)):
            if assets:
                facts.update(decide_by_envelope(store, {asset: facts[asset] for asset in assets},
                                                manifest_for_day=lambda day: community.manifest_on_day(history, day),
                                                verified_graph=verified_graph, today=community.curator_today()))
    return facts


def _manifest_history(client: DkgClient, context_graph_id: str) -> Optional[tuple[Any, ...]]:
    """The verified graph's root-signed manifests (None = unreadable or none)."""
    try:
        environment = community.network_environment(client.status(timeout=5.0))
    except DkgError as exc:
        logger.debug("blackbox: node status unavailable for the asset tiers: %s", exc)
        return None
    return community.verified_manifest_history(client, context_graph_id, environment) or None


def _store_url(client: DkgClient) -> str:
    try:
        return loopback_store_url(client.status(timeout=5.0))
    except DkgError as exc:
        logger.debug("blackbox: node status unavailable for the store endpoint: %s", exc)
        return ""


def scope_for_generation(
    client: DkgClient,
    context_graph_id: str,
    *,
    previous: Optional[VerifiedScope],
    suppressed: Optional[Iterable[str]],
    revoked: Iterable[str],
    listing: Optional[fetching.PartitionListing] = None,
    fallback: str = "off",
    legacy_assets_hash: Optional[str] = None,
) -> Optional[VerifiedScope]:
    """:func:`refresh_scope` fed by the node's partition listing (*listing* when
    the refresh already read it, else read now) — what the refresh cycle calls
    on every path. The active verified graph is resolved first (R5): when a
    successor is in effect its listing is read too and the cut-off applies.
    Fail-open: when anything raises, the previous scope stays (a scope problem
    never costs the generation)."""
    try:
        listing = listing or fetching.confirmed_partitions(client, context_graph_id)
        migration = community.active_verified_graph(client, BlackboxConfig(context_graph_id=context_graph_id)).migration
        successor = fetching.confirmed_partitions(client, migration.to_graph) if migration is not None else None
        return refresh_scope(
            client, context_graph_id, previous=previous,
            confirmed=listing.confirmed if listing is not None else None,
            suppressed=suppressed, revoked=revoked, fallback=fallback, legacy_assets_hash=legacy_assets_hash,
            migration=migration, successor_confirmed=successor.confirmed if successor is not None else None,
        )
    except Exception as exc:  # pragma: no cover - fail open (an outer boundary)
        logger.warning("blackbox: verified scope not refreshed: %s", exc)
        return previous
