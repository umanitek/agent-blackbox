"""The correction pin one refresh compiles with (trust-and-threat-lab R3; review 2026-11-26).

:mod:`.corrections` decides — purely — which ``CorrectionSignal`` rows count,
given a :class:`.corrections.CorrectionPin`. This module builds that pin from
what the node holds, so the PRODUCTION compile obeys it (before, only tests
passed a pin and the refresh honoured every unsigned correction):

* while no trusted curator manifest pins a legacy list — ``legacy_assets_hash``
  "" (no trusted manifest: today's default, no curator root is pinned for any
  network) or None (could not tell, and no earlier verdict) — no pin is in force
  and every correction is honoured as before R3 (:data:`.corrections.NO_PIN`);
* once one does, a correction counts when its asset is in the verified legacy
  list, or when it carries a quorum envelope under the manifest in force on its
  asset's day. A list whose hash does not match the pin makes no asset legacy:
  only signed corrections count (a correction REDUCES enforcement, so "could
  not tell" never honours an unsigned one) — except that an asset whose UAL
  could not be read this time keeps the verdict the last scope gave its
  corrections (the last verdict stands, LES-011).

Only the assets that hold a correction are looked at (one, on the live graph):
their UAL and day come from the previous scope's facts, else one bounded
``_meta`` read (:func:`.asset_facts.tier_assets`); the manifest history is read
only when such an asset is outside the legacy list.

Pattern: Builder. Usage::

    pin = correction_pin(client, graph, tagged_rows, legacy_assets_hash=pin_hash, previous=prior_scope)
    rs = compiler.build_from_rows(tagged_rows, pin=pin)
"""

from __future__ import annotations

import logging
from typing import Iterable, Mapping, Optional

from ... import community
from ...kernel import constants
from ...kernel.dkg_client import DkgClient, DkgError, extract_binding
from ...kernel.signing import key_manifest
from ...kernel.store import StoreClient, loopback_store_url
from .. import anchors
from .asset_facts import AssetFacts, tier_assets
from .corrections import NO_PIN, PUBLIC_SOURCE, CorrectionPin, TaggedRow
from .scope import VerifiedScope

logger = logging.getLogger(__name__)


def correction_pin(client: DkgClient, context_graph_id: str, rows: Iterable[TaggedRow], *,
                   legacy_assets_hash: Optional[str], previous: Optional[VerifiedScope]) -> CorrectionPin:
    """The pin for compiling *rows* (``(row, source)`` pairs) of *context_graph_id*.

    *legacy_assets_hash* — the trusted manifest's legacy pin as this refresh
    knows it (``curator_tier.legacy_pin``); *previous* — the last generation's
    scope (its asset facts and suppressions), None on a first refresh."""
    if not legacy_assets_hash:
        return NO_PIN
    legacy_uals = anchors.verified_legacy_assets(legacy_assets_hash).uals or frozenset()
    targets = _targets_by_graph(rows)
    if not targets:
        return CorrectionPin({}, frozenset())
    facts = _located(client, frozenset(targets), previous)
    in_list = {graph for graph in targets if facts[graph].ual and facts[graph].ual in legacy_uals}
    # An asset not located this time keeps the last scope's verdict on its corrections.
    held = previous.suppressed_subjects if previous is not None else frozenset()
    in_list |= {graph for graph, subjects in targets.items() if not facts[graph].ual and subjects <= held}
    outside = frozenset(targets) - in_list
    return CorrectionPin(_manifests(client, context_graph_id, outside, facts) if outside else {}, frozenset(in_list))


def _targets_by_graph(rows: Iterable[TaggedRow]) -> dict[str, frozenset[str]]:
    """assertion graph -> the subjects its public correction rows target."""
    targets: dict[str, set] = {}
    for row, source in rows:
        if source != PUBLIC_SOURCE or extract_binding(row.get("rdfType")) != constants.DEFENDER_CORRECTION_TYPE_IRI:
            continue
        graph = extract_binding(row.get("g")).strip()
        targets.setdefault(graph, set()).add(extract_binding(row.get("targetSubject")).strip())
    return {graph: frozenset(subjects) for graph, subjects in targets.items()}


def _located(client: DkgClient, graphs: frozenset[str], previous: Optional[VerifiedScope]) -> dict[str, AssetFacts]:
    """*graphs*' facts with their UAL and day where they can be known: the previous
    scope's, else read now from the node's ``_meta`` (left unknown when it cannot be)."""
    known = dict(previous.asset_facts) if previous is not None else {}
    facts = {graph: known.get(graph, AssetFacts()) for graph in graphs}
    if all(fact.ual for fact in facts.values()):
        return facts
    store = _store(client)
    return {**facts, **tier_assets(store, facts, legacy=frozenset())} if store is not None else facts


def _store(client: DkgClient) -> Optional[StoreClient]:
    try:
        url = loopback_store_url(client.status(timeout=5.0))
    except DkgError as exc:
        logger.debug("blackbox: node status unavailable for the correction pin: %s", exc)
        return None
    return StoreClient(url) if url else None


def _manifests(client: DkgClient, context_graph_id: str, graphs: frozenset[str],
               facts: Mapping[str, AssetFacts]) -> dict[str, key_manifest.KeyManifest]:
    """assertion graph -> the manifest in force on its asset's day (never later than
    today, as the envelope tier judges it); {} when the history cannot be read."""
    try:
        environment = community.network_environment(client.status(timeout=5.0))
    except DkgError as exc:
        logger.debug("blackbox: node status unavailable for the correction manifests: %s", exc)
        return {}
    history = community.verified_manifest_history(client, context_graph_id, environment)
    if not history:
        return {}
    today = community.curator_today()
    in_force = {graph: community.manifest_on_day(history, min(facts[graph].day or today, today)) for graph in graphs}
    return {graph: manifest for graph, manifest in in_force.items() if manifest is not None}
