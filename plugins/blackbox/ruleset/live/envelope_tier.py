"""An asset's tier decided ONCE from its rows' signed promotion envelopes (trust-and-threat-lab R2, §03.4).

After the legacy pin, the wallet alone can publish into the verified graph, so
a row is believed as BLOCK only when it carries a ``blackbox.promotion``
envelope that the key manifest in force on the asset's day accepts
(``has_quorum``: statement type, graph, chain, epoch, threshold of distinct
operators). Everything else is flag-only (F-010).

Three rules decide what a verified row may block on (the wallet alone never decides):

* the manifest that decides is the one in force on the asset's day — never
  the current list, so a routine rotation never un-blocks the curated corpus;
  the tier is decided once, carried in the facts and never re-tiered (a key
  removed later acts only through an explicit revocation);
* the rule a BLOCK row is served as comes from the signed payload; the row's
  unsigned triples only locate it;
* a row whose shown rule — what the reader's own builders make of its triples
  (:func:`..partitions.rows_from_triples` + ``row_adapters._row_to_rule``, the
  same code the live lookup runs) — names anything other than the signed
  identifier is a transplanted envelope: it is never served, its whole asset
  is FLAG, and it is an alarm input.

Cost: one VALUES-bound, LIMITed query per batch of NEW assets, with the facts
lane's pause after it and inside its budget (LES-040); nothing on the
recurring path, because a decided asset is never read again.

Pattern: Specification — :func:`rule_disagrees` is the ONE test "does this
built rule name what was signed", used here and on the hot path
(:meth:`.scope.VerifiedScope.as_tier_allows`). Usage::

    facts = decide_by_envelope(store, facts, manifest_for_day=lambda day: ..., verified_graph=graph_id,
                               today="2026-11-02")
"""

from __future__ import annotations

import logging
import time
from dataclasses import replace
from typing import Any, Callable, Mapping, Optional

from ...kernel import constants, signing, threat_ids
from ...kernel.dkg_client import extract_binding
from ...kernel.signing import key_manifest
from ...kernel.signing import CuratorStatement
from ...kernel.store import StoreClient
from .. import graph_queries, row_adapters
from ..partitions import rows_from_triples
from . import asset_facts
from .asset_facts import AssetFacts, AssetTier, SignedRule

logger = logging.getLogger(__name__)

#: The statement type a promoted row's envelope must carry.
PROMOTION_STATEMENT = CuratorStatement.PROMOTION.value
#: Rows per signed-rows query: 20 assets x <= 50 promoted rows x ~15 triples, with headroom.
#: A batch that comes back with this many rows may be cut short, so nothing in it is decided.
ROW_LIMIT = 20_000

#: Which key manifest was in force on a UTC day (None = none was).
ManifestForDay = Callable[[str], Optional[key_manifest.KeyManifest]]
Triple = tuple[str, str, str]


def decide_by_envelope(store: StoreClient, facts: Mapping[str, AssetFacts], *, manifest_for_day: ManifestForDay,
                       verified_graph: str, today: str,
                       budget_seconds: float = asset_facts.BUDGET_SECONDS) -> dict[str, AssetFacts]:
    """*facts* with every undecided asset whose ``_meta`` was read (its UAL is
    known, so legacy membership is settled) decided BLOCK or FLAG from its
    signed rows, judged by the manifest in force on the asset's day (its
    ``_meta`` day, never later than *today* = first sight). A decided tier is
    never changed; a batch the store could not answer, or answered at the row
    limit, decides nothing (could not tell, LES-011) and is read next refresh."""
    decided = dict(facts)
    undecided = sorted(graph for graph, fact in decided.items() if fact.tier is None and fact.ual)
    deadline = time.monotonic() + budget_seconds
    for start in range(0, len(undecided), asset_facts.BATCH):
        if time.monotonic() >= deadline:
            logger.info("blackbox: asset tiers — %d asset(s) wait for the next refresh", len(undecided) - start)
            break
        batch = undecided[start:start + asset_facts.BATCH]
        signed_rows = _read_signed_rows(store, batch)
        if signed_rows is None:
            break
        for graph in batch:
            day = min(decided[graph].day or today, today)
            decided[graph] = _decide(decided[graph], graph, signed_rows.get(graph, {}), manifest_for_day(day),
                                     verified_graph)
    return decided


def rule_disagrees(category: str, key: str, rule: Mapping[str, Any], signed: SignedRule) -> bool:
    """True when the rule built from a row (``category``, lookup ``key``,
    ``rule`` as ``row_adapters._row_to_rule`` returns them) names anything but
    the *signed* identifier — by its identifier, or by the fields detection
    matches it on (a dependency's ecosystem/name/version key, an IOC's
    type/value). Rows that only locate the signed rule agree."""
    if rule.get("identifier") != signed.identifier:
        return True
    if category == "dependency":
        named = threat_ids.parse_dependency_identifier(signed.identifier)
        return named is None or key != threat_ids.dependency_key(*named)
    if category == "ioc":
        try:
            shown = threat_ids.ioc_identifier(str(rule.get("iocType") or ""), str(rule.get("value") or ""))
        except (TypeError, ValueError):
            return True
        return shown != signed.identifier or key != signed.identifier
    return key != signed.identifier


def _decide(fact: AssetFacts, graph: str, subjects: Mapping[str, list[Triple]],
            manifest: Optional[key_manifest.KeyManifest], verified_graph: str) -> AssetFacts:
    """One asset's tier: BLOCK when at least one row carries a quorum envelope
    and no row shows a rule its signature does not name; FLAG otherwise."""
    signed: dict[str, SignedRule] = {}
    ignored = set()
    for subject, triples in sorted(subjects.items()):
        rule = _quorum_rule(triples, manifest, verified_graph)
        if rule is None:
            continue   # no envelope a quorum accepts: an unsigned row (flag-only)
        if _shows_another_rule(graph, triples, rule):
            ignored.add(subject)
            logger.warning("blackbox: SECURITY — verified row %s in %s shows a rule its signed envelope does not "
                           "name (%s); the row is ignored and its asset is flag-only", subject, graph, rule.identifier)
            continue
        signed[subject] = rule
    if signed and not ignored:
        return replace(fact, tier=AssetTier.BLOCK, signed=signed)
    return replace(fact, tier=AssetTier.FLAG, signed={}, ignored=frozenset(ignored))


def _quorum_rule(triples: list[Triple], manifest: Optional[key_manifest.KeyManifest],
                 verified_graph: str) -> Optional[SignedRule]:
    """The signed rule of a row whose ONE envelope the *manifest* accepts as a
    promotion in *verified_graph*; None otherwise (two envelopes on one row are
    ambiguous, so neither counts)."""
    literals = {extract_binding(obj) for _subject, predicate, obj in triples if predicate == constants.SIGNED_STATEMENT_PRED}
    if manifest is None or len(literals) != 1:
        return None
    envelope = signing.from_text(literals.pop())
    if envelope is None or not manifest.has_quorum(envelope, statement_type=PROMOTION_STATEMENT, graph=verified_graph):
        return None
    rule = SignedRule.from_payload(envelope.payload)
    return rule if rule.identifier else None


def _shows_another_rule(graph: str, triples: list[Triple], signed: SignedRule) -> bool:
    """True when ANY rule the reader's builders make of the row disagrees with
    *signed* (:func:`rule_disagrees`) — a typed row yields one rule per branch,
    and a multi-valued locator one per value, so each is checked."""
    for row in rows_from_triples(graph, triples):
        mapped = row_adapters._row_to_rule(row, "public")
        if mapped is not None and rule_disagrees(mapped[0], mapped[1], mapped[2], signed):
            return True
    return False


def _read_signed_rows(store: StoreClient, batch: list[str]) -> Optional[dict[str, dict[str, list[Triple]]]]:
    """Asset graph → signed subject → its triples, for *batch*; None when the
    store failed or the answer may be cut short."""
    sparql = graph_queries.signed_rows_sparql(batch, ROW_LIMIT)
    if not sparql:
        return {}
    answer = store.select(sparql, timeout=asset_facts.QUERY_TIMEOUT_SECONDS)
    time.sleep(asset_facts.PAUSE_SECONDS)
    if not answer.known:
        logger.warning("blackbox: signed verified rows not read (%s); retrying next refresh", answer.reason)
        return None
    rows = answer.rows or []
    if len(rows) >= ROW_LIMIT:
        logger.warning("blackbox: signed verified rows reached the row limit; these assets stay undecided")
        return None
    wanted = set(batch)
    by_graph: dict[str, dict[str, list[Triple]]] = {}
    for row in rows:
        graph = extract_binding(row.get("g"))
        if graph in wanted:
            by_graph.setdefault(graph, {}).setdefault(extract_binding(row.get("t")), []).append(
                (extract_binding(row.get("t")), extract_binding(row.get("p")), row.get("o") or ""))
    return by_graph
