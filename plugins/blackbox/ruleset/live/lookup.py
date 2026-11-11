"""Exact verified-rule lookups against the node's local store.

Pattern: Facade — detection asks two questions (``dependencies``, ``iocs``)
and never sees SPARQL, the scope filter or the row builder. Equivalence with
the compiled rules is by REUSE, not by a second implementation: the matching
subjects' triples come back and go through :func:`partitions.rows_from_triples`
and :func:`row_adapters._row_to_rule`, exactly as the compiler did.

Safety:

* untrusted values (what the agent is doing) enter a query only as escaped
  string literals (``sparql_string_literal``, LES-001/002), never as IRIs or
  query text;
* every query names its predicates and carries a LIMIT (LES-013);
* a row counts only when its graph is in the scope, its subject is not
  suppressed and its identifier not revoked;
* a store that failed or timed out gives ``COULD_NOT_TELL`` — hits found
  before the failure are still hits, but the absence of a hit proves nothing;
* every outcome is recorded in :data:`.health.HEALTH`, so a degraded store is
  visible to `blackbox status` and the dashboard, never silent.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from ...kernel import constants
from ...kernel import crypto_secrets
from ...kernel.dkg_client import extract_binding
from ...kernel.sparql_text import sparql_string_literal as literal
from ...kernel.store import StoreClient
from .. import row_adapters
from ..partitions import rows_from_triples
from .health import HEALTH, LookupHealth
from .scope import VerifiedScope

logger = logging.getLogger(__name__)

HIT = "hit"
CLEAN = "clean"
COULD_NOT_TELL = "could-not-tell"

#: Values per query. A 50-value IOC batch answered in 17 ms on the bench.
CHUNK = 200
#: The most values one call looks up — the content scanner's own candidate cap.
MAX_VALUES = 4000
#: Rows per query: candidates × ~15 triples each, with headroom.
ROW_LIMIT = 20_000
#: EVM addresses per call also asked for in their EIP-55 spelling (~0.3 ms each).
CHECKSUM_SPELLINGS = 64
#: While the store is degraded, one lookup probes it at most this often; the rest answer
#: could-not-tell at once. Why: a wedged store (port open, not answering — the restart-recovery
#: window) otherwise costs every tool call the 2 s timeout per chunk, dependency and IOC each.
RETRY_AFTER_SECONDS = 10.0

_DP = constants.DEFENDER_PREDICATES
_BP = constants.BLACKBOX_PREDICATES

DependencyCandidate = tuple[str, str, str]   # (ecosystem, package name, version or "*")


@dataclass(frozen=True)
class LookupAnswer:
    """``rules`` — matched public rules keyed as the compiled dicts were
    (``eco:name@version`` for dependencies, ``ioc:type:value`` for IOCs);
    ``outcome`` — ``HIT`` / ``CLEAN`` / ``COULD_NOT_TELL``; ``reason`` — the
    store's reason when it could not tell."""

    rules: dict[str, dict[str, Any]] = field(default_factory=dict)
    outcome: str = CLEAN
    reason: str = ""

    @property
    def known(self) -> bool:
        return self.outcome != COULD_NOT_TELL


class VerifiedLookup:
    """Exact lookups for one scope against one store. Stateless; build one per
    ruleset generation (:func:`compiler.Ruleset.live_lookup`)."""

    def __init__(self, scope: VerifiedScope, store: StoreClient, health: Optional[LookupHealth] = None,
                 fallback: Any = None) -> None:
        self.scope = scope
        self.store = store
        self.health = health or HEALTH
        #: The opt-in on-disk index (:class:`.fallback_index.FallbackIndex`), None by default.
        self.fallback = fallback

    def dependencies(self, candidates: Sequence[DependencyCandidate]) -> LookupAnswer:
        """Public dependency rules for exactly these ``(ecosystem, name, version)``
        triples; pass ``"*"`` as the version for a whole-package rule."""
        tuples: list[tuple[str, str, str]] = []
        for ecosystem, name, version in candidates[:MAX_VALUES]:
            ecosystem = ecosystem.strip().lower()
            for spelling in self.scope.spellings(ecosystem, name):
                tuples.append((spelling, ecosystem, version.strip()))
        return self._run(tuples, _dependency_sparql, "dependency")

    def iocs(self, identifiers: Sequence[str]) -> LookupAnswer:
        """Public IOC rules among these ``ioc:type:value`` identifiers (already
        normalised by ``threat_ids.ioc_identifier``). The store is asked by
        value — for an EVM wallet/contract by both spellings a feed may have
        stored (:func:`_stored_spellings`); the answer is keyed by the
        identifier the graph gives the rule, which the row builder normalises."""
        values = list(dict.fromkeys(_stored_spellings(identifiers[:MAX_VALUES])))
        return self._run(values, _ioc_sparql, "ioc")

    def _run(self, items: Sequence[Any], build_query: Any, category: str) -> LookupAnswer:
        if not items:
            return LookupAnswer({}, CLEAN)
        skipped = None if not self.scope.ready else self._while_degraded()   # not-ready is its own answer, recorded as before
        if skipped is not None:
            answer = skipped                                   # the breaker: not asked, not recorded
        else:
            answer = self._ask(items, build_query, category)
            self.health.record(answer.known, answer.reason)    # the STORE's health, whatever answers next
        if not answer.known and self.fallback is not None:
            return self._from_fallback(items, category, answer)
        return answer

    def _while_degraded(self) -> Optional[LookupAnswer]:
        """The could-not-tell answer to give without asking, while the store is degraded
        and its last probe is younger than :data:`RETRY_AFTER_SECONDS`; None = ask."""
        state = self.health.read()
        if not state.degraded or time.time() - state.last_at >= RETRY_AFTER_SECONDS:
            return None
        return LookupAnswer({}, COULD_NOT_TELL,
                            f"store degraded ({state.reason or 'did not answer'}); next probe in "
                            f"{RETRY_AFTER_SECONDS:.0f} s")

    def _from_fallback(self, items: Sequence[Any], category: str, store_answer: LookupAnswer) -> LookupAnswer:
        """The last resort (B9): the operator-enabled index answers; hits the store
        found before failing are kept; absence from a partial index stays could-not-tell."""
        if category == "dependency":
            fallback = self.fallback.dependencies([(eco, pkg, ver) for pkg, eco, ver in items])
        else:
            fallback = self.fallback.ioc_values(list(items))
        rules = {**fallback.rules, **store_answer.rules}
        return LookupAnswer(rules, HIT if rules else fallback.outcome, fallback.reason)

    def _ask(self, items: Sequence[Any], build_query: Any, category: str) -> LookupAnswer:
        if not self.scope.ready:
            return LookupAnswer({}, COULD_NOT_TELL, "verified scope not ready")
        rules: dict[str, dict[str, Any]] = {}
        for start in range(0, len(items), CHUNK):
            answer = self.store.select(build_query(items[start:start + CHUNK]))
            if not answer.known:
                return LookupAnswer(rules, COULD_NOT_TELL, answer.reason)
            rules.update(self._rules_from(answer.rows or [], category))
        return LookupAnswer(rules, HIT if rules else CLEAN)

    def _rules_from(self, rows: Iterable[dict[str, str]], category: str) -> dict[str, dict[str, Any]]:
        """Triples → rules through the compiler's own builders, scope applied
        (a FLAG-tier asset's rules capped at flag, a signed asset's served from
        their signed payload, a transplanted row dropped — :meth:`VerifiedScope.as_tier_allows`)."""
        by_graph: dict[str, list[tuple[str, str, str]]] = {}
        for row in rows:
            graph = extract_binding(row.get("g"))
            subject = extract_binding(row.get("t"))
            if graph not in self.scope.assertion_graphs or subject in self.scope.suppressed_subjects:
                continue
            by_graph.setdefault(graph, []).append((subject, extract_binding(row.get("p")), row.get("o") or ""))
        rules: dict[str, dict[str, Any]] = {}
        for graph, triples in by_graph.items():
            for built_row in rows_from_triples(graph, triples):
                mapped = row_adapters._row_to_rule(built_row, "public")
                if mapped is None or mapped[0] != category:
                    continue
                _category, key, rule = mapped
                if rule.get("identifier") in self.scope.revoked_identifiers:
                    continue
                allowed = self.scope.as_tier_allows(graph, category, key, rule)
                if allowed is not None:
                    rules.setdefault(key, allowed)
        return rules


def _stored_spellings(identifiers: Sequence[str]) -> list[str]:
    """The literal values to ask the store for these identifiers: each value as
    normalised (lower-case for an EVM address) and, for the first
    :data:`CHECKSUM_SPELLINGS` EVM wallets/contracts, its EIP-55 checksum spelling too.

    WHY both (KI-387): the store compares literals exactly, and a feed may publish an
    address checksummed. Asking for the two spellings in the VALUES list keeps the
    query an exact, bounded lookup; a LCASE() comparison would scan the shared store
    and can get it restarted (LES-040). Any other casing is not found."""
    out: list[str] = []
    checksummed = 0
    for identifier in identifiers:
        parts = identifier.split(":", 2)
        if len(parts) != 3:
            continue
        out.append(parts[2])
        if parts[1] in ("wallet", "contract") and checksummed < CHECKSUM_SPELLINGS:
            spelling = crypto_secrets.checksum_address(parts[2])
            if spelling and spelling != parts[2]:
                out.append(spelling)
                checksummed += 1
    return out


def _dependency_sparql(tuples: Sequence[tuple[str, str, str]]) -> str:
    values = " ".join(f"({literal(pkg)} {literal(eco)} {literal(ver)})" for pkg, eco, ver in tuples)
    return f"""SELECT ?g ?t ?p ?o WHERE {{
  VALUES (?pkg ?eco ?ver) {{ {values} }}
  GRAPH ?g {{
    ?t <{_DP}package> ?pkg ; <{_DP}ecosystem> ?eco ; <{_DP}version> ?ver .
    ?t ?p ?o .
  }}
}} LIMIT {ROW_LIMIT}"""


def _ioc_sparql(values: Sequence[str]) -> str:
    literals = " ".join(literal(value) for value in values)
    return f"""SELECT ?g ?t ?p ?o WHERE {{
  VALUES ?val {{ {literals} }}
  GRAPH ?g {{
    {{ ?t <{_DP}value> ?val . }} UNION {{ ?t <{_BP}normalizedValue> ?val . }}
    ?t ?p ?o .
  }}
}} LIMIT {ROW_LIMIT}"""
