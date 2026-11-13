"""Per-asset facts — counts and package spellings — read ONCE per verified asset.

WHY: the refresh used to count the live tiers and scan for odd package spellings
over the WHOLE store every time (7–20 s of full scans). The node's store is shared
with the DKG node itself, whose supervisor restarts Oxigraph when one of the node's
own queries misses its deadline — and a Blackbox scan on a busy 2-vCPU node can
cause exactly that (bench A 05:15 / C 04:19 UTC, 2026-10-10). A confirmed asset is
anchored on chain and never changes, so its facts are read once, in small batches
bound to named graphs (index lookups, not scans), with a pause between queries so
the node's own queries interleave, and carried forward forever after. After the
first sync a refresh reads nothing here.

Each asset also carries its :class:`AssetTier` (trust-and-threat-lab §03.4):
BLOCK when it is in the verified legacy list, FLAG when its rows may only flag,
None while undecided — None never caps a rule, so an upgrade or a refused list
can never turn the known corpus flag-only (F-055). The UAL the legacy list is
keyed by, and the day the node lists the asset under, are read only while a
verified list is in force and the tier is open. An asset outside the list is
decided from its rows' signed promotion envelopes (:mod:`.envelope_tier`, R2),
which also records each signed row's :class:`SignedRule` — the rule a BLOCK
row is served as — and the rows whose shown rule disagrees with their
signature (``ignored``: never served, an alarm input).

Pattern: Cache-aside over immutable keys (the asset IRI). Usage::

    facts = read_new_asset_facts(store, wanted=scope_graphs, known=previous_facts)
    facts = tier_assets(store, facts, legacy=verified_legacy_uals)   # only with a verified list
    facts = envelope_tier.decide_by_envelope(store, facts, ...)     # only with a manifest history
    counts, aliases = totals(facts, scope_graphs)
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field, replace
from datetime import date
from enum import Enum
from typing import Any, Iterable, Mapping, Optional

from ...kernel import constants, sparql_text, threat_ids
from ...kernel.dkg_client import extract_binding
from ...kernel.store import StoreClient
from .. import row_adapters

logger = logging.getLogger(__name__)

#: Assets per query: VALUES-bound graphs keep each query an index lookup.
BATCH = 20
#: Seconds each query may take, and the pause between queries (the node's own
#: queries run in the gaps).
QUERY_TIMEOUT_SECONDS = 20.0
PAUSE_SECONDS = 0.2
#: Total seconds one refresh spends here; the rest waits for the next refresh.
BUDGET_SECONDS = 120.0

_TYPE = constants.RDF_TYPE
_DP = constants.DEFENDER_PREDICATES
_BP = constants.BLACKBOX_PREDICATES
#: Key prefix of the per-ecosystem dependency counts (``"dependency:npm"``).
ECOSYSTEM_COUNT_PREFIX = "dependency:"
_DKG = "http://dkg.io/ontology/"
_VM_SEGMENT = "/_verifiable_memory/"
_DAY_LENGTH = len("YYYY-MM-DD")


class AssetTier(Enum):
    """What an asset's rules may do: BLOCK (blockable as verified) or FLAG (flag only)."""

    BLOCK = "block"
    FLAG = row_adapters.FLAG_TIER   # the one spelling (row_adapters, which live may import)


@dataclass(frozen=True)
class SignedRule:
    """The rule a quorum-signed promotion names — taken from the envelope's
    signed payload, never from the row's unsigned triples. Fields
    mirror ``row_builders.SIGNED_RULE_FIELDS``; ``package_*`` / ``ecosystem``
    are empty for the categories they do not apply to."""

    identifier: str
    severity: str = ""
    kind: str = ""
    ecosystem: str = ""
    package_name: str = ""
    package_version: str = ""

    @classmethod
    def from_payload(cls, payload: Mapping[str, str]) -> SignedRule:
        return cls(identifier=str(payload.get("identifier") or ""), severity=str(payload.get("severity") or ""),
                   kind=str(payload.get("kind") or ""), ecosystem=str(payload.get("ecosystem") or ""),
                   package_name=str(payload.get("packageName") or ""),
                   package_version=str(payload.get("packageVersion") or ""))

    def to_json(self) -> dict[str, str]:
        return {"identifier": self.identifier, "severity": self.severity, "kind": self.kind,
                "ecosystem": self.ecosystem, "packageName": self.package_name, "packageVersion": self.package_version}

    def served(self, rule: Mapping[str, Any]) -> dict[str, Any]:
        """*rule* (built from the row) with every field the signature names
        taken from the payload: identifier, severity, kind, version."""
        served = {**rule, "identifier": self.identifier,
                  "severity": constants.normalize_severity(self.severity, "high")}
        if self.kind:
            served["kind"] = self.kind
        if self.package_version and "packageVersion" in served:
            served["packageVersion"] = self.package_version
        return served


@dataclass(frozen=True)
class AssetFacts:
    """One asset's facts. ``counts`` — rules by tier (``dependency``, ``ioc``) and
    dependency rules per ecosystem (``dependency:<eco>``); ``aliases`` —
    ``"eco:canonical"`` → stored spellings that differ from the canonical one;
    ``ual`` — the asset's UAL from the node's ``_meta`` ("" = not read yet);
    ``day`` — the UTC day ``_meta`` lists the asset under ("" = none given;
    read with the UAL); ``tier`` — None = not decided yet (read again; never
    caps a rule); ``signed`` — threat subject → its :class:`SignedRule`, for an
    asset decided by its envelopes (empty for a legacy or FLAG asset);
    ``ignored`` — subjects whose shown rule disagrees with their signed one,
    never served at all (a transplanted envelope)."""

    counts: Mapping[str, int] = field(default_factory=dict)
    aliases: Mapping[str, tuple[str, ...]] = field(default_factory=dict)
    ual: str = ""
    tier: Optional[AssetTier] = None
    day: str = ""
    signed: Mapping[str, SignedRule] = field(default_factory=dict)
    ignored: frozenset[str] = frozenset()

    def to_json(self) -> dict[str, Any]:
        return {"counts": dict(self.counts), "aliases": {k: list(v) for k, v in self.aliases.items()},
                **({"ual": self.ual} if self.ual else {}), **({"tier": self.tier.value} if self.tier else {}),
                **({"day": self.day} if self.day else {}),
                **({"signed": {subject: rule.to_json() for subject, rule in sorted(self.signed.items())}}
                   if self.signed else {}),
                **({"ignored": sorted(self.ignored)} if self.ignored else {})}

    @classmethod
    def from_json(cls, data: Any) -> Optional[AssetFacts]:
        """Facts from :meth:`to_json`; a record written before tiers existed (or
        with an unknown tier) yields ``tier`` None — decided again, never FLAG."""
        if not isinstance(data, dict):
            return None
        counts, aliases, signed = data.get("counts"), data.get("aliases"), data.get("signed")
        tier = next((member for member in AssetTier if member.value == data.get("tier")), None)
        return cls(
            counts={str(k): int(v) for k, v in counts.items() if isinstance(v, (int, float))}
            if isinstance(counts, dict) else {},
            aliases={str(k): tuple(str(x) for x in v) for k, v in aliases.items() if isinstance(v, list)}
            if isinstance(aliases, dict) else {},
            ual=str(data.get("ual") or ""),
            tier=tier,
            day=str(data.get("day") or ""),
            signed={str(subject): SignedRule.from_payload(raw) for subject, raw in signed.items()
                    if isinstance(raw, dict) and raw.get("identifier")} if isinstance(signed, dict) else {},
            ignored=frozenset(str(subject) for subject in data.get("ignored") or () if subject)
            if isinstance(data.get("ignored"), list) else frozenset(),
        )


def read_new_asset_facts(store: StoreClient, *, wanted: frozenset[str], known: Mapping[str, AssetFacts],
                         budget_seconds: float = BUDGET_SECONDS) -> dict[str, AssetFacts]:
    """*known* facts for the assets still wanted, plus facts read now for the wanted
    assets not known yet — in batches, within the budget, stopping at the first
    query the store could not answer (the rest are read on a later refresh)."""
    facts = {graph: fact for graph, fact in known.items() if graph in wanted}
    missing = sorted(graph for graph in wanted if graph not in facts)
    deadline = time.monotonic() + budget_seconds
    for start in range(0, len(missing), BATCH):
        if time.monotonic() >= deadline:
            logger.info("blackbox: verified asset facts — %d asset(s) wait for the next refresh", len(missing) - start)
            break
        batch = missing[start:start + BATCH]
        read = _read_batch(store, batch)
        if read is None:
            break
        facts.update(read)
    return facts


def tier_assets(store: StoreClient, facts: Mapping[str, AssetFacts], *, legacy: frozenset[str],
                budget_seconds: float = BUDGET_SECONDS) -> dict[str, AssetFacts]:
    """*facts* with every undecided asset in the verified *legacy* list tiered
    BLOCK. UALs and days are read (one ``_meta`` query per batch, bound to each
    asset's graph) only for undecided assets whose UAL is not known yet; a
    decided tier is never changed here. An asset outside the list stays
    undecided (the curator envelope decides it, :mod:`.envelope_tier`)."""
    tiered = dict(facts)
    unlocated = sorted(graph for graph, fact in tiered.items() if fact.tier is None and not fact.ual)
    deadline = time.monotonic() + budget_seconds
    for start in range(0, len(unlocated), BATCH):
        if time.monotonic() >= deadline:
            break
        located = _read_meta(store, unlocated[start:start + BATCH])
        if located is None:
            break
        tiered.update({graph: replace(tiered[graph], ual=ual, day=day) for graph, (ual, day) in located.items()})
    return {graph: replace(fact, tier=AssetTier.BLOCK) if fact.tier is None and fact.ual in legacy else fact
            for graph, fact in tiered.items()}


def totals(facts: Mapping[str, AssetFacts], graphs: Iterable[str]) -> tuple[dict[str, int], dict[str, tuple[str, ...]]]:
    """Counts summed and aliases merged over *graphs* (assets without facts add nothing)."""
    counts: dict[str, int] = {}
    aliases: dict[str, set] = {}
    for graph in graphs:
        fact = facts.get(graph)
        if fact is None:
            continue
        for key, value in fact.counts.items():
            counts[key] = counts.get(key, 0) + int(value)
        for key, spellings in fact.aliases.items():
            aliases.setdefault(key, set()).update(spellings)
    return counts, {key: tuple(sorted(values)) for key, values in aliases.items()}


def _values(batch: list[str]) -> str:
    """*batch* as a VALUES list; a graph name that cannot be written as ``<iri>`` is left out
    (store-sourced text never reaches a query unchecked — kernel ``sparql_iri``)."""
    return " ".join(filter(None, map(sparql_text.sparql_iri, batch)))


def _queries(batch: list[str]) -> list[tuple[str, str]]:
    """(kind, SPARQL) for one batch: three tier counts, the ecosystem split, the spellings."""
    values = _values(batch)
    def count(pattern: str) -> str:
        return f"SELECT ?g (COUNT(DISTINCT ?t) AS ?n) WHERE {{ VALUES ?g {{ {values} }} GRAPH ?g {{ {pattern} }} }} GROUP BY ?g"
    return [
        ("dependency", count(f"?t <{_TYPE}> <urn:defender:DependencySignal> .")),
        ("ioc", count(f"?t <{_TYPE}> <urn:defender:IocSignal> .")),
        ("ioc", count(f'?t <{_TYPE}> <urn:blackbox:SourceObservation> ; <{_BP}lifecycleStatus> "active" .')),
        ("ecosystem", f"SELECT ?g ?eco (COUNT(?t) AS ?n) WHERE {{ VALUES ?g {{ {values} }} GRAPH ?g {{ "
                      f"?t <{_TYPE}> <urn:defender:DependencySignal> ; <{_DP}ecosystem> ?eco . }} }} GROUP BY ?g ?eco"),
        ("aliases", f"SELECT DISTINCT ?g ?eco ?pkg WHERE {{ VALUES ?g {{ {values} }} GRAPH ?g {{ "
                    f"?t <{_DP}package> ?pkg ; <{_DP}ecosystem> ?eco . }} "
                    f'FILTER(?pkg != LCASE(?pkg) || (?eco = "pypi" && (CONTAINS(?pkg, "_") || CONTAINS(?pkg, ".")))) }} '
                    f"LIMIT 50000"),
    ]


def _read_batch(store: StoreClient, batch: list[str]) -> Optional[dict[str, AssetFacts]]:
    counts: dict[str, dict[str, int]] = {graph: {"dependency": 0, "ioc": 0} for graph in batch}
    aliases: dict[str, dict[str, set]] = {graph: {} for graph in batch}
    for kind, sparql in _queries(batch):
        answer = store.select(sparql, timeout=QUERY_TIMEOUT_SECONDS)
        time.sleep(PAUSE_SECONDS)
        if not answer.known:
            logger.warning("blackbox: verified asset facts not read (%s); retrying next refresh", answer.reason)
            return None
        for row in answer.rows or []:
            graph = extract_binding(row.get("g"))
            if graph not in counts:
                continue
            if kind == "aliases":
                ecosystem = extract_binding(row.get("eco")).strip().lower()
                stored = extract_binding(row.get("pkg"))
                canonical = threat_ids.canonical_package_name(ecosystem, stored)
                if ecosystem and stored and stored != canonical:
                    aliases[graph].setdefault(f"{ecosystem}:{canonical}", set()).add(stored)
                continue
            key = ECOSYSTEM_COUNT_PREFIX + extract_binding(row.get("eco")).strip().lower() if kind == "ecosystem" else kind
            counts[graph][key] = counts[graph].get(key, 0) + _int(row.get("n"))
    return {graph: AssetFacts(counts=counts[graph],
                              aliases={k: tuple(sorted(v)) for k, v in aliases[graph].items()}) for graph in batch}


def _meta_graph(graph: str) -> str:
    """The ``_meta`` graph listing *graph* (``<data>/_verifiable_memory/…`` → ``<data>/_meta``)."""
    return graph.split(_VM_SEGMENT, 1)[0] + "/_meta" if _VM_SEGMENT in graph else ""


def _read_meta(store: StoreClient, batch: list[str]) -> Optional[dict[str, tuple[str, str]]]:
    """Asset graph → (UAL, day) for *batch*, each pair bound to its own ``_meta``
    graph; the day is ``dkg:publishedAt``'s UTC day ("" when absent or not a
    date). None when the store failed."""
    pairs = " ".join(f"({sparql_text.sparql_iri(graph)} {sparql_text.sparql_iri(meta)})" for graph in batch
                     if (meta := _meta_graph(graph)) and sparql_text.is_safe_iri(graph) and sparql_text.is_safe_iri(meta))
    if not pairs:
        return {}
    answer = store.select(f"SELECT ?g ?ual ?at WHERE {{ VALUES (?g ?m) {{ {pairs} }} GRAPH ?m {{ "
                          f"?ka <{_DKG}assertionGraph> ?g ; <{_DKG}kaUal> ?ual . "
                          f"OPTIONAL {{ ?ka <{_DKG}publishedAt> ?at . }} }} }}", timeout=QUERY_TIMEOUT_SECONDS)
    time.sleep(PAUSE_SECONDS)
    if not answer.known:
        logger.warning("blackbox: verified asset UALs not read (%s); retrying next refresh", answer.reason)
        return None
    wanted = set(batch)
    return {graph: (ual, _day(extract_binding(row.get("at")))) for row in answer.rows or []
            if (graph := extract_binding(row.get("g"))) in wanted and (ual := extract_binding(row.get("ual")))}


def _day(timestamp: str) -> str:
    """``2026-11-02T09:15:00Z`` → ``2026-11-02``; "" for anything that is not a date."""
    day = timestamp.strip()[:_DAY_LENGTH]
    try:
        return date.fromisoformat(day).isoformat()
    except ValueError:
        return ""


def _int(cell: Any) -> int:
    try:
        return int(float(extract_binding(cell) or 0))
    except ValueError:
        return 0
