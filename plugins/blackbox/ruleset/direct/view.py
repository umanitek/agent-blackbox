"""Bounded browsing and readiness over local confirmed VM; no rules export."""
from __future__ import annotations

import time

from ...kernel.sparql_text import sparql_string_literal as literal
from ...kernel.dkg_client import extract_binding
from ..compiler import Ruleset
from .reader import compile_reply, validate_config
from .client import LocalGraphClient, GraphReadUnavailable
from .queries import confirmed_scope, candidate_query, triples_query, G, DP, BP


def _entities(cg_id):
    return f'''{confirmed_scope(cg_id)} GRAPH ?sourceGraph {{
      {{ ?threat a ?type . VALUES (?type ?category) {{
        (<urn:defender:DependencySignal> "dependency")
        (<urn:defender:InjectionSignal> "injection")
        (<urn:defender:SkillSignal> "skill")
        (<urn:defender:IocSignal> "ioc")
      }} }} UNION {{ ?threat a <urn:blackbox:SourceObservation> ;
        <{BP}lifecycleStatus> "active" . BIND("ioc" AS ?category) }}
      UNION {{ ?threat <{G}identifier> ?identifier .
        BIND(STRBEFORE(?identifier, ":") AS ?prefix)
        BIND(IF(?prefix = "dep", "dependency", ?prefix) AS ?category)
        FILTER(?category IN ("dependency", "injection", "skill", "ioc", "fileaccess", "escalation")) }}
    }}'''


def _body(cfg, q="", category="", ecosystem=""):
    filters = []
    if category:
        filters.append(f"FILTER(?category = {literal(category)})")
    if ecosystem:
        filters.append(f"FILTER(LCASE(STR(?ecosystem)) = {literal(ecosystem.lower())})")
    if q:
        filters.append(f"FILTER(CONTAINS(LCASE(CONCAT(STR(?threat), COALESCE(STR(?name), ''), COALESCE(STR(?identifier), ''), COALESCE(STR(?value), ''))), {literal(q.lower())}))")
    return f'''{_entities(cfg.context_graph_id)} GRAPH ?sourceGraph {{
      OPTIONAL {{ ?threat <http://schema.org/name> ?name }}
      OPTIONAL {{ ?threat <{DP}ecosystem>|<{G}packageEcosystem> ?ecosystem }}
      OPTIONAL {{ ?threat <{DP}value>|<{BP}normalizedValue>|<{DP}package> ?value }}
    }} {' '.join(filters)}'''


class GraphView(Ruleset):
    """Status facade. Counts are confirmed entities, not compiled usable rules.

    No global in-process generation: even A -> B -> A profile switches obtain
    a new view and query the owning profile's node and Context Graph.
    """
    def __init__(self, cfg, client=None):
        validate_config(cfg)
        super().__init__(context_graph_id=cfg.context_graph_id)
        self.cfg, self.client, self._counts = cfg, client, None

    def counts(self):
        if self._counts is None:
            client = self.client or LocalGraphClient(self.cfg)
            reply = client.bounded(
                f'SELECT ?category (COUNT(DISTINCT ?threat) AS ?n) WHERE {{ {_entities(self.context_graph_id)} }} GROUP BY ?category',
                self.context_graph_id, max_rows=7,
            )
            counts = super().counts()
            for row in reply["result"]["bindings"]:
                category = extract_binding(row.get("category"))
                if category not in counts:
                    raise GraphReadUnavailable("QUERY_MALFORMED_RESPONSE")
                counts[category] = int(extract_binding(row.get("n")))
            self._counts, self.synced_at = counts, time.time()
        return dict(self._counts)

    def source_count(self, source):
        return sum(self.counts().values()) if source == "public" else 0

    def graph_count(self, source):
        return self.source_count(source)

    def iter_rules(self):
        raise GraphReadUnavailable("PAGED_GRAPH_READ_REQUIRED")

    def graph_entries(self, source):
        raise GraphReadUnavailable("PAGED_GRAPH_READ_REQUIRED")


def page(cfg, *, limit=100, offset=0, q="", category="", ecosystem="", client=None):
    """Page identities first, then fetch only their properties for the existing adapter.

    Totals count graph entities; malformed/uncompilable entities may yield no
    display entry. next_offset advances by entities examined, not rendered rows.
    """
    validate_config(cfg)
    limit = min(100, max(1, int(limit)))
    offset = min(1_000_000, max(0, int(offset)))
    client = client or LocalGraphClient(cfg)
    body = _body(cfg, q, category, ecosystem)
    totals_reply = client.bounded(f'SELECT ?category (COUNT(DISTINCT ?threat) AS ?n) WHERE {{ {body} }} GROUP BY ?category', cfg.context_graph_id, max_rows=7)
    totals = {extract_binding(r.get("category")): int(extract_binding(r.get("n"))) for r in totals_reply["result"]["bindings"]}
    selected = client.page(f'SELECT DISTINCT ?sourceGraph ?threat WHERE {{ {body} }} ORDER BY ?sourceGraph ?threat',
                           cfg.context_graph_id, limit=limit, offset=offset)
    reply = _selected_triples(cfg, client, selected["result"]["bindings"])
    rules = compile_reply(cfg, reply)
    return {"tier": "public", "threats": rules.graph_entries("public"), "offset": offset, "limit": limit,
            "next_offset": selected["nextOffset"], "partial": selected["hasMore"],
            "total": sum(totals.values()), "category_totals": totals, "ecosystem_totals": {},
            "coverage": "local-confirmed-subset", "count_kind": "confirmed-entities", "backend": "dkg"}


def lookup(cfg, identifier, *, client=None):
    validate_config(cfg)
    client = client or LocalGraphClient(cfg)
    packages = []
    if identifier.startswith("dep:"):
        packages = [identifier.split(":", 2)[-1].rsplit("@", 1)[0]]
    rules = compile_reply(cfg, client.bounded(candidate_query(cfg.context_graph_id, [identifier], packages), cfg.context_graph_id))
    return next((r for _, r in rules.iter_rules() if r.get("identifier") == identifier), None)


def ready_sample(cfg, *, client=None, cursor=None):
    """Bounded usable-rule sampling; the observer owns progress between polls."""
    validate_config(cfg)
    client = client or LocalGraphClient(cfg)
    cursor = cursor if cursor is not None else {"offset": 0}
    from .. import curator_tier
    for _ in range(4):
        selected = client.page(f'SELECT DISTINCT ?sourceGraph ?threat WHERE {{ {_entities(cfg.context_graph_id)} }} ORDER BY ?sourceGraph ?threat',
                               cfg.context_graph_id, limit=64, offset=cursor.get("offset", 0))
        rules = compile_reply(cfg, _selected_triples(cfg, client, selected["result"]["bindings"]))
        curator_tier.apply_curator_tier(rules, client, cfg)
        if getattr(rules, "curator_read_unavailable", False):
            raise GraphReadUnavailable("QUERY_AUTHORITY_UNAVAILABLE")
        if getattr(client, "failure_code", ""):
            raise GraphReadUnavailable(client.failure_code)
        cursor["offset"] = selected["nextOffset"] if selected["hasMore"] else 0
        count = rules.source_count("public")
        if count or not selected["hasMore"]:
            return count
    return 0


def _selected_triples(cfg, client, selected):
    from ..graph_queries import _FORBIDDEN_IRI_CHARS

    def iri(value):
        text = extract_binding(value)
        if not text or any(c.isspace() or c in _FORBIDDEN_IRI_CHARS for c in text) or ":" not in text:
            raise GraphReadUnavailable("QUERY_MALFORMED_RESPONSE")
        return "<" + text + ">"

    if not selected:
        return {"result": {"bindings": []}}
    pairs = " ".join("(" + iri(row.get("sourceGraph")) + " " + iri(row.get("threat")) + ")" for row in selected)
    # Explicit VALUES keep GRAPH variables out of nested SELECTs: the DKG
    # scope guard deliberately refuses those rather than risk a CG escape.
    selection = ('GRAPH ?sourceGraph { { VALUES (?selectedGraph ?threat) { ' + pairs + ' } } '
                 'UNION { ?threat a <urn:defender:CorrectionSignal> } } '
                 'FILTER(!BOUND(?selectedGraph) || ?sourceGraph = ?selectedGraph)')
    return client.bounded(triples_query(cfg.context_graph_id, selection), cfg.context_graph_id)
