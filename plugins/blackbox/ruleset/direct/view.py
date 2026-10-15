"""Bounded browsing and readiness over local confirmed VM; no rules export."""
from __future__ import annotations

import time

from ...kernel.sparql_text import sparql_string_literal as literal
from ...kernel.dkg_client import extract_binding
from ..compiler import Ruleset
from .reader import compile_reply, validate_config, read_candidates
from .client import LocalGraphClient, GraphReadUnavailable
from .queries import confirmed_scope, selected_query, iri, G, DP, BP


def _entities(cg_id, source_graph=None, category=""):
    # A sample binds one confirmed partition before scanning its entities. A
    # global DISTINCT/ORDER BY forces the store to sort the entire rule graph.
    graph = iri(source_graph) if source_graph is not None else "?sourceGraph"
    binding = f"VALUES ?sourceGraph {{ {graph} }}" if source_graph is not None else ""
    return f'{binding} {confirmed_scope(cg_id)} GRAPH {graph} {{ {_entity_patterns(category)} }}'


def _entity_patterns(category="", *, bind_category=True):
    if category:
        # Bind the requested category before reading entities, rather than
        # scanning every signal type and filtering the joined result afterward.
        types = {"dependency": "DependencySignal", "injection": "InjectionSignal",
                 "skill": "SkillSignal", "ioc": "IocSignal"}
        if category not in {*types, "fileaccess", "escalation"}:
            return "FILTER(false)"
        branches = []
        if category in types:
            branches.append(f'{{ ?threat a <urn:defender:{types[category]}> }}')
        if category == "ioc":
            branches.append(f'''{{ ?threat a <urn:blackbox:SourceObservation> ;
                <{BP}lifecycleStatus> "active" }}''')
        prefix = "dep" if category == "dependency" else category
        branches.append(f'''{{ ?threat <{G}identifier> ?identifier .
            FILTER(STRSTARTS(?identifier, {literal(prefix + ':')})) }}''')
        binding = f' BIND({literal(category)} AS ?category)' if bind_category else ''
        return '{ ' + ' UNION '.join(branches) + ' }' + binding
    return f'''{{ ?threat a ?type . VALUES (?type ?category) {{
        (<urn:defender:DependencySignal> "dependency")
        (<urn:defender:InjectionSignal> "injection")
        (<urn:defender:SkillSignal> "skill")
        (<urn:defender:IocSignal> "ioc")
      }} }} UNION {{ ?threat a <urn:blackbox:SourceObservation> ;
        <{BP}lifecycleStatus> "active" . BIND("ioc" AS ?category) }}
      UNION {{ ?threat <{G}identifier> ?identifier .
        BIND(STRBEFORE(?identifier, ":") AS ?prefix)
        BIND(IF(?prefix = "dep", "dependency", ?prefix) AS ?category)
        FILTER(?category IN ("dependency", "injection", "skill", "ioc", "fileaccess", "escalation")) }}'''


def _body(cfg, q="", category="", ecosystem=""):
    filters = []
    if category:
        filters.append(f"FILTER(?category = {literal(category)})")
    if ecosystem:
        filters.append(f"FILTER(LCASE(STR(?ecosystem)) = {literal(ecosystem.lower())})")
    if q:
        filters.append(f"FILTER(CONTAINS(LCASE(CONCAT(STR(?threat), COALESCE(STR(?name), ''), COALESCE(STR(?identifier), ''), COALESCE(STR(?value), ''))), {literal(q.lower())}))")
    properties = []
    if q:
        properties.extend(["OPTIONAL { ?threat <http://schema.org/name> ?name }",
                           f"OPTIONAL {{ ?threat <{DP}value>|<{BP}normalizedValue>|<{DP}package> ?value }}"])
    if ecosystem:
        properties.append(f"OPTIONAL {{ ?threat <{DP}ecosystem>|<{G}packageEcosystem> ?ecosystem }}")
    joins = 'GRAPH ?sourceGraph { ' + ' '.join(properties) + ' }' if properties else ''
    return f'{_entities(cfg.context_graph_id, category=category)} {joins} {" ".join(filters)}'


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
    rules = compile_reply(cfg, read_candidates(cfg, client, [identifier], packages))
    return next((r for _, r in rules.iter_rules() if r.get("identifier") == identifier), None)


def ready_sample(cfg, *, client=None, cursor=None):
    return sample_rules(cfg, client=client, cursor=cursor).source_count("public")


def _sample_partitions(cfg, client, cursor, category):
    after = f'FILTER(STR(?sourceGraph) > {literal(cursor["after"])})' if cursor.get("after") else ''
    # Sort only partition identities, not all matching entity identities.
    # Keep GRAPH variables at top level for the DKG scope guard.
    scope_body = confirmed_scope(cfg.context_graph_id)
    if category:
        # Existential selection returns at most one match per partition.
        # Enumerating all matching threats here consumes the shared read
        # deadline before their selected properties can be fetched.
        # Existence only needs matching entities. Binding an unused literal
        # here sends Blazegraph through MockTermResolverOp inside EXISTS.
        scope_body += f' GRAPH ?sourceGraph {{ FILTER EXISTS {{ {_entity_patterns(category, bind_category=False)} }} }}'
    return client.page(f'SELECT DISTINCT ?sourceGraph WHERE {{ {scope_body} {after} }} ORDER BY ?sourceGraph',
                       cfg.context_graph_id, limit=1)


def sample_rules(cfg, *, client=None, cursor=None, category=""):
    """Compile a bounded partition sample, with the same corrections/authority.

    The cursor contains identities/offsets only, never cached rules. Every read
    rechecks confirmed metadata. Four pages bound work per observation; callers
    may continue until ``exhausted`` rather than treating a partial scan as empty.
    """
    validate_config(cfg)
    client = client or LocalGraphClient(cfg)
    cursor = cursor if cursor is not None else {}
    scope = (cfg.context_graph_id, category)
    if cursor.get("scope") != scope or cursor.get("exhausted"):
        cursor.clear()
        cursor.update(scope=scope, offset=0, exhausted=False)
    from .. import curator_tier
    for _ in range(4):
        if not cursor.get("graph"):
            partitions = _sample_partitions(cfg, client, cursor, category)
            rows = partitions["result"]["bindings"]
            if not rows:
                cursor["exhausted"] = True
                return Ruleset(context_graph_id=cfg.context_graph_id)
            cursor["graph"] = extract_binding(rows[0].get("sourceGraph"))
            cursor["last_graph"] = not partitions["hasMore"]
        selected = client.page(f'SELECT DISTINCT ?sourceGraph ?threat WHERE {{ {_entities(cfg.context_graph_id, cursor["graph"], category)} }} ORDER BY ?threat',
                               cfg.context_graph_id, limit=64, offset=cursor["offset"])
        rules = compile_reply(cfg, _selected_triples(cfg, client, selected["result"]["bindings"]))
        curator_tier.apply_curator_tier(rules, client, cfg)
        if getattr(rules, "curator_read_unavailable", False):
            raise GraphReadUnavailable("QUERY_AUTHORITY_UNAVAILABLE")
        if getattr(client, "failure_code", ""):
            raise GraphReadUnavailable(client.failure_code)
        if selected["hasMore"]:
            cursor["offset"] = selected["nextOffset"]
        else:
            cursor.update(after=cursor.pop("graph"), offset=0, exhausted=cursor["last_graph"])
        count = rules.source_count("public")
        if count or cursor["exhausted"]:
            return rules
    return Ruleset(context_graph_id=cfg.context_graph_id)


def _selected_triples(cfg, client, selected):

    if not selected:
        return {"result": {"bindings": []}}
    return client.bounded(selected_query(cfg.context_graph_id, selected), cfg.context_graph_id)
