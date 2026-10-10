"""Bounded candidate reads, scoped to owner-pinned, confirmed VM partitions.

Exact indicators use RDF equality lookups; package aliases are normalized in-query. The small curated pattern
and skill tiers are read in full per decision, with an explicit overflow error.
No command text, file contents or credential values are sent to the node.
"""
from __future__ import annotations

from ...detection import command_text, parse_dependency_installs, iter_ioc_candidates, injection_scan_text
from ...kernel import threat_ids
from ...kernel.sparql_text import sparql_string_literal as literal
from ..graph_queries import _context_graph_data_uri, _owner_pin
from .client import GraphReadUnavailable

MAX_CANDIDATES = 64
G = "http://umanitek.ai/ontology/guardian/"
DP = "urn:defender:p:"
BP = "urn:blackbox:p:"


def candidates(tool: str, args) -> tuple[list[str], list[str]]:
    identifiers = set(iter_ioc_candidates(injection_scan_text(args)))
    packages = set()
    for dep in parse_dependency_installs(command_text(args)):
        eco, name, version = dep["ecosystem"], dep["name"], dep.get("version")
        packages.add(threat_ids.canonical_package_name(eco, name))
        identifiers.add(threat_ids.dependency_identifier(eco, name, version or "*"))
        identifiers.add(threat_ids.dependency_identifier(eco, name, "*"))
    if len(identifiers) + len(packages) > MAX_CANDIDATES:
        raise GraphReadUnavailable("QUERY_CANDIDATE_LIMIT")
    return sorted(identifiers), sorted(packages)


def confirmed_scope(cg_id: str) -> str:
    graph = _context_graph_data_uri(cg_id)
    if not graph:
        raise GraphReadUnavailable("INVALID_CONTEXT_GRAPH")
    return f'''GRAPH <{graph}/_meta> {{
      ?ka <http://dkg.io/ontology/assertionGraph> ?sourceGraph ;
          <http://dkg.io/ontology/status> "confirmed" .
      {_owner_pin(cg_id).replace('dkg:kaUal', '<http://dkg.io/ontology/kaUal>')}
    }}
    FILTER(STRSTARTS(STR(?sourceGraph), {literal(graph + '/_verifiable_memory/')}))'''


def candidate_query(cg_id: str, identifiers: list[str], packages: list[str]) -> str:
    # Legacy behavioural identifiers remain bounded alongside their newer types.
    branches = ['''{ ?threat a ?kind . VALUES ?kind {
      <urn:defender:InjectionSignal> <urn:defender:SkillSignal> <urn:defender:CorrectionSignal>
    } }''', f'''{{ ?threat <{G}identifier> ?id .
      FILTER(STRSTARTS(?id, "injection:") || STRSTARTS(?id, "skill:") ||
             STRSTARTS(?id, "escalation:") || STRSTARTS(?id, "fileaccess:")) }}''']
    if identifiers:
        values = " ".join(literal(value) for value in identifiers)
        branches.append(f"{{ VALUES ?id {{ {values} }} ?threat <{G}identifier> ?id }}")
        iocs = [item.split(":", 2)[2] for item in identifiers if item.startswith("ioc:")]
        if iocs:
            values = " ".join(literal(value) for value in iocs)
            branches.append(f"{{ VALUES ?value {{ {values} }} VALUES ?valuePredicate {{ <{DP}value> <{BP}normalizedValue> }} ?threat ?valuePredicate ?value }}")
    if packages:
        values = ", ".join(literal(value) for value in packages)
        # Identifier-only legacy Python rules have the same package-name semantics.
        branches.append(f'''{{ ?threat <{G}identifier> ?legacyId .
          FILTER(STRSTARTS(STR(?legacyId), "dep:pypi:"))
          BIND(STRBEFORE(SUBSTR(STR(?legacyId), 10), "@") AS ?legacyPackage)
          FILTER(REPLACE(LCASE(?legacyPackage), "[-_.]+", "-") IN ({values})) }}''')
        # Python distribution names treat [-_.] runs as the same character.
        branches.append(f'''{{ VALUES ?packagePredicate {{ <{DP}package> <{G}packageName> }}
          ?threat ?packagePredicate ?package .
          FILTER(LCASE(STR(?package)) IN ({values}) || REPLACE(LCASE(STR(?package)), "[-_.]+", "-") IN ({values})) }}''')
    selection = " UNION ".join(branches)
    return triples_query(cg_id, "GRAPH ?sourceGraph { " + selection + " }")


def triples_query(cg_id: str, selection: str) -> str:
    # Plain triples avoid the old Cartesian product of 27 OPTIONAL properties.
    return f'''SELECT DISTINCT ?sourceGraph ?ka ?threat ?p ?o WHERE {{
      {confirmed_scope(cg_id)}
      {selection}
      GRAPH ?sourceGraph {{ ?threat ?p ?o }}
    }} ORDER BY ?sourceGraph ?threat ?p ?o'''
