"""SPARQL builders for reading the VERIFIED threat graph.

Pure string builders — no I/O. Every untrusted value that reaches a query goes
through :func:`..kernel.sparql_text.sparql_string_literal`; IRIs are checked with
:func:`..kernel.sparql_text.is_safe_iri`. Used by :mod:`.fetching` (paged reads) and
:mod:`.compiler` (legacy proof reads).
"""

from __future__ import annotations

import json
import re
from typing import Sequence

from ..kernel import constants, sparql_text

_SELECT_COLUMNS = """?threat ?rdfType ?identifier ?severity ?name ?description
       ?pattern ?toolName ?argShape ?packageName ?packageVersion
       ?packageEcosystem ?advisoryId ?curated ?category ?skillName
       ?skillVersion ?dangerShape ?kind ?iocValue ?targetSubject
       ?correctionAction ?canonicalType ?observationCategory
       ?lifecycleStatus ?normalizedValue ?provenanceJson ?sourceId
       ?signedStatement"""

_DEFENDER_PREFIXES = """PREFIX defender: <urn:defender:>
PREFIX dp: <urn:defender:p:>
PREFIX blackbox: <urn:blackbox:>
PREFIX bp: <urn:blackbox:p:>
PREFIX schema: <http://schema.org/>
"""
#: A wallet-namespaced graph id starts with its owner's address (lowercased here).
_WALLET_ADDRESS = re.compile(r"0x[0-9a-f]{40}")


#: The correction lane: target and action, plus the curator envelope literal a
#: post-pin correction must carry (trust-and-threat-lab R3, :mod:`.live.corrections`).
CORRECTION_PROPERTIES = f"""    OPTIONAL {{ ?threat dp:targetSubject ?targetSubject . }}
    OPTIONAL {{ ?threat dp:action ?correctionAction . }}
    OPTIONAL {{ ?threat <{constants.SIGNED_STATEMENT_PRED}> ?signedStatement . }}"""


def _threat_cursor_filter(after: str) -> str:
    if not after:
        return ""
    return f"FILTER(STR(?threat) > {json.dumps(after, ensure_ascii=True)})"


def _scoped(body: str, graph_uri: str, graph_prefix: str) -> tuple:
    """Wrap *body* in the graph it reads: ONE named graph (*graph_uri*), or every
    graph under *graph_prefix* (``GRAPH ?g`` + a prefix filter, ``?g`` selected so
    the caller can keep only the confirmed assets). Returns (body, select columns)."""
    if graph_prefix:
        body = (f"  GRAPH ?g {{\n{body}\n  }}\n"
                f"  FILTER(STRSTARTS(STR(?g), {json.dumps(graph_prefix)}))")
        return body, f"{_SELECT_COLUMNS} ?g"
    if graph_uri:
        body = f"  GRAPH <{graph_uri}> {{\n{body}\n  }}"
    return body, _SELECT_COLUMNS


def _defender_page_sparql(
    signal_type: str,
    properties: str,
    limit: int,
    after: str,
    graph_uri: str = "",
    *,
    graph_prefix: str = "",
) -> str:
    cursor_filter = _threat_cursor_filter(after)
    body = f"""    {{
        SELECT ?threat WHERE {{
            ?threat a defender:{signal_type} .
            {cursor_filter}
        }}
        ORDER BY STR(?threat)
        LIMIT {int(limit)}
    }}
    BIND(defender:{signal_type} AS ?rdfType)
{properties}"""
    body, columns = _scoped(body, graph_uri, graph_prefix)
    return f"""{_DEFENDER_PREFIXES}
SELECT DISTINCT {columns}
WHERE {{
{body}
}}
ORDER BY STR(?threat)
"""


def _source_observations_sparql(
    limit: int,
    after: str = "",
    graph_uri: str = "",
) -> str:
    """Fetch compact IOC observations without pulling citation triples."""
    cursor_filter = _threat_cursor_filter(after)
    body = f"""    {{
        SELECT ?threat WHERE {{
            ?threat a blackbox:SourceObservation .
            {cursor_filter}
        }}
        ORDER BY STR(?threat)
        LIMIT {int(limit)}
    }}
    BIND(blackbox:SourceObservation AS ?rdfType)
    OPTIONAL {{ ?threat bp:canonicalType ?canonicalType . }}
    OPTIONAL {{ ?threat bp:category ?observationCategory . }}
    OPTIONAL {{ ?threat bp:lifecycleStatus ?lifecycleStatus . }}
    OPTIONAL {{ ?threat bp:normalizedValue ?normalizedValue . }}
    OPTIONAL {{ ?threat bp:provenanceJson ?provenanceJson . }}
    OPTIONAL {{ ?threat bp:sourceId ?sourceId . }}"""
    if graph_uri:
        body = f"  GRAPH <{graph_uri}> {{\n{body}\n  }}"
    return f"""{_DEFENDER_PREFIXES}
SELECT DISTINCT {_SELECT_COLUMNS}
WHERE {{
{body}
}}
ORDER BY STR(?threat)
"""


def _threats_sparql(limit: int, after: str = "", graph_uri: str = "") -> str:
    return _defender_page_sparql(
        "DependencySignal",
        """    OPTIONAL { ?threat dp:kind ?kind . }
    OPTIONAL { ?threat dp:severity ?severity . }
    OPTIONAL { ?threat schema:name ?name . }
    OPTIONAL { ?threat schema:description ?description . }
    OPTIONAL { ?threat dp:package ?packageName . }
    OPTIONAL { ?threat dp:version ?packageVersion . }
    OPTIONAL { ?threat dp:ecosystem ?packageEcosystem . }
    OPTIONAL { ?threat dp:advisoryId ?advisoryId . }""",
        limit,
        after,
        graph_uri,
    )


def _defender_threats_sparql(
    limit: int,
    after: str = "",
    graph_uri: str = "",
) -> tuple:
    return (
        _threats_sparql(limit, after, graph_uri),
        _defender_page_sparql(
            "InjectionSignal",
            """    OPTIONAL { ?threat dp:kind ?kind . }
    OPTIONAL { ?threat dp:severity ?severity . }
    OPTIONAL { ?threat schema:name ?name . }
    OPTIONAL { ?threat schema:description ?description . }
    OPTIONAL { ?threat dp:pattern ?pattern . }""",
            limit,
            after,
            graph_uri,
        ),
        _defender_page_sparql(
            "SkillSignal",
            """    OPTIONAL { ?threat dp:kind ?kind . }
    OPTIONAL { ?threat dp:severity ?severity . }
    OPTIONAL { ?threat schema:name ?name . }
    OPTIONAL { ?threat schema:description ?description . }""",
            limit,
            after,
            graph_uri,
        ),
        _defender_page_sparql(
            "IocSignal",
            """    OPTIONAL { ?threat dp:kind ?kind . }
    OPTIONAL { ?threat dp:severity ?severity . }
    OPTIONAL { ?threat schema:name ?name . }
    OPTIONAL { ?threat schema:description ?description . }
    OPTIONAL { ?threat dp:iocType ?category . }
    OPTIONAL { ?threat dp:value ?iocValue . }""",
            limit,
            after,
            graph_uri,
        ),
        _defender_page_sparql(
            "CorrectionSignal",
            CORRECTION_PROPERTIES,
            limit,
            after,
            graph_uri,
        ),
        _source_observations_sparql(limit, after, graph_uri),
    )


#: The verified tiers still COMPILED after DKG-lookup B6: scanned against text or
#: shapes, so they must live in memory. Dependency / IOC rules (hundreds of
#: thousands) are looked up live instead (:mod:`.live`).
SMALL_TIER_SIGNALS = (
    ("InjectionSignal", """    OPTIONAL { ?threat dp:kind ?kind . }
    OPTIONAL { ?threat dp:severity ?severity . }
    OPTIONAL { ?threat schema:name ?name . }
    OPTIONAL { ?threat schema:description ?description . }
    OPTIONAL { ?threat dp:pattern ?pattern . }"""),
    ("SkillSignal", """    OPTIONAL { ?threat dp:kind ?kind . }
    OPTIONAL { ?threat dp:severity ?severity . }
    OPTIONAL { ?threat schema:name ?name . }
    OPTIONAL { ?threat schema:description ?description . }"""),
    ("CorrectionSignal", CORRECTION_PROPERTIES),
)


def _verified_small_tier_lanes(limit: int, after: str, vm_prefix: str) -> tuple:
    """The cursor-paged lanes that read the small verified tiers from EVERY
    assertion graph under *vm_prefix* at once (``?g`` in each row): the legacy
    ``g:identifier`` rules (escalation, fileaccess), then the defender signal
    types in :data:`SMALL_TIER_SIGNALS`. One read for 564 assets instead of 564."""
    return (
        _legacy_threats_sparql(limit, after, graph_prefix=vm_prefix),
        *(_defender_page_sparql(signal, properties, limit, after, graph_prefix=vm_prefix)
          for signal, properties in SMALL_TIER_SIGNALS),
    )


def _legacy_threats_sparql(
    limit: int,
    after: str = "",
    graph_uri: str = "",
    *,
    graph_prefix: str = "",
) -> str:
    cursor_filter = _threat_cursor_filter(after)
    body = f"""  {{
    SELECT ?threat WHERE {{
      ?threat g:identifier ?cursorIdentifier .
      {cursor_filter}
    }}
    ORDER BY STR(?threat)
    LIMIT {int(limit)}
  }}
  ?threat g:identifier ?identifier .
  OPTIONAL {{ ?threat a ?rdfType . }}
  OPTIONAL {{ ?threat g:kind ?kind . }}
  OPTIONAL {{ ?threat g:severity ?severity . }}
  OPTIONAL {{ ?threat schema:name ?name . }}
  OPTIONAL {{ ?threat schema:description ?description . }}
  OPTIONAL {{ ?threat g:pattern ?pattern . }}
  OPTIONAL {{ ?threat g:toolName ?toolName . }}
  OPTIONAL {{ ?threat g:argShape ?argShape . }}
  OPTIONAL {{ ?threat g:packageName ?packageName . }}
  OPTIONAL {{ ?threat g:packageVersion ?packageVersion . }}
  OPTIONAL {{ ?threat g:packageEcosystem ?packageEcosystem . }}
  OPTIONAL {{ ?threat schema:identifier ?advisoryId . }}
  OPTIONAL {{ ?threat g:curated ?curated . }}
  OPTIONAL {{ ?threat g:category ?category . }}
  OPTIONAL {{ ?threat g:skillName ?skillName . }}
  OPTIONAL {{ ?threat g:skillVersion ?skillVersion . }}
  OPTIONAL {{ ?threat g:dangerShape ?dangerShape . }}"""
    body, columns = _scoped(body, graph_uri, graph_prefix)
    return f"""PREFIX g: <http://umanitek.ai/ontology/guardian/>
PREFIX schema: <http://schema.org/>
SELECT DISTINCT {columns}
WHERE {{
{body}
}}
ORDER BY STR(?threat)
"""


def _context_graph_data_uri(cg_id: str) -> str:
    value = str(cg_id or "").strip()
    if not sparql_text.is_safe_iri(value):
        return ""
    return f"did:dkg:context-graph:{value}"


def verifiable_memory_prefix(cg_id: str) -> str:
    """The IRI prefix every confirmed asset graph of verified graph *cg_id*
    starts with (``did:dkg:context-graph:<cg_id>/_verifiable_memory/``); ""
    for an id that is not safe to embed. Takes any verified graph — the
    configured one or its successor (trust-and-threat-lab R5) — so a reader can
    tell which graph an asset belongs to by its IRI alone."""
    data_graph = _context_graph_data_uri(cg_id)
    return f"{data_graph}/_verifiable_memory/" if data_graph else ""


def _verified_partitions_sparql(cg_id: str) -> str:
    """The verified graph's VM assertion graphs, PINNED to the graph owner.

    KI-106 (Refine R0): any authorized publisher can write the verified
    graph, so only assets whose on-chain UAL sits in the owner's namespace
    (``did:dkg:<chain>/<owner>/<id>`` — the ``0x…`` prefix of a
    wallet-namespaced graph id) are read. Bench-checked 2026-10-01 on a
    mainnet node: all 178 verified assets carry the owner segment and no
    attribution predicate, so this is the key the data actually has. A graph
    id that is not wallet-namespaced is not pinned. (Pull-synced metadata is
    responder-asserted; the cryptographic pin is R7a's signed envelope.)
    """
    data_graph = _context_graph_data_uri(cg_id)
    if not data_graph:
        return ""
    vm_prefix = verifiable_memory_prefix(cg_id)
    pin = _owner_pin(cg_id)
    return f"""PREFIX dkg: <http://dkg.io/ontology/>
SELECT DISTINCT ?assertionGraph ?status WHERE {{
  GRAPH <{data_graph}/_meta> {{
    ?ka dkg:assertionGraph ?assertionGraph .
{pin}    OPTIONAL {{ ?ka dkg:status ?status . }}
  }}
  FILTER(STRSTARTS(STR(?assertionGraph), {json.dumps(vm_prefix)}))
}}
ORDER BY ?assertionGraph
"""


def _owner_pin(cg_id: str) -> str:
    """The KI-106 owner pin as SPARQL lines (empty for a graph id that is not
    wallet-namespaced) — shared by every read of the verified graph's _meta."""
    owner = str(cg_id).split("/", 1)[0].lower()
    if not _WALLET_ADDRESS.fullmatch(owner):
        return ""
    return f"    ?ka dkg:kaUal ?kaUal .\n    FILTER(CONTAINS(LCASE(STR(?kaUal)), {json.dumps('/' + owner + '/')}))\n"


def _verified_partition_totals_sparql(cg_id: str) -> str:
    """ONE aggregate row: how many verified assets this node holds CONFIRMED,
    and their public triple count — for the dashboard's sync meter.

    Same owner pin and prefix as :func:`_verified_partitions_sparql`; bounded
    by construction (an aggregate, no listing — LES-013). The node's _meta
    holds only assets it has already downloaded, so this is "downloaded",
    never the graph's full size (that comes from the node's recovery backlog).
    """
    data_graph = _context_graph_data_uri(cg_id)
    if not data_graph:
        return ""
    vm_prefix = verifiable_memory_prefix(cg_id)
    return f"""PREFIX dkg: <http://dkg.io/ontology/>
SELECT (COUNT(DISTINCT ?ka) AS ?assets) (SUM(?publicTriples) AS ?triples) WHERE {{
  GRAPH <{data_graph}/_meta> {{
    ?ka dkg:assertionGraph ?assertionGraph ;
        dkg:status ?status .
{_owner_pin(cg_id)}    OPTIONAL {{ ?ka dkg:publicTripleCount ?publicTriples . }}
  }}
  FILTER(STR(?status) = "confirmed")
  FILTER(STRSTARTS(STR(?assertionGraph), {json.dumps(vm_prefix)}))
}}
"""


def signed_rows_sparql(graphs: Sequence[str], limit: int) -> str:
    """The facts lane's once-per-NEW-asset read (trust-and-threat-lab R2, §03.4):
    every triple of every SIGNED subject — one carrying the promotion envelope
    literal under ``SIGNED_STATEMENT_PRED`` — in *graphs*. VALUES-bound to the
    named graphs (index lookups, never a scan; LES-013/LES-040) and LIMITed, so
    a caller that gets *limit* rows back knows the answer may be cut short.
    "" when no graph IRI is safe to embed."""
    values = " ".join(filter(None, (sparql_text.sparql_iri(graph) for graph in graphs)))
    if not values:
        return ""
    return (f"SELECT ?g ?t ?p ?o WHERE {{ VALUES ?g {{ {values} }} GRAPH ?g {{ "
            f"?t <{constants.SIGNED_STATEMENT_PRED}> ?signed . ?t ?p ?o . }} }} LIMIT {int(limit)}")


# ---------------------------------------------------------------------------
# Legacy proof verification (backward compatibility)
# ---------------------------------------------------------------------------

# This fallback keeps already-published proof-era rows effective.
_PROOFS_SPARQL = """PREFIX g: <http://umanitek.ai/ontology/guardian/>
SELECT ?proof ?root ?member WHERE {
  ?proof a g:CurationProof .
  ?proof g:anchorRoot ?root .
  ?proof g:anchorMember ?member .
}"""
