"""Saved queries for the DKG node's own UI — the curator's read side (Refine R6, decision 26).

No bespoke curator panel: the read side ships as saved queries in the node's
query catalog, shown in the existing node UI under the Umanitek Guardian
name. Each view is one SPARQL query over a context graph; the catalog is
written through the node's guarded route in its ``prof:`` vocabulary
(``http://dkg.io/ontology/profile/``: SavedQuery, displayName, sparqlQuery,
scopeGraph, inCatalog, rank; read from the node's source on the bench,
2026-10-02). What the node UI cannot show, ``blackbox curate view <name>``
prints from the same query (the CLI stands in).

Pattern: a Constant table (:data:`COMMUNITY_VIEWS`, :data:`VERIFIED_VIEWS`).
"""

from __future__ import annotations

from dataclasses import dataclass

from ..kernel import constants
from ..kernel import rdf_terms, sparql_text

PROFILE_NS = "http://dkg.io/ontology/profile/"
RDF_TYPE = constants.RDF_TYPE
SCHEMA_DESCRIPTION = "http://schema.org/description"
CATALOG_IRI = "urn:blackbox:query-catalog:umanitek-guardian"
_G = sparql_text.GUARDIAN_PREFIX + "\n"


@dataclass(frozen=True)
class SavedView:
    """One saved query: ``slug`` (stable id), ``name`` (shown), ``description``, ``sparql``."""

    slug: str
    name: str
    description: str
    sparql: str

    @property
    def iri(self) -> str:
        return f"urn:blackbox:saved-query:{self.slug}"


COMMUNITY_VIEWS: tuple[SavedView, ...] = (
    SavedView("reports-by-threat", "Guardian · reports per threat",
              "Community threat reports grouped by identifier with the number of reporting rows (unverified count; the plugin verifies signatures).",
              _G + "SELECT ?identifier (COUNT(DISTINCT ?r) AS ?rows) WHERE { ?r a g:ThreatReport ; g:identifier ?identifier } "
                   "GROUP BY ?identifier ORDER BY DESC(?rows) LIMIT 500"),
    SavedView("disputes", "Guardian · disputes",
              "False-positive disputes with their closed reason.",
              _G + "SELECT ?identifier ?reporter ?reportReason WHERE { ?r a g:FalsePositive ; g:identifier ?identifier ; g:reporter ?reporter . "
                   "OPTIONAL { ?r g:reportReason ?reportReason } } ORDER BY ?identifier LIMIT 500"),
    SavedView("retractions", "Guardian · retractions",
              "Reports their reporter withdrew.",
              _G + "SELECT ?identifier ?reporter WHERE { ?r a g:Retraction ; g:identifier ?identifier ; g:reporter ?reporter } ORDER BY ?identifier LIMIT 500"),
    SavedView("sighting-digests", "Guardian · weekly sighting digests",
              "One digest per reporter per ISO week; the threats each names.",
              _G + "SELECT ?reporter ?isoWeek ?threat WHERE { ?r a g:SightingDigest ; g:reporter ?reporter ; g:isoWeek ?isoWeek . "
                   "OPTIONAL { ?r g:reportsThreat ?threat } } ORDER BY DESC(?isoWeek) ?reporter LIMIT 1000"),
    SavedView("keep-alive-copies", "Guardian · keep-alive copies per report",
              "Reports with more than one asset copy on the graph (epoch keep-alive, R5): the subject and how many copies readers fold.",
              _G + "SELECT ?r (COUNT(DISTINCT ?g) AS ?copies) WHERE { GRAPH ?g { ?r a g:ThreatReport } } GROUP BY ?r HAVING (COUNT(DISTINCT ?g) > 1) ORDER BY DESC(?copies) LIMIT 500"),
    SavedView("confirmed-pool", "Guardian · confirmed pool (candidates)",
              "Confirmations the community curators published, with the signed statement that carries the evidence they checked. "
              "Anyone can write rows here: `blackbox curate pool` verifies the signatures and lists what really stands.",
              _G + "SELECT ?identifier ?r ?signedStatement WHERE { ?r a g:CuratorStatement ; g:identifier ?identifier ; "
                   "g:signedStatement ?signedStatement . FILTER(STRSTARTS(STR(?r), \"urn:guardian:curator:confirmation:\")) } "
                   "ORDER BY ?identifier LIMIT 500"),
    SavedView("curator-statements", "Guardian · curator statements",
              "Curator verdicts and notices in the community graph (meaning is in the signed envelope).",
              _G + "SELECT ?r ?identifier WHERE { ?r a g:CuratorStatement ; g:identifier ?identifier } ORDER BY ?r LIMIT 500"),
)

VERIFIED_VIEWS: tuple[SavedView, ...] = (
    SavedView("verified-by-kind", "Guardian · verified threats by kind",
              "The verified graph's threats with severity and kind.",
              _G + "SELECT ?identifier ?severity ?kind WHERE { ?t g:identifier ?identifier ; g:severity ?severity . "
                   "OPTIONAL { ?t g:kind ?kind } } ORDER BY ?identifier LIMIT 2000"),
    SavedView("key-manifests", "Guardian · curator key manifests",
              "Root-signed curator key manifests (meaning is in the signed envelope).",
              _G + "SELECT ?r WHERE { ?r a g:KeyManifest } ORDER BY ?r"),
    SavedView("kill-list", "Guardian · kill list versions",
              "Every kill-list version the curators signed (entries are inside the signed envelope; readers keep the last-good one).",
              _G + "SELECT ?r WHERE { ?r a g:KillList } ORDER BY DESC(?r) LIMIT 100"),
    SavedView("enforcement-statements", "Guardian · enforcement statements",
              "Curator revocations, pauses and the counted-author list in the verified graph.",
              _G + "SELECT ?r ?identifier WHERE { ?r a g:CuratorStatement ; g:identifier ?identifier } ORDER BY ?r LIMIT 500"),
)


def catalog_quads(views: tuple[SavedView, ...], scope_graph: str) -> list[rdf_terms.Quad]:
    """The catalog entries for *views*, scoped to *scope_graph* (a context graph id)."""
    scope = f"did:dkg:context-graph:{scope_graph}"
    quads = [
        rdf_terms.make_quad(CATALOG_IRI, RDF_TYPE, rdf_terms.iri(f"{PROFILE_NS}QueryCatalog")),
        rdf_terms.make_quad(CATALOG_IRI, f"{PROFILE_NS}displayName", rdf_terms.literal("Umanitek Guardian")),
        rdf_terms.make_quad(CATALOG_IRI, f"{PROFILE_NS}scopeGraph", rdf_terms.iri(scope)),
    ]
    for rank, view in enumerate(views, start=1):
        quads += [
            rdf_terms.make_quad(view.iri, RDF_TYPE, rdf_terms.iri(f"{PROFILE_NS}SavedQuery")),
            rdf_terms.make_quad(view.iri, f"{PROFILE_NS}inCatalog", rdf_terms.iri(CATALOG_IRI)),
            rdf_terms.make_quad(view.iri, f"{PROFILE_NS}scopeGraph", rdf_terms.iri(scope)),
            rdf_terms.make_quad(view.iri, f"{PROFILE_NS}displayName", rdf_terms.literal(view.name)),
            rdf_terms.make_quad(view.iri, SCHEMA_DESCRIPTION, rdf_terms.literal(view.description)),
            rdf_terms.make_quad(view.iri, f"{PROFILE_NS}sparqlQuery", rdf_terms.literal(view.sparql)),
            rdf_terms.make_quad(view.iri, f"{PROFILE_NS}rank", rdf_terms.literal(str(rank))),
        ]
    return quads


def find_view(slug: str) -> SavedView:
    for view in (*COMMUNITY_VIEWS, *VERIFIED_VIEWS):
        if view.slug == slug:
            return view
    raise KeyError(slug)
