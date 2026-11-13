"""Browsing the live tiers: one page of verified dependency / IOC threats from the store.

The dashboard's graph page used to slice an in-memory list of every public
rule. Those rules now stay in the node's store (DKG-lookup B6), so a page is a
bounded query: a filtered subject window (OFFSET / LIMIT, no ORDER BY — a sort
over 250k subjects cost 25× on the bench, KI-264; the store's own order is
stable between pages of one generation), then the window's triples through the
compiler's own builders (:func:`partitions.rows_from_triples`,
:func:`row_adapters._row_to_graph_entry`). Totals for the whole filtered result
come from the scope's refresh-time counts (per ecosystem too); a search reads its
matches once, up to the page's end + 1 (``capped`` = there are more); plain paging
stops at MAX_DEPTH. The window and its triples are TWO queries (bench A: the
joined form ran > 120 s, the window alone 0.04 s).

Every untrusted value (the search needle, the ecosystem) enters a query as an
escaped literal (LES-001/002); every query names its predicates and carries a
LIMIT or is a GROUP BY summary (LES-013). A store that could not answer gives
``known=False`` — the caller shows what it has and says the live part is unavailable.

Usage: ``page = public_page(scope, store, category="dependency", ecosystem="npm", offset=0, limit=50)``
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Optional, Sequence

from ...kernel import constants
from ...kernel.dkg_client import extract_binding
from ...kernel.sparql_text import is_safe_iri, sparql_string_literal as literal
from ...kernel.store import StoreClient
from .. import row_adapters
from ..partitions import rows_from_triples
from .scope import ECOSYSTEM_COUNT_PREFIX, VerifiedScope

logger = logging.getLogger(__name__)

#: A browse query waits at most this long (a dashboard read, not the hot path).
BROWSE_TIMEOUT_SECONDS = 10.0
#: Entries per live page at most; the dashboard pages past it with ``offset``.
MAX_PAGE = 500
#: Plain paging stops here: the store walks past every earlier row (offset 5,000:
#: 0.5 s; 150,000: > 10 s on bench A). Deeper threats are reached by search or filter.
MAX_DEPTH = 50_000
#: Triples fetched for a page: subjects × ~15 triples, with headroom.
_TRIPLES_PER_SUBJECT = 40

_TYPE = constants.RDF_TYPE
_DP = constants.DEFENDER_PREDICATES
_BP = constants.BLACKBOX_PREDICATES
#: The live kinds in page order, and the category each answers to.
KINDS: tuple[str, ...] = ("dependency", "ioc")


@dataclass(frozen=True)
class LivePage:
    """``entries`` — graph entries (identifier, category, severity, name, subject,
    source) for the requested window; ``total`` — live entries matching the
    filters (all kinds); ``kind_totals`` — per kind; ``ecosystem_totals`` —
    dependency entries per ecosystem; ``known`` — False when the store could not
    answer (``reason`` says why); what was gathered before is still in the page."""

    entries: list[dict[str, Any]] = field(default_factory=list)
    total: int = 0
    kind_totals: dict[str, int] = field(default_factory=dict)
    ecosystem_totals: dict[str, int] = field(default_factory=dict)
    known: bool = True
    reason: str = ""
    #: True when a search found more matches than this page reaches ("N or more").
    capped: bool = False


def public_page(scope: VerifiedScope, store: StoreClient, *, category: str = "", ecosystem: str = "",
                needle: str = "", offset: int = 0, limit: int = 50) -> LivePage:
    """One page of the live public tiers that match the filters (see module doc)."""
    kinds = [kind for kind in KINDS if _kind_matches(kind, category, ecosystem)]
    limit = max(0, min(int(limit), MAX_PAGE))
    offset = max(0, int(offset))
    if offset + limit > MAX_DEPTH:
        return LivePage(known=False, reason=f"pages past {MAX_DEPTH:,} are not browsable; search or filter instead")
    browser = _Browser(scope, store, ecosystem=ecosystem.strip().lower(), needle=needle.strip().lower(),
                       depth=offset + limit)
    totals: dict[str, int] = {}
    for kind in kinds:
        total = browser.total(kind)
        if total is None:
            return LivePage(known=False, reason=browser.reason)
        totals[kind] = total
    ecosystems = browser.ecosystems() if "dependency" in kinds else {}
    if ecosystems is None:
        return LivePage(kind_totals=totals, total=sum(totals.values()), known=False, reason=browser.reason)
    entries: list[dict[str, Any]] = []
    for kind in kinds:                      # the window runs across the kinds in order
        if offset >= totals[kind]:
            offset -= totals[kind]
            continue
        take = min(limit, totals[kind] - offset)
        if take <= 0:
            break
        found = browser.window(kind, offset, take)
        if found is None:
            return LivePage(entries, sum(totals.values()), totals, ecosystems, False, browser.reason)
        entries.extend(found)
        limit -= take
        offset = 0
    return LivePage(entries, sum(totals.values()), totals, ecosystems, capped=browser.capped)


def _kind_matches(kind: str, category: str, ecosystem: str) -> bool:
    category = category.strip().lower()
    if category and category != kind:
        return False
    return not (ecosystem.strip() and kind != "dependency")   # ecosystems belong to dependencies


class _Browser:
    """The queries behind one page (one scope, one store, one set of filters)."""

    def __init__(self, scope: VerifiedScope, store: StoreClient, *, ecosystem: str, needle: str, depth: int) -> None:
        self.scope, self.store = scope, store
        self.ecosystem, self.needle = ecosystem, needle
        #: A search reads its matches ONCE, up to the page's end + 1, and pages from that.
        self.depth = depth
        self._matches: dict[str, list[tuple[str, str]]] = {}
        self.prefix = f"did:dkg:context-graph:{scope.context_graph_id}/_verifiable_memory/"
        self.reason = ""
        self.capped = False

    def _pattern(self, kind: str) -> str:
        """The subject pattern of *kind* with the filters applied, inside ``GRAPH ?g``."""
        if kind == "dependency":
            # The ecosystem is BOUND as a literal (an index lookup), never a FILTER over every row.
            eco = literal(self.ecosystem) if self.ecosystem else "?eco"
            pattern = (f"?t <{_TYPE}> <urn:defender:DependencySignal> ; "
                       f"<{_DP}package> ?pkg ; <{_DP}ecosystem> {eco} .")
            filters = [f"CONTAINS(LCASE(?pkg), {literal(self.needle)})"] if self.needle else []
        else:
            pattern = (f"{{ ?t <{_TYPE}> <urn:defender:IocSignal> ; <{_DP}value> ?val . }} UNION "
                       f'{{ ?t <{_TYPE}> <urn:blackbox:SourceObservation> ; <{_BP}lifecycleStatus> "active" ; '
                       f"<{_BP}normalizedValue> ?val . }}")
            filters = [f"CONTAINS(LCASE(?val), {literal(self.needle)})"] if self.needle else []
        clause = " ".join(f"FILTER({f})" for f in filters)
        return f"GRAPH ?g {{ {pattern} {clause} }} FILTER(STRSTARTS(STR(?g), {literal(self.prefix)}))"

    def _select(self, sparql: str) -> Optional[list[dict[str, str]]]:
        answer = self.store.select(sparql, timeout=BROWSE_TIMEOUT_SECONDS)
        if not answer.known:
            self.reason = answer.reason
            logger.debug("blackbox: live browse could not read the store: %s", answer.reason)
        return answer.rows

    def total(self, kind: str) -> Optional[int]:
        """Entries of *kind* matching the filters. Without a search the scope's
        refresh-time counts answer (per ecosystem too) — counting 250k rows per page
        load took 7–12 s on bench A. A search counts at most :data:`SEARCH_CAP`
        matches (a full CONTAINS count took 19.6 s); ``capped`` then says "or more".
        None when the store could not answer."""
        counts = self.scope.verified_counts
        if not self.needle:
            if kind == "dependency" and self.ecosystem:
                return int(counts.get(ECOSYSTEM_COUNT_PREFIX + self.ecosystem, 0))
            return int(counts.get(kind, 0))
        matches = self._search(kind)
        if matches is None:
            return None
        if len(matches) > self.depth:            # there are more than this page reaches
            self.capped = True
        return len(matches)

    def _search(self, kind: str) -> Optional[list[tuple[str, str]]]:
        """The search's matches of *kind*, read once: up to the page's end + 1 (a full
        CONTAINS count took 19.6 s on bench A; a page's worth, ~1.5 s)."""
        if kind not in self._matches:
            rows = self._select(f"SELECT ?g ?t WHERE {{ {self._pattern(kind)} }} LIMIT {self.depth + 1}")
            if rows is None:
                return None
            self._matches[kind] = [(extract_binding(r.get("g")), extract_binding(r.get("t"))) for r in rows]
        return self._matches[kind]

    def ecosystems(self) -> Optional[dict[str, int]]:
        """Dependency entries per ecosystem: the scope's refresh-time counts ({} during
        a search — a per-ecosystem search count would be another full scan)."""
        if self.needle:
            return {}
        counts = self.scope.verified_counts
        per = {key[len(ECOSYSTEM_COUNT_PREFIX):]: int(value) for key, value in counts.items()
               if key.startswith(ECOSYSTEM_COUNT_PREFIX)}
        return {self.ecosystem: per.get(self.ecosystem, 0)} if self.ecosystem else per

    def window(self, kind: str, offset: int, limit: int) -> Optional[list[dict[str, Any]]]:
        """Graph entries for *limit* subjects of *kind* after *offset* — TWO queries.

        One query that windows the subjects and joins their triples ran > 120 s on
        Oxigraph (bench A, 2026-10-10: the planner evaluated ``GRAPH ?g { ?t ?p ?o }``
        before the window); the window alone takes 0.04 s and the bound triple read is
        an index lookup, like the live lookups.
        """
        if self.needle:
            matches = self._search(kind)
            if matches is None:
                return None
            pairs = matches[offset:offset + limit]
        else:
            window = self._select(f"SELECT ?g ?t WHERE {{ {self._pattern(kind)} }} OFFSET {int(offset)} LIMIT {int(limit)}")
            if window is None:
                return None
            pairs = [(extract_binding(row.get("g")), extract_binding(row.get("t"))) for row in window]
        pairs = [(g, t) for g, t in pairs if g in self.scope.assertion_graphs and _iri(g) and _iri(t)]
        if not pairs:
            return []
        values = " ".join(f"(<{g}> <{t}>)" for g, t in pairs)
        rows = self._select(f"SELECT ?g ?t ?p ?o WHERE {{ VALUES (?g ?t) {{ {values} }} GRAPH ?g {{ ?t ?p ?o }} }} "
                            f"LIMIT {len(pairs) * _TRIPLES_PER_SUBJECT}")
        return None if rows is None else self._entries(rows)

    def _entries(self, rows: Sequence[dict[str, str]]) -> list[dict[str, Any]]:
        by_graph: dict[str, list[tuple[str, str, str]]] = {}
        for row in rows:
            graph, subject = extract_binding(row.get("g")), extract_binding(row.get("t"))
            if graph in self.scope.assertion_graphs and subject not in self.scope.suppressed_subjects:
                by_graph.setdefault(graph, []).append((subject, extract_binding(row.get("p")), row.get("o") or ""))
        entries: list[dict[str, Any]] = []
        for graph, triples in by_graph.items():
            for built in rows_from_triples(graph, triples):
                entry = row_adapters._row_to_graph_entry(built, "public")
                if entry and entry["identifier"] not in self.scope.revoked_identifiers:
                    entries.append(entry)
        return entries


def _iri(value: str) -> bool:
    """True when *value* can be written as ``<value>`` (it came from the store, but an
    IRI is re-sent only when it cannot break out of the brackets)."""
    return is_safe_iri(value)


def _int(cell: Any) -> int:
    try:
        return int(float(extract_binding(cell) or 0))
    except ValueError:
        return 0
