"""Paged reads of the verified graph from the local DKG node.

Since DKG-lookup B6 only the SMALL verified tiers are read (injection, skill,
corrections, legacy-identifier rules): one cursor-paged lane per type over every
confirmed assertion graph at once. Dependency and IOC rules stay in the node's
store and are looked up live (:mod:`.live`). The root data graph and other
views are cursor-paged in lanes here too. Also row de-duplication. Returns
raw rows (or ``None`` on failure); turning rows into rules is
:mod:`.compiler`'s job.

Usage: ``rows = fetching.fetch_tier(client, context_graph_id, view)`` (called
by :mod:`.refresh_cycle` and the dashboard; tests patch it here).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable, Dict, FrozenSet, List, Optional, Tuple
from ..kernel import constants
from ..kernel.dkg_client import DkgClient, extract_binding
from ..kernel import sparql_text
from ..kernel.store import StoreClient, loopback_store_url
from . import graph_queries, partitions

logger = logging.getLogger(__name__)

# Rows fetched per page when syncing a tier. One SPARQL round-trip each.
_PAGE_SIZE = 5000


_QUERY_ERROR = object()  # sentinel: distinguishes a tier failure from an empty tier


@dataclass(frozen=True)
class PartitionListing:
    """What the node's ``_meta`` says about the verified graph's assets.

    ``graphs`` — every VM assertion graph listed (any status); ``confirmed`` —
    the owner-pinned, on-chain-confirmed ones, sorted: the only graphs a
    public rule may come from.
    """

    graphs: frozenset[str]
    confirmed: tuple[str, ...]


def confirmed_partitions(client: DkgClient, cg_id: str) -> Optional[PartitionListing]:
    """List the verified graph's assertion graphs; None when the node could
    not be asked, or lists partitions but confirms none yet (a broad read then
    would promote tentative assets to public rules — keep the last-good tier)."""
    partition_query = graph_queries._verified_partitions_sparql(cg_id)
    if not partition_query:
        return None
    metadata = client.query(partition_query, cg_id, view=None, on_error=_QUERY_ERROR)
    if metadata is _QUERY_ERROR:
        return None
    vm_prefix = f"{graph_queries.context_graph_data_uri(cg_id)}/_verifiable_memory/"
    partition_metadata = [
        (graph, extract_binding(row.get("status")))
        for row in metadata
        if (graph := extract_binding(row.get("assertionGraph"))).startswith(vm_prefix)
        and graph != vm_prefix
        and sparql_text.is_safe_iri(graph)
    ]
    graphs = frozenset(graph for graph, _status in partition_metadata)
    confirmed = tuple(sorted({graph for graph, status in partition_metadata if status == "confirmed"}))
    if graphs and not confirmed:
        return None
    return PartitionListing(graphs=graphs, confirmed=confirmed)


def fetch_tier(
    client: DkgClient,
    cg_id: str,
    view: str,
    agent_address: Optional[str] = None, listing: Optional[PartitionListing] = None,
) -> Optional[list[dict[str, Any]]]:
    """Fully paginate one tier. Returns all rows, or ``None`` if the node errored.

    ``None`` (error) is distinct from ``[]`` (the tier is genuinely empty) so
    the caller can preserve a tier's last-good rules through a transient failure
    instead of wiping them. *listing*: the ``_meta`` listing when already read.
    """
    if view == constants.VIEW_VERIFIABLE_MEMORY:
        listing = listing or confirmed_partitions(client, cg_id)
        if listing is None:
            return None
        data_graph = graph_queries.context_graph_data_uri(cg_id)
        small_tiers = _verified_small_tier_rows(client, cg_id, f"{data_graph}/_verifiable_memory/", listing)
        if small_tiers is None:
            return None
        # DKG-lookup B6: dependency / IOC rules are not compiled — they are looked up
        # live in every confirmed asset — so every confirmed asset is "compiled".
        partitions.record_progress(cg_id, partitions.PartitionRead(total=len(listing.confirmed),
                                                                    compiled=len(listing.confirmed)))
        root_rows = _fetch_paged_lanes(
            client,
            cg_id,
            lambda limit, after: (
                graph_queries._legacy_threats_sparql(limit, after, data_graph),
                *graph_queries._defender_threats_sparql(limit, after, data_graph),
            ),
            view=None,
        )
        if root_rows is None:
            return None
        if len(small_tiers) + len(root_rows) >= sparql_text.MAX_ROWS:
            return None
        return _dedupe_threat_rows([*small_tiers, *root_rows])

    return _fetch_paged_lanes(
        client,
        cg_id,
        lambda limit, after: (
            graph_queries._legacy_threats_sparql(limit, after),
            *graph_queries._defender_threats_sparql(limit, after),
        ),
        view=view,
        agent_address=agent_address,
    )


def fetch_local_records(client: DkgClient, local_graph: str, agent_address: str) -> Optional[list[dict[str, Any]]]:
    """This node's private audit records (``g:identifier`` rows) from its OWN graph's
    working memory — the dashboard's Local tier. ONE identifier lane only: the private
    graph holds audit records and nothing else, and the defender-signal lanes over a
    working-memory view scanned the whole store (> 30 s on bench A, 2026-10-10 — the
    node's supervisor then restarted Oxigraph, LES-040). None when the node failed."""
    return _fetch_paged_lanes(
        client, local_graph,
        lambda limit, after: (graph_queries._legacy_threats_sparql(limit, after),),
        view=constants.VIEW_WORKING_MEMORY, agent_address=agent_address,
    )


def _verified_small_tier_rows(client: DkgClient, cg_id: str, vm_prefix: str,
                              listing: PartitionListing) -> Optional[list[dict[str, Any]]]:
    """The small verified tiers (injection, skill, corrections, legacy-identifier
    rules) from every CONFIRMED asset: one cursor-paged read per lane over
    ``GRAPH ?g`` under *vm_prefix*, then only rows whose graph the node confirmed
    (a tentative or foreign asset never becomes a public rule). None on failure."""
    rows = _fetch_paged_lanes(
        _StoreLanes.for_node(client) or client, cg_id,
        lambda limit, after: graph_queries._verified_small_tier_lanes(limit, after, vm_prefix),
        view=constants.VIEW_VERIFIABLE_MEMORY,
    )
    if rows is None:
        return None
    partitions.forget_cached_assets()   # the per-asset row cache these lanes replaced
    confirmed = set(listing.confirmed)
    return [row for row in rows if extract_binding(row.get("g")) in confirmed]


class _StoreLanes:
    """The lane reader pointed at the node's LOCAL store instead of its query API.

    Bench A 2026-10-10: the InjectionSignal lane took 0.05 s at the store and 25–29 s
    through the node's /api/query (with or without the verified-memory view, which also
    rewrote it to an 86 KB query listing all 564 asset graphs) — long enough for the
    node's own supervisor to restart the store (KI-330, LES-040). Adapter: the
    ``query(sparql, cg, view=, on_error=)`` shape the pager calls, answered by
    :class:`~..kernel.store.StoreClient`; a failed read returns *on_error*.
    """

    def __init__(self, store: StoreClient) -> None:
        self.store = store

    @classmethod
    def for_node(cls, client: Any) -> Optional[_StoreLanes]:
        """A store-backed reader when the node reports a loopback store; else None."""
        status = getattr(client, "status", None)
        if not callable(status):
            return None
        try:
            url = loopback_store_url(status(timeout=5.0))
        except Exception:   # a node without a status answer: the caller uses its query API
            return None
        return cls(StoreClient(url, timeout=STORE_LANE_TIMEOUT_SECONDS)) if url else None

    def query(self, sparql: str, _cg_id: str, *, view: Optional[str] = None, on_error: Any = None, **_: Any) -> Any:
        answer = self.store.select(sparql)
        return answer.rows if answer.known else on_error


#: One lane page at the store (0.05 s on bench A; generous for a busy node).
STORE_LANE_TIMEOUT_SECONDS = 20.0


def _fetch_paged_lanes(
    client: DkgClient,
    cg_id: str,
    query_lanes: Callable[[int, str], tuple],
    *,
    view: Optional[str],
    agent_address: Optional[str] = None,
) -> Optional[list[dict[str, Any]]]:
    """Cursor-page every lane until an empty page; None when any page fails."""
    rows: list[dict[str, Any]] = []
    lane_count = len(query_lanes(1, ""))
    for lane_index in range(lane_count):
        after = ""
        fetched_subjects = 0
        while fetched_subjects < sparql_text.MAX_ROWS:
            kwargs: dict[str, Any] = {"view": view, "on_error": _QUERY_ERROR}
            if agent_address:
                kwargs["agent_address"] = agent_address
            query = query_lanes(_PAGE_SIZE, after)[lane_index]
            page = client.query(query, cg_id, **kwargs)
            if page is _QUERY_ERROR:
                return None
            rows.extend(page)
            page_subjects = list(
                dict.fromkeys(
                    subject
                    for row in page
                    if (subject := extract_binding(row.get("threat")))
                )
            )
            if not page_subjects:
                if page:
                    return None
                break
            next_cursor = page_subjects[-1]
            if next_cursor <= after:
                return None
            fetched_subjects += len(page_subjects)
            # Keep paging until an EMPTY page. A short page does NOT mean the
            # lane is exhausted: DKG daemons cap a response below the requested
            # LIMIT (measured on 10.0.19: 5,000 requested -> 1,000 returned),
            # and the old short-page break silently truncated every lane to its
            # first page (the KI-052 "one _PAGE_SIZE compiled" signature).
            after = next_cursor
    return rows


def _dedupe_threat_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Prefer confirmed partition rows when a migrated root repeats a threat."""
    result: list[dict[str, Any]] = []
    seen: set = set()
    for row in rows:
        threat = extract_binding(row.get("threat"))
        if threat and threat in seen:
            continue
        if threat:
            seen.add(threat)
        result.append(row)
    return result
