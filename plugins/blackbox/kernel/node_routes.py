"""Node routes the curator uses that the hot path never does (Refine R6).

Thin, typed wrappers over the DKG node's HTTP API, all through the one HTTP
seam (:meth:`.dkg_client.DkgClient.request`). Route facts were read from the
node's own source on the bench (DKG 10.0.20, 2026-10-02):

* ``POST /api/knowledge-assets/{name}/vm/publish {contextGraphId}`` publishes
  a sealed KA to verifiable memory (on-chain; needs the publishing wallet
  funded — 200 confirmed, 207 minted but graph binding failed, 502 not
  confirmed). Since DKG 10.0.23 the KA must first be a COMPLETE share in the
  graph's shared memory (``/swm/share-async`` with ``entities: "all"``);
  otherwise the node answers 409 PUBLISH_NOT_FULL_SHARE (KI-351, measured on
  the Umanitek node 2026-10-12). Sharing is free; only the publish is paid.
* The same route publishes ANOTHER node's asset that arrived as a complete
  share — a promoted community report (DKG 10.0.25 source, 2026-10-16:
  GH#1778 "curator publishes a member KA", GH#1786): the body adds the
  ``subGraphName`` the asset was shared into and
  ``selectedAuthorAgentAddress``, the author among those holding that name.
  The node publishes it as its author sealed it; this node's wallet pays. A
  member's asset is minted once: a second publish of it is refused
  (PUBLISH_AUTHOR_NOT_CUSTODIAL — this node cannot re-sign it).
* ``GET /api/knowledge-assets/{name}?contextGraphId&subGraphName&agentAddress``
  — one author's lifecycle descriptor of that name: per-layer pointers
  (``swmCurrentAssertion``, ``vmCurrentAssertion``) and its UALs
  (``reservedUal``; ``publishedUal`` once confirmed). 404: no such asset.
* ``POST /api/query {sparql, contextGraphId, view, subGraphName?}`` reads one
  memory view of one sub-graph (the node client names a sub-graph only for
  shared memory).
* ``POST /api/chat {to, text, contextGraphId?}`` sends one private
  point-to-point message to a peer (name or peer id); ``GET /api/messages``
  with ``direction=in&order=asc&since=&sinceId=`` reads the inbox losslessly.
* ``POST /api/profile/query-catalog/write {contextGraphId, quads}`` saves
  immutable catalog entries in the ``prof:`` vocabulary;
  ``/read {contextGraphId}`` lists them.

Usage::

    from ..kernel import node_routes
    node_routes.publish_to_verified_memory(client, vm_graph, name, quads)
    node_routes.publish_shared_asset(client, vm_graph, name, author=reporter, sub_graph="reports")
    node_routes.send_message(client, peer, text)
    for message in node_routes.inbox(client, since_id=last_seen): ...
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from urllib.parse import quote, urlencode

from . import sparql_text
from .dkg_client import DkgClient, DkgError, Quad

#: Seconds a Verified Memory publish may take: the node collects storage acks
#: and waits for the chain, far past the client's 3 s default.
PUBLISH_TIMEOUT_SECONDS = 150.0
QUERY_TIMEOUT_SECONDS = 30.0


@dataclass(frozen=True)
class InboxMessage:
    """One inbound message: ``id`` (the cursor), ``ts`` (sender-side epoch
    ms), ``peer`` (peer id), ``text``."""

    id: int
    ts: int
    peer: str
    text: str


def publish_to_verified_memory(client: DkgClient, graph: str, name: str, quads: list[Quad]) -> dict[str, Any]:
    """Create + seal *quads* as KA *name*, share it in full to the graph's shared
    memory (DKG 10.0.23 publishes nothing else, KI-351), then publish it to
    verifiable memory.

    Returns the node's publish result. Raises :class:`.dkg_client.DkgError` on
    any failure (a 502 "did not confirm" included): a promotion that did not
    confirm is NOT published, and the caller must say so.
    """
    client.write_private_knowledge_asset(graph, name, quads)
    client.share_finalized_knowledge_asset(graph, name)
    return client.request("POST", f"/api/knowledge-assets/{quote(name, safe='')}/vm/publish", {"contextGraphId": graph},
                          timeout=PUBLISH_TIMEOUT_SECONDS)


def publish_shared_asset(client: DkgClient, graph: str, name: str, *, author: str, sub_graph: str = "") -> dict[str, Any]:
    """Publish ANOTHER node's asset *name* — written and sealed by agent
    *author*, a complete share in *graph*'s shared memory (sub-graph
    *sub_graph*; "" = the root) — to Verified Memory, as its author sealed it.

    Returns the node's publish result (``ual``, ``status``). Raises
    :class:`.dkg_client.DkgError`: a 4xx is a definite refusal and nothing was
    paid (409 PUBLISH_NOT_FULL_SHARE when the share is not complete on this
    node; a refused author selection); a 5xx or a timeout could not tell.
    """
    body = {"contextGraphId": graph, "selectedAuthorAgentAddress": author, **({"subGraphName": sub_graph} if sub_graph else {})}
    return client.request("POST", f"/api/knowledge-assets/{quote(name, safe='')}/vm/publish", body,
                          timeout=PUBLISH_TIMEOUT_SECONDS)


def shared_asset(client: DkgClient, graph: str, name: str, *, author: str, sub_graph: str = "") -> Optional[dict[str, Any]]:
    """*author*'s lifecycle descriptor of asset *name* in *graph* (sub-graph
    *sub_graph*) as this node holds it; None when the node holds no such
    asset (404). Any other failure raises :class:`.dkg_client.DkgError`."""
    query = urlencode({"contextGraphId": graph, "agentAddress": author, **({"subGraphName": sub_graph} if sub_graph else {})})
    try:
        reply = client.request("GET", f"/api/knowledge-assets/{quote(name, safe='')}?{query}")
    except DkgError as exc:
        if exc.status_code == 404:
            return None
        raise
    return reply if isinstance(reply, dict) else {}


def query_rows(client: DkgClient, sparql: str, graph: str, *, view: str, sub_graph: str = "") -> Optional[list[dict[str, Any]]]:
    """The rows ONE query returns from *graph*'s *view* of sub-graph
    *sub_graph* ("" = the root); None when the query failed or the reply is
    not one the daemon is known to give (never read as "no rows")."""
    body = {"sparql": sparql, "contextGraphId": graph, "view": view, **({"subGraphName": sub_graph} if sub_graph else {})}
    try:
        reply = client.request("POST", "/api/query", body, timeout=QUERY_TIMEOUT_SECONDS)
    except DkgError:
        return None
    return sparql_text.recognized_bindings(reply)


def send_message(client: DkgClient, peer: str, text: str, graph: str = "") -> dict[str, Any]:
    """Send one private message to *peer*; returns the node's delivery result."""
    body: dict[str, Any] = {"to": peer, "text": text}
    if graph:
        body["contextGraphId"] = graph
    return client.request("POST", "/api/chat", body)


def inbox(client: DkgClient, *, since_id: int = 0, since: int = 0, limit: int = 100) -> list[InboxMessage]:
    """Inbound messages after the compound cursor (*since*, *since_id*),
    oldest first — the lossless pagination the node documents."""
    query = urlencode({"direction": "in", "order": "asc", "limit": limit, "since": since, "sinceId": since_id})
    result = client.request("GET", f"/api/messages?{query}", None)
    rows = result.get("messages") if isinstance(result, dict) else result
    out: list[InboxMessage] = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        try:
            out.append(InboxMessage(id=int(row.get("id") or 0), ts=int(row.get("ts") or 0),
                                    peer=str(row.get("peer") or ""), text=str(row.get("text") or "")))
        except (TypeError, ValueError):
            continue
    return out


def write_query_catalog(client: DkgClient, graph: str, quads: list[Quad]) -> dict[str, Any]:
    """Save immutable saved-query catalog entries for *graph*."""
    return client.request("POST", "/api/profile/query-catalog/write", {"contextGraphId": graph, "quads": quads})


def read_query_catalog(client: DkgClient, graph: str) -> dict[str, Any]:
    """The saved-query catalog of *graph*, as the node returns it."""
    return client.request("POST", "/api/profile/query-catalog/read", {"contextGraphId": graph})

