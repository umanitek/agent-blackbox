"""Community membership — the verified graph's subscription WITH shared memory, on the node's word.

Since 2026-10-16 there is one graph: the community's reports live in the
verified graph's shared memory (sub-graph ``constants.COMMUNITY_SUB_GRAPH``),
so belonging to the community is the verified graph's subscription with its
shared memory included. The graph is public: there is no join step (D-040).
Before Refine R0 (KI-064/114) the ruleset subscribed on EVERY refresh; one
object now owns that state:

* connect to the graph's owner (``graph_peer_id``, the curator) before the
  first subscribe, and keep that link: re-dial it every ``OWNER_LINK_SECONDS``,
  never this node itself. Reports reach a node over that link; a node that
  lost it stayed "subscribed" while receiving nothing for hours (KI-297);
* subscribe with shared memory once per process — a node subscribed VM-only
  by an older release gets its shared memory added by that request. The node
  answers whether the catch-up it started (or found) includes shared memory;
* confirm only once the node holds the graph's definition: its listing names
  an access policy (``synced`` can say true before that). Without it every
  write is refused with CONTEXT_GRAPH_NOT_FOUND (KI-295). Registered on chain
  or not, an edge that reaches the graph only through relays never gets the
  definition from the cores (DKG #3264): dial the owner and subscribe again
  with ``forceCatchup``, which brings it in seconds;
* a subscribe the node refused, one answered by a VM-only catch-up still
  running (shared memory can be added once it ends) and a definition still
  missing are retried after ``FAILED_SUBSCRIBE_RETRY_SECONDS``;
* after that, re-read the node's own listing at most once per
  ``RETRY_SECONDS`` and subscribe again only when it no longer lists the graph
  as subscribed;
* register the report sub-graph on this node before its first write there.

Pattern: a single owner of mutable state with one lock, exposed as the
module-level :data:`MEMBERSHIP` (Global Object — the state is per process by
nature, like the node it talks to).

Usage::

    ok, detail = community.ensure_community_subscription(client, cfg)
"""

from __future__ import annotations

import logging
import threading
import time
from enum import Enum
from typing import Any, Callable, Optional

from ..kernel import constants
from ..kernel.dkg_client import DkgClient, DkgError

logger = logging.getLogger(__name__)


class CommunityMembership:
    """Subscription state for this process, guarded by one lock."""

    #: How long a confirmed subscription is trusted before the node's listing is
    #: read again, and how long a subscribe the node did not take waits.
    RETRY_SECONDS = 600.0
    #: A subscribe the node REFUSED (owner not reachable yet, chain hiccup), one
    #: answered without shared memory, and a missing definition: retried this soon.
    FAILED_SUBSCRIBE_RETRY_SECONDS = 60.0
    #: How often the live link to the graph owner is re-dialled (KI-297). A dial
    #: of a connected peer is a cheap no-op on the node; a dropped link costs at
    #: most this long plus the node's catch-up (169 s measured on the bench).
    OWNER_LINK_SECONDS = 120.0

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._last_subscribe: dict[str, float] = {}
        #: graph -> when the node last confirmed it is subscribed; inside
        #: RETRY_SECONDS the listing is not re-read (the pulse calls every ~20 s).
        self._confirmed: dict[str, float] = {}
        #: graphs this process saw the node subscribe WITH shared memory
        self._with_shared_memory: set[str] = set()
        self._last_owner_dial: dict[str, float] = {}
        self._own_peer = ""   # this node's peer id, once known (never dial ourselves)
        #: graphs whose ``constants.COMMUNITY_SUB_GRAPH`` is registered on this node
        self._lane_ready: set[str] = set()

    def ensure_report_lane(self, client: DkgClient, graph: str) -> bool:
        """Register the community subgraph on this node before its first write
        (a node writes into a named subgraph only once that subgraph is
        registered locally; receiving nodes register it from the first share).
        Once per process per graph; "already exists" counts as ready. Returns
        whether the lane is ready; a failure is logged and the write proceeds,
        so the node's own error names what went wrong (fail-open)."""
        with self._lock:
            if graph in self._lane_ready:
                return True
        try:
            client.request("POST", "/api/sub-graph/create",
                           {"contextGraphId": graph, "subGraphName": constants.COMMUNITY_SUB_GRAPH})
        except Exception as exc:
            if "already exists" not in str(exc):
                logger.warning("blackbox: could not register the community subgraph on this node: %s", exc)
                return False
        with self._lock:
            self._lane_ready.add(graph)
        return True

    def ensure(self, client: DkgClient, cfg: object) -> tuple[bool, str]:
        """Make sure this node is subscribed to the verified graph with its shared
        memory and holds the graph's definition. Fail-open: returns ``(ok, detail-for-logs)``."""
        graph = str(getattr(cfg, "context_graph_id", "") or "")
        if not graph:
            return False, "no graph configured"
        owner = str(getattr(cfg, "graph_peer_id", "") or "")
        dialled = self._keep_owner_link(client, owner)
        if self._recently_confirmed(graph):
            return True, "subscribed"
        entry = _graph_entry(client, graph)
        subscribed = bool(entry and entry.get("subscribed"))
        defined = not owner or bool(entry and _has_definition(entry))   # the owner holds it
        if subscribed and defined and graph in self._with_shared_memory:
            self._confirm(graph)
            return True, "subscribed"
        if not self._due(self._last_subscribe, graph):
            return subscribed, "subscribe attempted recently; waiting for the node"
        if owner and not dialled:
            self._dial_owner(client, owner)
        return self._subscribe(client, graph, owner, force_catchup=subscribed and not defined)

    def _subscribe(self, client: DkgClient, graph: str, owner: str, *,
                   force_catchup: bool) -> tuple[bool, str]:
        """Subscribe with shared memory; *force_catchup* when the node is subscribed but
        lacks the graph's definition (DKG #3264). Confirmed only with the definition in."""
        if force_catchup:
            logger.info("blackbox: this node lacks the graph's definition (its writes would be "
                        "refused); fetching it again from the owner")
        try:
            reply = client.subscribe_context_graph(graph, include_shared_memory=True,
                                                   force_catchup=force_catchup)
        except DkgError as exc:
            logger.info("blackbox: subscribe with shared memory failed (retry in %ds): %s",
                        int(self.FAILED_SUBSCRIBE_RETRY_SECONDS), exc)
            self._retry_sooner(self._last_subscribe, graph)
            return False, f"subscribe failed: {exc}"
        if not _includes_shared_memory(reply):
            self._retry_sooner(self._last_subscribe, graph)
            return True, "subscribed; shared memory follows once the running catch-up ends"
        with self._lock:
            self._with_shared_memory.add(graph)
        entry = _graph_entry(client, graph)
        if owner and not (entry and _has_definition(entry)):
            self._retry_sooner(self._last_subscribe, graph)   # look for the definition in a minute
            return True, "subscribed; fetching the graph definition from its owner"
        self._confirm(graph)
        return True, "subscribed"

    def _keep_owner_link(self, client: DkgClient, owner: str) -> bool:
        """Re-dial the graph owner every ``OWNER_LINK_SECONDS`` (KI-297). Returns
        True when it dialled (or found the owner is this node) on this call."""
        if not owner or not self._due_after(self._last_owner_dial, owner, self.OWNER_LINK_SECONDS):
            return False
        self._dial_owner(client, owner)
        return True

    def _dial_owner(self, client: DkgClient, owner: str) -> None:
        """Dial the graph owner by peer id (DHT-resolved, or through a relay); never
        this node itself. Fail-open: a failed dial is logged, the subscribe still runs."""
        if owner == self._own_peer_id(client):
            return
        try:
            client.connect_peer(owner)
        except DkgError as exc:
            logger.info("blackbox: could not reach the graph owner %s: %s", owner, exc)

    def _own_peer_id(self, client: DkgClient) -> str:
        if not self._own_peer:
            try:
                self._own_peer = str((client.status() or {}).get("peerId") or "")
            except DkgError:   # cannot tell yet: dial anyway (the node refuses a self-dial)
                return ""
        return self._own_peer

    def _due_after(self, last: dict[str, float], key: str, window: float) -> bool:
        """Claim the next attempt for *key* if *window* seconds have passed."""
        now = self._clock()
        with self._lock:
            if key in last and now - last[key] < window:
                return False
            last[key] = now
            return True

    def _confirm(self, graph: str) -> None:
        with self._lock:
            self._confirmed[graph] = self._clock()

    def _recently_confirmed(self, graph: str) -> bool:
        with self._lock:
            when = self._confirmed.get(graph)
        return when is not None and self._clock() - when < self.RETRY_SECONDS

    def _retry_sooner(self, last: dict[str, float], graph: str) -> None:
        """Pull the next attempt forward to ``FAILED_SUBSCRIBE_RETRY_SECONDS`` from now."""
        with self._lock:
            last[graph] = self._clock() - (self.RETRY_SECONDS - self.FAILED_SUBSCRIBE_RETRY_SECONDS)

    def _due(self, last: dict[str, float], graph: str) -> bool:
        """Claim the next attempt for *graph* if the retry window has passed."""
        return self._due_after(last, graph, self.RETRY_SECONDS)


def _includes_shared_memory(reply: Any) -> bool:
    """Whether the node's answer to a subscribe covers shared memory. The node
    hands back an already-running catch-up instead of starting one, and that
    job's own setting is what holds (``includeWorkspace``); an answer that
    does not say is taken as covering it — the request asked for it."""
    catchup = reply.get("catchup") if isinstance(reply, dict) else None
    if not isinstance(catchup, dict):
        return True
    return catchup.get("includeSharedMemory", catchup.get("includeWorkspace")) is not False


def _graph_entry(client: DkgClient, graph: str) -> Optional[dict[str, object]]:
    """The node's own listing row for *graph* (``subscribed``, ``accessPolicy``…), or None."""
    try:
        entries = client.context_graphs()
    except Exception as exc:  # cannot tell -> treat as not subscribed (gated by the retry window)
        logger.debug("blackbox: subscription probe failed: %s", exc)
        return None
    for entry in entries:
        if str(entry.get("id") or "") == graph:
            return entry
    return None


def _has_definition(entry: dict[str, object]) -> bool:
    """True when the node holds the graph's definition: its listing names an
    access policy. A node without it lists the graph with no policy (KI-295)."""
    return str(entry.get("accessPolicy") or "").strip().lower() in {"public", "private"}


#: The process's membership state (see module docstring).
MEMBERSHIP = CommunityMembership()


def ensure_report_lane(client: DkgClient, graph: str) -> bool:
    """Before writing a community statement: register the community subgraph
    on this node (:meth:`CommunityMembership.ensure_report_lane`)."""
    return MEMBERSHIP.ensure_report_lane(client, graph)


def ensure_community_subscription(client: DkgClient, cfg: object) -> tuple[bool, str]:
    """Subscribe this node to the verified graph with its shared memory — at
    most once per process, again only when the node says it is not subscribed."""
    return MEMBERSHIP.ensure(client, cfg)


class JoinState(Enum):
    """Where this node stands with the graph the community lives in, as its own listing says.

    JOINED — subscribed with the graph's definition in (it can read and post);
    AWAITING_DEFINITION — subscribed, the definition still on its way (the node
    logs "not authorized" meanwhile, KI-295);
    JOINING — not subscribed yet;
    UNKNOWN — the node could not be asked (never read as "not joined", LES-011).
    """

    JOINED = "joined"
    AWAITING_DEFINITION = "awaiting-definition"
    JOINING = "joining"
    UNKNOWN = "unknown"


#: One plain line per state, for the dashboard (no jargon, no ids).
JOIN_STATE_TEXT: dict[JoinState, str] = {
    JoinState.JOINED: "connected",
    JoinState.AWAITING_DEFINITION: "connecting — fetching the graph's definition",
    JoinState.JOINING: "connecting — subscribing to the graph",
    JoinState.UNKNOWN: "could not check the connection (local node not answering)",
}


def join_state_of(entry: Optional[dict[str, object]], *, listing_read: bool) -> JoinState:
    """Pure: the :class:`JoinState` of the node's listing row *entry* for the
    graph (None when the graph is not listed). *listing_read* False means the
    listing itself could not be read."""
    if not listing_read:
        return JoinState.UNKNOWN
    if entry is None or not entry.get("subscribed"):
        return JoinState.JOINING
    return JoinState.JOINED if _has_definition(entry) else JoinState.AWAITING_DEFINITION


def read_join_state(client: DkgClient, graph: str) -> JoinState:
    """Ask the node once (its context-graph listing) where it stands with *graph*."""
    try:
        entries = client.context_graphs()
    except Exception as exc:   # could not tell (LES-011)
        logger.debug("blackbox: community join state unreadable: %s", exc)
        return JoinState.UNKNOWN
    entry = next((row for row in entries if str(row.get("id") or "") == graph), None)
    return join_state_of(entry, listing_read=True)
