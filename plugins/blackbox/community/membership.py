"""Community membership — the verified graph's subscription WITH shared memory, on the node's word.

Since 2026-10-16 there is one graph: the community's reports live in the
verified graph's shared memory (sub-graph ``constants.COMMUNITY_SUB_GRAPH``),
so belonging to the community is the verified graph's subscription with its
shared memory included. The graph is registered on chain, so a fresh node
finds it without first dialling an owner peer (the separate community graph
was unregistered and needed that, KI-216), and the node gets its definition
by itself, also when it reaches only Cores (DKG 10.0.25: OriginTrail/dkg#3303,
#3311). It is public: there is no join step (D-040). Before Refine R0
(KI-064/114) the ruleset subscribed on EVERY refresh; one object now owns that
state:

* subscribe with shared memory once per process — a node subscribed VM-only
  by an older release gets its shared memory added by that request. The node
  answers whether the catch-up it started (or found) includes shared memory;
* after that, re-read the node's own listing at most once per
  ``RETRY_SECONDS`` and subscribe again only when it no longer lists the graph
  as subscribed;
* a subscribe the node refused, or one answered by a VM-only catch-up still
  running (shared memory can be added once it ends), is retried after
  ``FAILED_SUBSCRIBE_RETRY_SECONDS``;
* on the graph owner's node only, register the report sub-graph before the
  first write there: every other node writes into the owner's sub-graph as it
  is (DKG 10.0.25 looks the owner's registration up at a member's first write,
  OriginTrail/dkg#3306).

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

from ..kernel import constants, identity
from ..kernel.dkg_client import DkgClient, DkgError

logger = logging.getLogger(__name__)


class CommunityMembership:
    """Subscription state for this process, guarded by one lock."""

    #: How long a confirmed subscription is trusted before the node's listing is
    #: read again, and how long a subscribe the node did not take waits.
    RETRY_SECONDS = 600.0
    #: A subscribe the node REFUSED (authority not reachable yet, chain hiccup),
    #: or answered without shared memory, is retried this soon.
    FAILED_SUBSCRIBE_RETRY_SECONDS = 60.0

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._last_subscribe: dict[str, float] = {}
        #: graph -> when the node last confirmed it is subscribed; inside
        #: RETRY_SECONDS the listing is not re-read (the pulse calls every ~20 s).
        self._confirmed: dict[str, float] = {}
        #: graphs this process saw the node subscribe WITH shared memory
        self._with_shared_memory: set[str] = set()
        #: graphs whose ``constants.COMMUNITY_SUB_GRAPH`` this node may write into: registered
        #: here when this node owns the graph, the owner's registration otherwise
        self._lane_ready: set[str] = set()

    def ensure_report_lane(self, client: DkgClient, graph: str) -> bool:
        """Before this node's first write into the community sub-graph: when this
        node OWNS the graph (its agent address is the graph id's namespace),
        register the sub-graph; that registration is what every other node's
        write resolves, so a member registers nothing (DKG 10.0.25 looks the
        owner's registration up at a member's first write, OriginTrail/dkg#3306).
        Once per process per graph; "already exists" counts as ready. Returns
        whether the lane is ready (False also while this node's own address is
        unknown); a failure is logged and the write proceeds, so the node's own
        error names what went wrong (fail-open)."""
        with self._lock:
            if graph in self._lane_ready:
                return True
        address = identity.reporter_address(client)
        if not address:
            return False
        if not _owns(address, graph):   # a member: nothing to register
            with self._lock:
                self._lane_ready.add(graph)
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
        """Make sure this node is subscribed to the verified graph with its
        shared memory. Fail-open: returns ``(ok, detail-for-logs)``."""
        graph = str(getattr(cfg, "context_graph_id", "") or "")
        if not graph:
            return False, "no graph configured"
        if self._recently_confirmed(graph):
            return True, "subscribed"
        if graph in self._with_shared_memory:
            entry = _graph_entry(client, graph)
            if entry and entry.get("subscribed"):
                self._confirm(graph)
                return True, "subscribed"
        return self._subscribe(client, graph)

    def _subscribe(self, client: DkgClient, graph: str) -> tuple[bool, str]:
        if not self._due(self._last_subscribe, graph):
            return False, "subscribe attempted recently; waiting for the node"
        try:
            reply = client.subscribe_context_graph(graph, include_shared_memory=True)
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
        self._confirm(graph)
        return True, "subscribed"

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
        now = self._clock()
        with self._lock:
            if graph in last and now - last[graph] < self.RETRY_SECONDS:
                return False
            last[graph] = now
            return True


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


def _owns(address: str, graph: str) -> bool:
    """*address* owns *graph*: a registered graph's id is its owner's address, "/", its name."""
    owner, slash, _name = graph.partition("/")
    return bool(slash) and owner.lower() == address.lower()


def _has_definition(entry: dict[str, object]) -> bool:
    """True when the node holds the graph's definition: its listing names an
    access policy. A node without it lists the graph with no policy (KI-295)."""
    return str(entry.get("accessPolicy") or "").strip().lower() in {"public", "private"}


#: The process's membership state (see module docstring).
MEMBERSHIP = CommunityMembership()


def ensure_report_lane(client: DkgClient, graph: str) -> bool:
    """Before writing a community statement: on the graph owner's node, register
    the community sub-graph (:meth:`CommunityMembership.ensure_report_lane`)."""
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
