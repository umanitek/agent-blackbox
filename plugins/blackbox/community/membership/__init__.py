"""Community membership — the verified graph's subscription WITH shared memory, on the node's word.

Since 2026-10-16 there is one graph: the community's reports live in the
verified graph's shared memory (sub-graph ``constants.COMMUNITY_SUB_GRAPH``),
so belonging to the community is the verified graph's subscription with its
shared memory included. The graph is registered on chain, so a fresh node
finds it without first dialling an owner peer (the separate community graph
was unregistered and needed that, KI-216), and the node gets its definition
by itself, also when it reaches only Cores (DKG 10.0.25: OriginTrail/dkg#3303,
#3311). Its access is public, but its publish policy is CURATED: the owner keeps
shared-memory writes only from agents on its sync allowlist and silently drops
the rest (production, 2026-10-21, KI-439). So every node asks to join once, and
the owner admits it (``community_auto_approve`` on a Blackbox owner, or
scripts/blackbox-curator-approve.py on the owner's bare DKG node). Admission
is the sync allowlist only, never a right to publish. Before Refine R0
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
* on the graph owner's node only, register the community lanes (``reports``
  and ``sandbox``) before the first write there: every other node writes into
  the owner's sub-graphs as they are (DKG 10.0.25 looks the owner's
  registration up at a member's first write, OriginTrail/dkg#3306);
* a member sends ONE join request per process, within seconds of starting, when
  the node's own listing says the owner decides who writes (private access, or
  a curated publish policy) — positive evidence only (LES-028) — and never to
  itself; whether or not sharing is on. Until that answer is known the listing
  is read at most once a minute, and never again once it is;
* an owner with ``community_auto_approve`` approves pending join requests at
  most once per ``APPROVE_SECONDS``.

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
import urllib.parse
from typing import Any, Callable, Optional

from ...kernel import constants, identity
from ...kernel.dkg_client import DkgClient, DkgError
from .join_status import (ADMISSION_TEXT, JOIN_STATE_TEXT, Admission, JoinState, MembershipStatus, has_definition,
                          join_state_of, needs_join, owns, read_join_state, read_membership_status)
from .readiness import READINESS, GraphReadiness

logger = logging.getLogger(__name__)

#: The shared-memory lanes the graph owner registers (2026-10-21): real reports, and sandbox tests.
COMMUNITY_LANES = (constants.COMMUNITY_SUB_GRAPH, constants.SANDBOX_SUB_GRAPH)


class CommunityMembership:
    """Subscription state for this process, guarded by one lock."""

    #: How long a confirmed subscription is trusted before the node's listing is
    #: read again, and how long a subscribe the node did not take waits.
    RETRY_SECONDS = 600.0
    #: A subscribe the node REFUSED (authority not reachable yet, chain hiccup),
    #: or answered without shared memory, is retried this soon.
    FAILED_SUBSCRIBE_RETRY_SECONDS = 60.0
    #: Owner node with ``community_auto_approve``: how often the pending join requests are read.
    APPROVE_SECONDS = 60.0

    def __init__(self, clock: Callable[[], float] = time.monotonic, readiness: Optional[GraphReadiness] = None) -> None:
        self._clock = clock
        #: whether this node already added the graph's shared memory (KI-449,
        #: :mod:`.readiness`); None = the process's :data:`READINESS`, looked up on use
        self._own_readiness = readiness
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
        self._joined: set[str] = set()          # graphs this process asked to join (or owns)
        self._open: set[str] = set()            # graphs known to need no join (open, unregistered)
        self._last_join_probe: dict[str, float] = {}
        self._last_approve: dict[str, float] = {}

    @property
    def _readiness(self) -> GraphReadiness:
        return self._own_readiness if self._own_readiness is not None else READINESS

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
        if not owns(address, graph):   # a member: nothing to register
            with self._lock:
                self._lane_ready.add(graph)
            return True
        for lane in COMMUNITY_LANES:
            try:
                client.request("POST", "/api/sub-graph/create", {"contextGraphId": graph, "subGraphName": lane})
            except DkgError as exc:   # the client wraps HTTP and transport failures in DkgError
                if "already exists" not in str(exc):
                    logger.warning("blackbox: could not register the community subgraph %r on this node: %s", lane, exc)
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
        if getattr(cfg, "snapshot_sync_error", ""):
            return False, "snapshot_sync configuration invalid; subscription unchanged"
        if getattr(cfg, "snapshot_sync", None) is not None:
            # Adding shared memory can schedule catch-up. Do not race the owned
            # foreground snapshot; existing local community protections still read.
            try:
                job = client.request("GET", "/api/context-graph/snapshot-sync")
            except DkgError:
                return False, "snapshot state unavailable; subscription unchanged"
            if job.get("state") not in {"complete", "failed"}:
                return False, "shared memory follows the owned public snapshot"
        if getattr(cfg, "community_auto_approve", False):
            self._approve_pending(client, graph)
        self._join_check(client, cfg, graph)
        if self._recently_confirmed(graph):
            return True, "subscribed"
        # KI-449: the shared memory is added ONCE per node (the readiness record survives
        # restarts); afterwards only the node's listing is confirmed, never re-subscribed.
        if graph in self._with_shared_memory or self._readiness.shared_memory_added(graph):
            readable, entry = _listing_row(client, graph)
            if not readable:   # could not tell: request nothing (LES-011)
                return False, "the node's listing could not be read; nothing requested"
            if entry and entry.get("subscribed"):
                self._confirm(graph)
                return True, "subscribed"
        return self._subscribe(client, graph)

    def _join_check(self, client: DkgClient, cfg: object, graph: str) -> None:
        """Decide at once whether this node must ask to join, and ask. Reads the node's
        listing at most once per ``FAILED_SUBSCRIBE_RETRY_SECONDS`` and ONLY until the
        answer is known — joined, or a graph that needs no join — then never again for
        this; a fresh install asks within seconds of subscribing (Amos, 2026-10-21: no
        wait). Positive evidence only (LES-028): an undecided listing is asked again.
        A node the listing already names as a member (``callerInvolved``) sends nothing,
        so a restart never re-asks a graph this node was admitted to (bench 2026-10-21)."""
        with self._lock:
            if graph in self._joined or graph in self._open:
                return
        if not self._due_after(self._last_join_probe, graph, self.FAILED_SUBSCRIBE_RETRY_SECONDS):
            return
        entry = _graph_entry(client, graph)
        verdict = join_verdict(entry)
        if verdict == "open":
            with self._lock:
                self._open.add(graph)
        elif verdict == "member":
            with self._lock:
                self._joined.add(graph)
        elif verdict == "join":
            self._request_join(client, cfg, graph)

    def _request_join(self, client: DkgClient, cfg: object, graph: str) -> None:
        """Send this node's one join request for *graph* (never from the owner itself)."""
        address = identity.reporter_address(client)
        owner_peer = str(getattr(cfg, "graph_peer_id", "") or "")
        if not address or not owner_peer:
            return   # asked again at the next probe
        if not owns(address, graph):
            try:
                client.request_join(graph, owner_peer)
            except DkgError as exc:   # asked again at the next probe
                logger.info("blackbox: join request for %s failed: %s", graph, exc)
                return
        with self._lock:
            self._joined.add(graph)

    def _approve_pending(self, client: DkgClient, graph: str) -> int:
        """Owner node: approve every pending join request for *graph*, at most once per
        ``APPROVE_SECONDS``. Admission is the sync allowlist only — Verified Memory of a
        curated graph accepts publishes only from its publish authority (chain-checked);
        trust stays read-side (signed reports, verified authors, flag-only). Returns how many."""
        if not self._due_after(self._last_approve, graph, self.APPROVE_SECONDS):
            return 0
        encoded = urllib.parse.quote(graph, safe="")
        try:
            reply = client.request("GET", f"/api/context-graph/{encoded}/join-requests")
        except DkgError as exc:   # not the owner, or the node is busy: nothing to do
            logger.debug("blackbox: join requests unreadable for %s: %s", graph, exc)
            return 0
        approved = 0
        for agent in pending_join_agents(reply):
            try:
                client.request("POST", f"/api/context-graph/{encoded}/approve-join", {"agentAddress": agent})
                approved += 1
            except DkgError as exc:   # e.g. a revoked agent: the owner re-adds it by hand (KI-445)
                logger.warning("blackbox: could not approve the join request of %s: %s", agent, exc)
        if approved:
            logger.info("blackbox: approved %d join request(s) for %s", approved, graph)
        return approved

    def _due_after(self, last: dict[str, float], key: str, window: float) -> bool:
        """Claim the next attempt for *key* if *window* seconds have passed."""
        now = self._clock()
        with self._lock:
            if key in last and now - last[key] < window:
                return False
            last[key] = now
            return True

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
        self._readiness.mark_shared_memory_added(graph)   # added once: later processes only confirm
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


def pending_join_agents(reply: object) -> list[str]:
    """Pure: the agent addresses of the PENDING requests in a ``join-requests`` reply
    (mirrored by scripts/blackbox-curator-approve.py; parity-tested)."""
    rows = reply.get("requests") if isinstance(reply, dict) else None
    out: list[str] = []
    for row in rows or []:
        if not isinstance(row, dict) or str(row.get("status") or "pending").lower() != "pending":
            continue
        agent = str(row.get("agentAddress") or row.get("agent") or "")
        if agent.startswith("0x") and len(agent) == 42:
            out.append(agent)
    return out


def join_verdict(entry: Optional[dict[str, object]]) -> str:
    """Pure: what this node must do about joining the listed graph.

    * ``member`` — the owner decides who writes AND the node says this node is already
      admitted (``callerInvolved`` true: its wallet is the curator or on the allowlist);
    * ``join`` — the owner decides who writes and the node says this node is NOT admitted;
    * ``open`` — definitely no join step: an unregistered graph whose definition is in,
      or a registered one whose publish policy is not curated;
    * ``undecided`` — not listed, the definition or chain record has not arrived, or the
      node could not tell whether this node is admitted (it leaves ``callerInvolved``
      out when its allowlist lookup fails) — ask again later, never guess (LES-011).

    ``callerInvolved`` is DKG 10.0.25's own answer for the calling agent: the curator
    match OR ``callerIsAllowlistedAgentParticipant`` (dkg-agent-cg-resolve.js)."""
    if not entry:
        return "undecided"
    if needs_join(entry):
        involved = entry.get("callerInvolved")
        if involved is True:
            return "member"
        return "join" if involved is False else "undecided"
    registered = bool(entry.get("onChainId")) or isinstance(entry.get("onChain"), dict)
    if registered:
        on_chain = entry.get("onChain") if isinstance(entry.get("onChain"), dict) else {}
        return "open" if on_chain.get("publishPolicy") else "undecided"
    return "open" if has_definition(entry) else "undecided"


def _listing_row(client: DkgClient, graph: str) -> tuple[bool, Optional[dict[str, object]]]:
    """``(readable, row)``: whether the node's listing could be read, and its row for
    *graph* (None when not listed) — "could not read" and "not listed" kept apart."""
    try:
        entries = client.context_graphs()
    except Exception as exc:  # health: allow BLE001 -- fail-open probe: any failure means "could not tell", and the caller then requests nothing
        logger.debug("blackbox: subscription probe failed: %s", exc)
        return False, None
    return True, next((entry for entry in entries if str(entry.get("id") or "") == graph), None)


def _graph_entry(client: DkgClient, graph: str) -> Optional[dict[str, object]]:
    """The node's own listing row for *graph* (``subscribed``, ``accessPolicy``…), or None."""
    return _listing_row(client, graph)[1]


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


__all__ = [
    "ADMISSION_TEXT",
    "COMMUNITY_LANES",
    "JOIN_STATE_TEXT",          # re-exported from join_status (the read side)
    "MEMBERSHIP",
    "Admission",
    "CommunityMembership",
    "JoinState",
    "MembershipStatus",
    "ensure_community_subscription",
    "ensure_report_lane",
    "join_state_of",
    "join_verdict",
    "needs_join",
    "pending_join_agents",
    "read_join_state",
    "read_membership_status",
]
