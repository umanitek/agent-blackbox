"""Where this node stands with the community's graph, as the node's own listing says.

Split out of the membership module (2026-10-21) when it reached the 400-line alarm:
this is the read side the dashboard shows (connected or not); the membership
module keeps the state machine that subscribes and joins.

Public surface: :class:`JoinState`, :data:`JOIN_STATE_TEXT`, :func:`join_state_of`
(pure), :func:`read_join_state` (one listing read), :class:`Admission` / :data:`ADMISSION_TEXT` / :func:`admission_of` (pure: has the
owner approved this node), :func:`read_membership_status` (both from one listing read),
and the pure listing reads
:func:`has_definition`, :func:`needs_join` and :func:`owns`.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from ...kernel import identity
from ...kernel.dkg_client import DkgClient

logger = logging.getLogger(__name__)


def has_definition(entry: dict[str, object]) -> bool:
    """True when the node holds the graph's definition: its listing names an
    access policy. A node without it lists the graph with no policy (KI-295)."""
    return str(entry.get("accessPolicy") or "").strip().lower() in {"public", "private"}



def listing_row(client: DkgClient, graph: str) -> tuple[bool, Optional[dict[str, object]]]:
    """``(readable, row)``: whether the node's context-graph listing could be read, and its row
    for *graph* (None when not listed) — "could not read" and "not listed" kept apart. The ONE
    read of the listing: the join state machine, the dashboard's status and the community
    read's "is an empty read proof?" check all ask it."""
    try:
        entries = client.context_graphs()
    except Exception as exc:  # health: allow BLE001 -- fail-open probe: any failure means "could not tell" (LES-011)
        logger.debug("blackbox: context-graph listing unreadable: %s", exc)
        return False, None
    return True, next((entry for entry in entries if str(entry.get("id") or "") == graph), None)

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


def needs_join(entry: dict[str, object]) -> bool:
    """Pure: whether writing to the listed graph needs the owner's admission — private
    access, or a registered graph with a CURATED publish policy (the verified graph)."""
    on_chain = entry.get("onChain") if isinstance(entry.get("onChain"), dict) else {}
    return (str(entry.get("accessPolicy") or "") == "private"
            or str(on_chain.get("publishPolicy") or "").lower() == "curated")


def owns(address: str, graph: str) -> bool:
    """*address* owns *graph*: a registered graph's id is its owner's address, "/", its name."""
    owner, slash, _name = graph.partition("/")
    return bool(slash) and owner.lower() == address.lower()


def join_state_of(entry: Optional[dict[str, object]], *, listing_read: bool) -> JoinState:
    """Pure: the :class:`JoinState` of the node's listing row *entry* for the
    graph (None when the graph is not listed). *listing_read* False means the
    listing itself could not be read."""
    if not listing_read:
        return JoinState.UNKNOWN
    if entry is None or not entry.get("subscribed"):
        return JoinState.JOINING
    return JoinState.JOINED if has_definition(entry) else JoinState.AWAITING_DEFINITION


def read_join_state(client: DkgClient, graph: str) -> JoinState:
    """Ask the node once (its context-graph listing) where it stands with *graph*."""
    readable, entry = listing_row(client, graph)
    return join_state_of(entry, listing_read=readable)


class Admission(Enum):
    """Whether the graph's owner lets this node write into its shared memory, as the
    node's own listing says (``callerInvolved``: DKG 10.0.25's answer for the calling
    agent — the curator, or an agent on the graph's allowlist).

    OWNER — this node's agent owns the graph (it approves the others);
    APPROVED — the owner decides who writes and has admitted this node;
    WAITING — the owner decides who writes and has not admitted this node yet;
    OPEN — the graph admits every writer, nothing to approve;
    UNKNOWN — the node could not tell (never read as "not approved", LES-011).
    """

    OWNER = "owner"
    APPROVED = "approved"
    WAITING = "waiting"
    OPEN = "open"
    UNKNOWN = "unknown"


#: One plain line per state, for the dashboard.
ADMISSION_TEXT: dict[Admission, str] = {
    Admission.OWNER: "this node owns the graph and approves its members",
    Admission.APPROVED: "approved by the graph's owner: this node's warnings reach the other members",
    Admission.WAITING: "waiting for the graph owner's approval: until then the owner drops this node's warnings",
    Admission.OPEN: "open graph: no approval needed",
    Admission.UNKNOWN: "could not check the approval (local node not answering)",
}


def admission_of(entry: Optional[dict[str, object]], address: str, graph: str) -> Admission:
    """Pure: the :class:`Admission` of this node (agent *address*) for *graph*, from the
    node's listing row *entry* (None when it could not be read or does not list it)."""
    if entry is None:
        return Admission.UNKNOWN
    if address and owns(address, graph):
        return Admission.OWNER
    # The state machine's own decision, so the dashboard can never say "open" while it waits.
    return _ADMISSION_OF_VERDICT[join_verdict(entry)]


#: :func:`join_verdict` -> what the dashboard shows.
_ADMISSION_OF_VERDICT = {"member": Admission.APPROVED, "join": Admission.WAITING, "open": Admission.OPEN,
                         "undecided": Admission.UNKNOWN}


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


@dataclass(frozen=True)
class MembershipStatus:
    """Where this node stands with the graph: connected (``join``) and admitted
    (``admission``), both from ONE read of the node's listing."""

    join: JoinState
    admission: Admission


def read_membership_status(client: DkgClient, graph: str) -> MembershipStatus:
    """Ask the node once (its context-graph listing) where it stands with *graph*:
    connected or not, approved or not. Fail-open: an unreadable listing is UNKNOWN."""
    readable, entry = listing_row(client, graph)
    if not readable:
        return MembershipStatus(JoinState.UNKNOWN, Admission.UNKNOWN)
    address = identity.reporter_address(client) or ""
    return MembershipStatus(join_state_of(entry, listing_read=True), admission_of(entry, address, graph))
