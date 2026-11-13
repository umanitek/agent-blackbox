"""Proposals travel between curator nodes by private point-to-point message (Refine R6).

Plan §09 TRANSPORT: a proposal is stored in each curator's private memory and
sent to the other curator over the network's private messaging — never in a
shared graph before approval. ONE hand-off: the first curator proposes, the
second approves and publishes. The message text is the proposal's JSON behind
a fixed prefix; what matters inside it is the signed envelope, which the
receiver verifies against the key manifest (:mod:`.verbs`), never the message.
Peers are the other curators' DKG peer ids, given to the service with ``--peer``.

A proposal that reached no other curator is sent again on every beat; the
:class:`DeliveryLedger` counts those beats, and from the third one in a row it
is an ALARM (a health item on ``blackbox status``) — a halted quorum is
visible, never silent (trust-and-threat-lab §03.3, F-036).

Usage::

    transport.send_proposal(client, peer, proposal)
    for proposal in transport.receive_proposals(client, InboxCursor()): store.save(proposal)
    entry = DeliveryLedger().failed(proposal.id, now=time.time())   # no curator reached this beat
    DeliveryLedger().delivered(proposal.id)                          # one did
"""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path
from dataclasses import dataclass
from typing import Any, Optional

from ...kernel import node_routes, yaml_files
from ...kernel.bounded_files import read_json_object
from ...kernel.dkg_client import DkgClient
from ...kernel.health import HealthClass, HealthItem
from .. import keys
from .proposal import Proposal, ProposalError, ProposalState
from ...kernel.bounded_files import atomic_write

logger = logging.getLogger(__name__)

PROPOSAL_PREFIX = "blackbox-proposal:"
_CURSOR_FILE = "inbox_cursor.json"
_DELIVERY_FILE = "undelivered.json"
#: Beats in a row a proposal reached no other curator before it is an alarm.
ALARM_AFTER_BEATS = 3
#: An undelivered proposal not retried for this long has closed some other way
#: (published, rejected, expired) and is no longer shown as an alarm.
ALARM_FRESH_SECONDS = 6 * 3600


class InboxCursor:
    """Where this curator stopped reading its inbox (``since``, ``since_id``);
    persisted so no message is read twice or skipped. One lock, atomic write."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or (keys.curate_home() / _CURSOR_FILE)
        self._lock = threading.Lock()

    def read(self) -> dict[str, int]:
        try:
            data = json.loads(self._path.read_text(encoding="utf-8-sig"))
            return {"since": int(data.get("since", 0)), "since_id": int(data.get("since_id", 0))}
        except (OSError, ValueError, TypeError, AttributeError):
            return {"since": 0, "since_id": 0}

    def advance(self, message: node_routes.InboxMessage) -> None:
        with self._lock:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            atomic_write(self._path, json.dumps({"since": message.ts, "since_id": message.id}))


def send_proposal(client: DkgClient, peer: str, proposal: Proposal) -> dict[str, Any]:
    """Send *proposal* to the other curator; returns the node's delivery result."""
    return node_routes.send_message(client, peer, PROPOSAL_PREFIX + proposal.to_json())


def parse_message(text: str) -> Optional[Proposal]:
    """The proposal a message carries, as PROPOSED; None for any other message."""
    if not text.startswith(PROPOSAL_PREFIX):
        return None
    try:
        proposal = Proposal.from_json(text[len(PROPOSAL_PREFIX):])
    except ProposalError:
        return None
    if proposal.state is ProposalState.DRAFT:
        proposal = proposal.transition(ProposalState.PROPOSED)
    return proposal if proposal.state is ProposalState.PROPOSED else None


def receive_proposals(client: DkgClient, cursor: InboxCursor) -> list[Proposal]:
    """Every proposal in the inbox since the cursor, advancing it past each
    message read (proposal or not)."""
    position = cursor.read()
    found: list[Proposal] = []
    for message in node_routes.inbox(client, since=position["since"], since_id=position["since_id"]):
        proposal = parse_message(message.text)
        if proposal is not None:
            found.append(proposal)
        cursor.advance(message)
    return found


@dataclass(frozen=True)
class Undelivered:
    """A proposal no other curator has received: ``beats`` in a row tried, the last at ``last_tried`` (epoch s)."""

    proposal_id: str
    beats: int
    last_tried: float

    @property
    def alarmed(self) -> bool:
        return self.beats >= ALARM_AFTER_BEATS

    def text(self) -> str:
        """The beat's error line for this proposal."""
        if self.alarmed:
            return (f"ALARM: proposal {self.proposal_id} reached no other curator for {self.beats} beats — "
                    "the quorum is halted (check the --peer ids and that the curator nodes are dialled)")
        return f"proposal {self.proposal_id} reached no other curator yet (retrying next beat, {self.beats} of {ALARM_AFTER_BEATS})"


class DeliveryLedger:
    """Which of this node's proposals reached no other curator, and for how
    many beats in a row (``<curate home>/undelivered.json``). One lock, atomic
    write; an unreadable file reads as empty (the next failed beat starts it again)."""

    _lock = threading.Lock()

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path or (keys.curate_home() / _DELIVERY_FILE)

    def _read(self) -> dict[str, dict[str, float]]:
        data = read_json_object(self._path) or {}
        return {str(key): value for key, value in data.items() if isinstance(value, dict)}

    def failed(self, proposal_id: str, *, now: float) -> Undelivered:
        """Record one more beat in which *proposal_id* reached no other curator."""
        with self._lock:
            entries = self._read()
            beats = int((entries.get(proposal_id) or {}).get("beats", 0) or 0) + 1
            entries[proposal_id] = {"beats": beats, "last_tried": now}
            yaml_files.atomic_write(self._path, json.dumps(entries))
        return Undelivered(proposal_id, beats, now)

    def delivered(self, proposal_id: str) -> None:
        """*proposal_id* reached a curator (or is finished): forget it."""
        with self._lock:
            entries = self._read()
            if entries.pop(proposal_id, None) is not None:
                yaml_files.atomic_write(self._path, json.dumps(entries))

    def alarms(self, now: float) -> list[Undelivered]:
        """The proposals alarmed and still being retried, oldest-tried first."""
        found = []
        for proposal_id, entry in self._read().items():
            try:
                item = Undelivered(proposal_id, int(entry.get("beats", 0)), float(entry.get("last_tried", 0)))
            except (TypeError, ValueError):
                continue
            if item.alarmed and now - item.last_tried <= ALARM_FRESH_SECONDS:
                found.append(item)
        return sorted(found, key=lambda item: item.last_tried)


def delivery_health_items(now: float, ledger: Optional[DeliveryLedger] = None) -> list[HealthItem]:
    """One ACTION item per alarmed proposal (none on a node that is not a curator)."""
    return [HealthItem("operator", HealthClass.ACTION,
                       f"curator quorum HALTED: proposal {item.proposal_id} reached no other curator for {item.beats} beats",
                       "check the service's --peer ids and that both curator nodes keep a dialled link; it is retried every beat")
            for item in (ledger or DeliveryLedger()).alarms(now)]
