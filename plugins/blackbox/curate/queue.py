"""The curator's queue — the delta view and its lanes (Refine R6, plan §09).

The queue opens split in two (v1.3 DELTA VIEW): NEW threats — absent from the
verified graph, the only items that reach a lane — and ALREADY VERIFIED ones —
community reports of a threat the verified graph already lists, closed as
duplicates (their sightings feed the R2b counter instead). Lanes order the
curator's attention when over budget: (1) disputes against verified + revocations,
(2) blockable with evidence, (3) graduation, (4) blockable needing reproduction,
(5) flag-only sampling.

A dispute a listed party files on the public page (``intake.DisputeIntake``,
trust-and-threat-lab §03.3) is admitted to lane 1 — :attr:`Lane.DISPUTE` — with
no counted reporter behind it, and even when the verified graph already lists
the threat: a wrong VERIFIED listing is exactly what a dispute is for.

Pattern: pure functions over the compiled community store (every node has the
same one, R3) and the verified identifiers.

Usage::

    view = queue.delta_view(rs.community, verified_identifiers, publicly_disputed=open_dispute_identifiers)
    for item in view.new: print(item.lane, item.identifier, item.stage)
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import AbstractSet, Any, Mapping

#: Threat classes whose verified rule may BLOCK (the truth check is mandatory).
BLOCKABLE_PREFIXES = ("dep:", "escalation:", "fileaccess:", "skill:")


class Lane(Enum):
    """Where an item waits, in priority order (plan §09 CAPACITY AND BACKLOG MODE)."""

    DISPUTES_AND_REVOCATIONS = 1
    #: The same lane by its short name — where a public-page dispute waits (an Enum alias, not a sixth lane).
    DISPUTE = 1  # noqa: PIE796 — a deliberate alias of DISPUTES_AND_REVOCATIONS (see the comment above)
    BLOCKABLE_WITH_EVIDENCE = 2
    GRADUATION = 3
    BLOCKABLE_NEEDS_REPRODUCTION = 4
    FLAG_ONLY_SAMPLING = 5


@dataclass(frozen=True)
class QueueItem:
    """One NEW community threat: its local stage and reason (R3), how many
    verified signers reported it, whether a counted author disputes it, and
    its lane."""

    identifier: str
    stage: str
    enforcement: str
    reason: str
    reporters: int
    disputed: bool
    lane: Lane


@dataclass(frozen=True)
class DeltaView:
    """``new`` — items for the lanes, ordered by lane then most reporters;
    ``already_verified`` — identifiers the verified graph already lists;
    ``unlisted_only`` — new threats reported by unlisted authors alone and
    undisputed: stored and shown with the "new reporter" label, but ADMITTED
    to no lane (plan §05 queue admission — counted weight, or a dispute).
    Without this rule 5,000 fresh single-author reports would fill every
    lane and fire the intake webhook 5,000 times (KI-194)."""

    new: tuple[QueueItem, ...]
    already_verified: tuple[str, ...]
    unlisted_only: tuple[str, ...] = ()


def admitted(rule: Mapping[str, Any]) -> bool:
    """Plan §05: a threat reaches a curator lane only with counted weight
    behind it or a dispute against it."""
    return int(rule.get("counted") or 0) > 0 or rule.get("disputed") == "yes"


def has_evidence(rule: Mapping[str, Any]) -> bool:
    """A dependency report with an advisory-backed reason carries evidence.
    Compiled community rules carry the reason as ``reportReason`` (the reader's
    variable name); ``reason`` / ``advisoryId`` are the builder's and the
    verified tier's names."""
    reason = str(rule.get("reportReason") or rule.get("reason") or "")
    return reason.startswith("advisory:") or bool(rule.get("advisoryId"))


def credits_a_newcomer(rule: Mapping[str, Any]) -> bool:
    """True when an unlisted reporter is among the threat's reporters: confirming
    it is what lets that reporter earn its way onto the trusted list. Admission
    is unchanged — the threat is in the queue only because a COUNTED reporter
    (or a dispute) is behind it, so a flood of fresh reports still reaches no lane."""
    return int(rule.get("unlistedReporters") or 0) > 0


def lane_for(identifier: str, rule: Mapping[str, Any]) -> Lane:
    if rule.get("disputed") == "yes":
        return Lane.DISPUTES_AND_REVOCATIONS
    if identifier.startswith(BLOCKABLE_PREFIXES) and has_evidence(rule):
        return Lane.BLOCKABLE_WITH_EVIDENCE
    if credits_a_newcomer(rule):
        return Lane.GRADUATION
    if identifier.startswith(BLOCKABLE_PREFIXES):
        return Lane.BLOCKABLE_NEEDS_REPRODUCTION
    return Lane.FLAG_ONLY_SAMPLING


def _item(identifier: str, rule: Mapping[str, Any], lane: Lane) -> QueueItem:
    return QueueItem(identifier=identifier, stage=str(rule.get("stage") or "reported"),
                     enforcement=str(rule.get("enforcement") or "monitor"), reason=str(rule.get("stageReason") or ""),
                     reporters=int(rule.get("reporterCount") or 0),
                     disputed=lane is Lane.DISPUTE or rule.get("disputed") == "yes", lane=lane)


def delta_view(community_rules: Mapping[str, Mapping[str, Any]], verified_identifiers: AbstractSet[str],
               publicly_disputed: AbstractSet[str] = frozenset()) -> DeltaView:
    """Split the compiled community store against the verified graph.
    *publicly_disputed* — identifiers with an open public-page dispute: each is
    admitted to :attr:`Lane.DISPUTE` whatever its counted weight, verified or not."""
    new = [_item(identifier, community_rules.get(identifier) or {}, Lane.DISPUTE) for identifier in publicly_disputed]
    already = []
    unlisted = []
    for identifier, rule in community_rules.items():
        if identifier in publicly_disputed:
            continue
        if identifier in verified_identifiers:
            already.append(identifier)
            continue
        if not admitted(rule):
            unlisted.append(identifier)
            continue
        new.append(_item(identifier, rule, lane_for(identifier, rule)))
    new.sort(key=lambda item: (item.lane.value, -item.reporters, item.identifier))
    return DeltaView(new=tuple(new), already_verified=tuple(sorted(already)), unlisted_only=tuple(sorted(unlisted)))
