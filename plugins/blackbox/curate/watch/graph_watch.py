"""Verified-graph watch — every new asset must be explained by a record this node keeps.

The verified graph is owned by the publishing wallet, so an asset that appears
there and that no record on this node explains means the wallet was used by
someone else (SECURITY). Which record explains an asset depends on the node
(pattern: Strategy, one class per record):

* :class:`LedgerExpectation` — the publisher node: the asset's UAL is one its
  :class:`~..publishing.ledger.PublishLedger` recorded. A batch still SUBMITTED
  or MINTED with no UAL yet (a 207 whose answer named none) may account for
  one asset that appeared after it was submitted: that asset is "could not
  tell" (INFO), never cleared and never alarmed, and the caller passes it
  again on the next beat. The submit time comes from the ledger's lines, not
  the batch's latest move, so an asset seen between the submit and the 207
  being recorded stays claimable.
* :class:`CosignExpectation` — the second curator node, which has no publish
  ledger: every signed envelope the asset carries is one its own key signed or
  co-signed (its :class:`.SigningLog`). An asset with no envelope is the wallet
  alone and is unexplained too.

Also here, because the second node's watcher runs them beside the graph watch:

* :func:`proposal_rate` — the first curator's proposals per lane against the
  lane's normal; :data:`RATE_WARNING_FACTOR` times normal or more → ACTION.
* :func:`dead_man_beat` — the watcher's own daily "all quiet" record, produced
  once per UTC day; whoever receives it alarms when a day passes without one.

Every function is a pure comparison: records come in as values or readers, the
clock as a number.

Usage::

    expected = LedgerExpectation(PublishLedger().transitions())      # or
    expected = CosignExpectation(SigningLog().rows(), my_public_key)
    items = unexpected_assets([GraphAsset(ual, digests, seen_at)], expected)
    items += proposal_rate({"dependency": 40}, {"dependency": 8.0})
    beat = dead_man_beat(now, last_beat_day, items)   # None: today's beat exists
"""

from __future__ import annotations

import math
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Iterable, Mapping, Optional, Protocol, Sequence

from ...kernel.health import HealthClass, HealthItem
from .signing_log import SigningRow

if TYPE_CHECKING:  # at run time publishing is imported late: it reaches curate.context, which imports watch
    from ..publishing.ledger import Transition

_CURATOR = "curator"
#: Proposals in a lane at this multiple of the lane's normal (or more) → ACTION.
RATE_WARNING_FACTOR = 5.0
#: A lane with no history counts as this normal, so a quiet lane's first burst still warns.
MIN_LANE_NORMAL = 1.0


@dataclass(frozen=True)
class GraphAsset:
    """One asset newly seen in the verified graph. ``ual`` — its UAL;
    ``envelope_digests`` — ``signing.content_id`` of every signed envelope it
    carries (empty: none); ``seen_at`` — Unix time it was first seen."""

    ual: str
    envelope_digests: tuple[str, ...]
    seen_at: float


class AssetExpectation(Protocol):
    """A node's record of the assets it expects (the Strategy interface)."""

    def split(self, assets: Sequence[GraphAsset]) -> tuple[list[GraphAsset], list[GraphAsset]]:
        """``(unexplained, could_not_tell)`` — explained assets are in neither."""
        ...


class LedgerExpectation:
    """Expected = the publish ledger's lines (``PublishLedger().transitions()``, the publisher node)."""

    def __init__(self, transitions: Iterable[Transition]) -> None:
        from ..publishing.ledger import PublishState  # late: see the TYPE_CHECKING import

        # A batch whose money may have left without the ledger knowing its UAL yet.
        unsettled = (PublishState.SUBMITTED, PublishState.MINTED)
        current: dict[str, Transition] = {}
        submitted_at: dict[str, float] = {}
        for step in transitions:
            current[step.record.batch_id] = step
            if step.record.state is PublishState.SUBMITTED:
                submitted_at[step.record.batch_id] = step.record.at   # the latest attempt is the one in flight
        self._known_uals = {step.record.ual for step in current.values() if step.record.ual}
        self._in_flight_since = sorted(submitted_at[batch_id] for batch_id, step in current.items()
                                       if step.record.state in unsettled and not step.record.ual)

    def split(self, assets: Sequence[GraphAsset]) -> tuple[list[GraphAsset], list[GraphAsset]]:
        unknown = sorted((asset for asset in assets if asset.ual not in self._known_uals),
                         key=lambda asset: asset.seen_at)
        could_not_tell: list[GraphAsset] = []
        for submitted_at in self._in_flight_since:  # each in-flight batch accounts for at most one asset
            claim = next((asset for asset in unknown if asset.seen_at >= submitted_at), None)
            if claim is not None:
                unknown.remove(claim)
                could_not_tell.append(claim)
        return unknown, could_not_tell


class CosignExpectation:
    """Expected = envelopes this node's *key* signed or co-signed (the second curator node)."""

    def __init__(self, signing_rows: Iterable[SigningRow], key: str) -> None:
        key = key.lower()
        self._signed = {row.digest for row in signing_rows if row.key.lower() == key}

    def split(self, assets: Sequence[GraphAsset]) -> tuple[list[GraphAsset], list[GraphAsset]]:
        unexplained = [asset for asset in assets
                       if not asset.envelope_digests or not set(asset.envelope_digests) <= self._signed]
        return unexplained, []


def unexpected_assets(new_assets: Sequence[GraphAsset], expected: AssetExpectation) -> list[HealthItem]:
    """SECURITY when any new asset is unexplained; INFO for assets that could not be told yet."""
    unexplained, could_not_tell = expected.split(new_assets)
    items: list[HealthItem] = []
    if unexplained:
        first = _utc(min(asset.seen_at for asset in unexplained))
        items.append(HealthItem(
            _CURATOR, HealthClass.SECURITY,
            f"{len(unexplained)} verified-graph asset(s) that no record on this node explains, the first seen "
            f"{first} — the publishing wallet was used by someone else",
            "stop publishing from this wallet and move the verified graph to a new wallet",
        ))
    if could_not_tell:
        items.append(HealthItem(
            _CURATOR, HealthClass.INFO,
            f"{len(could_not_tell)} verified-graph asset(s) wait for an in-flight batch to record its UAL",
            "nothing — they are checked again on the next beat",
        ))
    return items


def proposal_rate(proposals_per_lane: Mapping[str, int], normal_per_lane: Mapping[str, float]) -> list[HealthItem]:
    """One ACTION item per lane whose proposal count is at least
    :data:`RATE_WARNING_FACTOR` times its normal (both over the same window)."""
    items: list[HealthItem] = []
    for lane, count in sorted(proposals_per_lane.items()):
        normal = float(normal_per_lane.get(lane, 0.0))
        if not math.isfinite(normal) or normal < MIN_LANE_NORMAL:  # max(nan, 1.0) is nan: it would never warn
            normal = MIN_LANE_NORMAL
        if count >= RATE_WARNING_FACTOR * normal:
            items.append(HealthItem(
                _CURATOR, HealthClass.ACTION,
                f"lane {lane}: {count} proposal(s), {count / normal:.1f}× its normal of {normal:g}",
                "check the proposing curator's recent proposals before co-signing more in this lane",
            ))
    return items


@dataclass(frozen=True)
class DeadManBeat:
    """The watcher's daily proof of life. ``day`` — UTC ``YYYY-MM-DD``;
    ``alarms`` — today's items that were not INFO (0 = all quiet)."""

    day: str
    alarms: int

    @property
    def quiet(self) -> bool:
        return self.alarms == 0

    def as_health_item(self) -> HealthItem:
        status = "all quiet" if self.quiet else f"{self.alarms} alarm(s) raised"
        return HealthItem(_CURATOR, HealthClass.INFO, f"watcher beat {self.day}: {status}",
                          "nothing — a day without this beat is the alarm")


def dead_man_beat(now: float, last_beat_day: str, todays_items: Sequence[HealthItem]) -> Optional[DeadManBeat]:
    """Today's beat, or None when *last_beat_day* is already today (UTC)."""
    today = time.strftime("%Y-%m-%d", time.gmtime(now))
    if last_beat_day == today:
        return None
    return DeadManBeat(today, sum(1 for item in todays_items if item.klass is not HealthClass.INFO))


def _utc(timestamp: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))
