"""Wallet watch — the publishing wallet's TRAC on chain vs what the publish ledger spent.

The chain is the one record a node cannot rewrite, so this runs on both
nodes: over a window, the balance the chain reports may only have dropped by
what the publish ledger says batches cost in that window. More than that (a
transfer out, a mint nobody recorded) → SECURITY.

A batch's cost is set on the move where the chain took the money and carried
on every later line (``BatchRecord.cost_trac``), so the spend at time *t* is
the first line of each batch that carries a cost.

A pure comparison: the caller reads the chain (``ChainRecord``) and passes the
ledger's transitions (``PublishLedger().transitions()``).

Usage::

    items = wallet_drift(ChainRecord(since, until, start, end, top_ups), ledger.transitions())
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from decimal import Decimal
from typing import TYPE_CHECKING, Sequence

from ...kernel.health import HealthClass, HealthItem

if TYPE_CHECKING:  # never at run time: publishing reaches curate.context, which imports watch
    from ..publishing.ledger import Transition

_CURATOR = "curator"
#: A drift at or under this much TRAC is rounding, not a loss.
DRIFT_TOLERANCE_TRAC = Decimal("0.000001")


@dataclass(frozen=True)
class ChainRecord:
    """The wallet's TRAC as the chain reports it over ``[since, until)`` (Unix
    times): ``start_balance`` and ``end_balance``, plus ``top_ups`` — TRAC
    received in the window (from the cold wallet), which explains a rise."""

    since: float
    until: float
    start_balance: Decimal
    end_balance: Decimal
    top_ups: Decimal = Decimal(0)


def ledger_spend(transitions: Sequence[Transition], since: float, until: float) -> Decimal:
    """TRAC the ledger says batches cost with the spend falling in ``[since, until)``."""
    spent_at: dict[str, Transition] = {}
    for step in transitions:
        record = step.record
        if record.cost_trac is not None and record.batch_id not in spent_at:
            spent_at[record.batch_id] = step
    return sum((step.record.cost_trac for step in spent_at.values()
                if since <= step.record.at < until and step.record.cost_trac is not None), Decimal(0))


def wallet_drift(chain_record: ChainRecord, ledger: Sequence[Transition]) -> list[HealthItem]:
    """SECURITY when the balance dropped by more than the ledger's spend in the window."""
    dropped = chain_record.start_balance + chain_record.top_ups - chain_record.end_balance
    unexplained = dropped - ledger_spend(ledger, chain_record.since, chain_record.until)
    if unexplained <= DRIFT_TOLERANCE_TRAC:
        return []
    return [HealthItem(
        _CURATOR, HealthClass.SECURITY,
        f"the publishing wallet lost {unexplained} TRAC between {_utc(chain_record.since)} and "
        f"{_utc(chain_record.until)} that the publish ledger does not explain",
        "stop publishing from this wallet, move what is left to the cold wallet and check its transfers",
    )]


def _utc(timestamp: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp))
