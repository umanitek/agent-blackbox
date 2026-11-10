"""The pipeline's running numbers — one typed record for the console and the Slack monitor (trust-and-threat-lab C4, §03.4, F-035).

Pattern: Facade. :func:`collect_metrics` reads the stores that already hold
the answers — the PublishLedger (failures, 207s, last good batch, the month's
spend, the batch cost behind the wallet floor), the LabJobStore, the curate
queue (the delta view, ages from each rule's ``firstSeen``), the co-sign
DeliveryLedger's alarms, the SigningLog (this node's own heartbeat) and the
context's key list and curator view — and keeps no state of its own.

:class:`PipelineMetrics` is the ONE definition of the metric names: the
console's ``GET /api/metrics`` answers :meth:`PipelineMetrics.as_dict` and
the watch verb (W3, ``curate.intake``) posts :meth:`PipelineMetrics.as_payload`
— ``{"kind": "metrics", "metrics": {name: value}}``, the body its sinks send —
or :meth:`PipelineMetrics.lines` to a chat sink. :data:`METRIC_NAMES` lists
the names. W3's sinks call exactly ``as_payload()`` and ``lines()``; a rename
here breaks the Slack monitor.

Every metric is a value or :data:`UNAVAILABLE`. A store that is not wired,
cannot be read or raises makes ITS metrics "unavailable" and nothing else —
never a zero (could-not-tell is not "none", LES-011) and never a crash.
"never" is a real answer from a readable store (no batch bound yet, no
heartbeat seen).

Usage::

    metrics = collect_metrics(MetricsSources(), context=lambda: build_context(None, authority="verified"),
                              now=time.time())
    metrics.as_dict()["publish_207s"]          # 0, 3, … or "unavailable"
    sink_body = metrics.as_payload()           # {"kind": "metrics", "metrics": {"queue_depth_by_lane": {...}, ...}}
"""

from __future__ import annotations

import logging
import time
from collections import Counter
from dataclasses import dataclass, fields
from decimal import Decimal
from typing import Callable, Mapping, Optional, Sequence, TypeVar

from ...kernel.health import key_fingerprint, utc_day, utc_day_or
from ...kernel.signing import CuratorStatement
from .. import queue
from ..context import CurateContext, verified_identifiers
from ..lab.jobs import LabJobState, LabJobStore
from ..publishing.ledger import PublishLedger
from ..sources import LookupItem, queue_metrics
from ..proposals import DeliveryLedger
from ..watch import SigningLog
from .roster import renewal_status
from ...kernel.health import days_between

logger = logging.getLogger(__name__)

UNAVAILABLE = "unavailable"
NEVER = "never"
#: The publishing wallet keeps at least this many batches' worth of TRAC and gas.
FLOOR_BATCHES = 2
#: Reader update uptake is the share of installs on the newest release this long after it ships.
UPTAKE_AFTER_SECONDS = 7 * 86_400
_WAITING_LAB_STATES = (LabJobState.QUEUED, LabJobState.RUNNING)

#: A reading of an age that may be "never" (a readable store that has no such event yet).
Age = int | str
_T = TypeVar("_T")


@dataclass(frozen=True)
class WalletBalance:
    """The publishing wallet as the chain reports it: ``trac`` and ``gas`` (the
    chain's native token); ``gas_per_batch`` — what one batch burns in gas, when
    known (the publish ledger records TRAC only, so the gas floor needs it)."""

    trac: Decimal
    gas: Decimal
    gas_per_batch: Optional[Decimal] = None


@dataclass(frozen=True)
class UpdateUptake:
    """The dashboard's version-health counts for the newest reader release:
    ``release`` shipped at ``shipped_at`` (Unix s); ``installs_on_release`` of
    ``installs_total`` installs run it now."""

    release: str
    shipped_at: float
    installs_on_release: int
    installs_total: int


@dataclass(frozen=True)
class MetricsSources:
    """Where each metric is read — every reader injectable; None = not wired
    (its metrics are "unavailable"). The defaults open the stores in the curate
    home. ``queue`` turns the context and today's UTC day into the open queue items; ``wallet`` and
    ``uptake`` have no store yet on a node (no chain-balance reader, no
    version-health item), so they stay unwired until one exists."""

    publish_ledger: Optional[Callable[[], PublishLedger]] = PublishLedger
    lab_jobs: Optional[Callable[[], LabJobStore]] = LabJobStore
    delivery: Optional[Callable[[], DeliveryLedger]] = DeliveryLedger
    signing_log: Optional[Callable[[], SigningLog]] = SigningLog
    queue: Optional[Callable[[CurateContext, str], Sequence[LookupItem]]] = None   # None → open_queue_items
    wallet: Optional[Callable[[], WalletBalance]] = None
    uptake: Optional[Callable[[], UpdateUptake]] = None


@dataclass(frozen=True)
class PipelineMetrics:
    """The F-035 metrics; every field None = "unavailable". Field names ARE the
    metric names (console JSON and webhook payload alike). Money is Decimal
    text; ages are whole seconds or days as named."""

    queue_depth_by_lane: Optional[Mapping[str, int]] = None
    queue_oldest_age_days: Optional[int] = None
    proposals_awaiting_cosign: Optional[tuple[Mapping[str, object], ...]] = None   # > 3 beats undelivered
    publish_failures: Optional[int] = None
    publish_207s: Optional[int] = None
    seconds_since_last_batch: Optional[Age] = None
    month_spend_trac: Optional[str] = None
    month_spend_bytes: Optional[int] = None
    wallet_trac: Optional[str] = None
    wallet_gas: Optional[str] = None
    wallet_trac_floor: Optional[str] = None
    wallet_gas_floor: Optional[str] = None
    wallet_below_floor: Optional[bool] = None
    curator_heartbeat_age_days: Optional[Mapping[str, Age]] = None   # key fingerprint → days
    seconds_since_own_heartbeat: Optional[Age] = None
    manifest_days_to_expiry: Optional[int] = None
    lab_queue_depth: Optional[int] = None
    lab_oldest_job_age_seconds: Optional[int] = None
    reader_newest_release: Optional[str] = None
    reader_update_uptake: Optional[float] = None   # share 0..1, seven days after the release shipped

    def as_dict(self) -> dict[str, object]:
        """``{metric name: value or "unavailable"}``, in :data:`METRIC_NAMES` order."""
        return {name: UNAVAILABLE if getattr(self, name) is None else _plain(getattr(self, name))
                for name in METRIC_NAMES}

    def as_payload(self) -> dict[str, object]:
        """The JSON body a webhook receives (W3's ``WebhookSink.notify_metrics``):
        ``{"kind": "metrics", "metrics": {name: value}}``."""
        return {"kind": "metrics", "metrics": self.as_dict()}

    def lines(self) -> list[str]:
        """One ``name: value`` line per metric, for chat sinks (Slack, Telegram)."""
        return [f"{name}: {value}" for name, value in self.as_dict().items()]


METRIC_NAMES: tuple[str, ...] = tuple(f.name for f in fields(PipelineMetrics))


def collect_metrics(sources: MetricsSources, context: Optional[Callable[[], CurateContext]],
                    now: float) -> PipelineMetrics:
    """Read every metric once. *context* — a fresh CurateContext (the key list,
    curator view and compiled queue); None or a failing one leaves those metrics
    unavailable."""
    ctx = _read("context", context)
    ledger = _read("publish ledger", sources.publish_ledger)
    today = utc_day(now)
    values: dict[str, object] = {}
    if ledger is not None:
        _merge(values, "publish ledger", lambda: _publish_values(ledger, now))
    if sources.wallet:
        _merge(values, "wallet", lambda: _wallet_values(sources.wallet(), _largest_batch_trac(ledger)))
    if ctx is not None:
        _merge(values, "queue", lambda: _queue_values(sources.queue or open_queue_items, ctx, today))
        _merge(values, "key list", lambda: _key_list_values(ctx, today))
    if sources.lab_jobs:
        _merge(values, "lab jobs", lambda: _lab_values(sources.lab_jobs(), now))
    if sources.uptake:
        _merge(values, "uptake", lambda: _uptake_values(sources.uptake(), now))
    if sources.delivery:
        values["proposals_awaiting_cosign"] = _read("delivery ledger", lambda: tuple(
            {"proposalId": item.proposal_id, "beats": item.beats} for item in sources.delivery().alarms(now)))
    if sources.signing_log:
        values["seconds_since_own_heartbeat"] = _read("signing log", lambda: _own_heartbeat(sources.signing_log(), now))
    return PipelineMetrics(**values)


def open_queue_items(ctx: CurateContext, today: str) -> Sequence[LookupItem]:
    """The queue's admitted items as the look-up step sees them, aged from each
    community rule's ``firstSeen`` (a rule without one counts as new *today*, as
    the community tier treats it). Raises when the context has no compiled ruleset."""
    compiled = ctx.compiled
    if compiled is None:
        raise LookupError("no compiled ruleset: the queue is not known")
    rules = compiled.community
    view = queue.delta_view(rules, verified_identifiers(compiled, rules))
    return [LookupItem(item.identifier, item.lane, first_seen=utc_day_or(rules[item.identifier].get("firstSeen"), today))
            for item in view.new]


# -- one reader each ---------------------------------------------------------------------------


def _publish_values(ledger: PublishLedger, now: float) -> dict[str, object]:
    published = ledger.metrics(now)
    month = published.monthly.get(time.strftime("%Y-%m", time.gmtime(now)))
    return {
        "publish_failures": published.failures, "publish_207s": published.minted_207s,
        "seconds_since_last_batch": NEVER if published.seconds_since_last_success is None
        else int(published.seconds_since_last_success),
        "month_spend_trac": str(month.trac if month else Decimal(0)),
        "month_spend_bytes": month.bytes if month else 0,
    }


def _largest_batch_trac(ledger: Optional[PublishLedger]) -> Optional[Decimal]:
    """The dearest batch so far, which sizes the TRAC floor; None when no ledger, no
    priced batch, or the ledger cannot be read (the balance itself still renders)."""
    if ledger is None:
        return None
    costs = _read("publish ledger", lambda: [r.cost_trac for r in ledger.batches() if r.cost_trac is not None])
    return max(costs, default=None) if costs else None


def _wallet_values(balance: WalletBalance, largest_batch_trac: Optional[Decimal]) -> dict[str, object]:
    """Balances against the two-batch floor; a floor with no batch cost to size it is unavailable."""
    trac_floor = None if largest_batch_trac is None else FLOOR_BATCHES * largest_batch_trac
    gas_floor = None if balance.gas_per_batch is None else FLOOR_BATCHES * balance.gas_per_batch
    below = [balance.trac < trac_floor] if trac_floor is not None else []
    below += [balance.gas < gas_floor] if gas_floor is not None else []
    return {"wallet_trac": str(balance.trac), "wallet_gas": str(balance.gas),
            "wallet_trac_floor": None if trac_floor is None else str(trac_floor),
            "wallet_gas_floor": None if gas_floor is None else str(gas_floor),
            "wallet_below_floor": any(below) if below else None}


def _queue_values(items_of: Callable[[CurateContext, str], Sequence[LookupItem]], ctx: CurateContext,
                  today: str) -> dict[str, object]:
    items = items_of(ctx, today)
    depth = Counter(item.lane for item in items)
    return {"queue_depth_by_lane": {lane.name.lower(): depth[lane] for lane in queue.Lane},
            "queue_oldest_age_days": queue_metrics(items, today).oldest_age_days}


def _key_list_values(ctx: CurateContext, today: str) -> dict[str, object]:
    """Days since each listed curator's newest heartbeat, and the list's days to expiry."""
    manifest = ctx.manifest
    if manifest is None:
        raise LookupError("no effective key list")
    beats = ctx.own_view.heartbeats
    ages = {key_fingerprint(key): max(0, days_between(beats[key], today)) if beats.get(key) else NEVER
            for key in manifest.curator_keys}
    renewal = renewal_status(manifest, today)
    return {"curator_heartbeat_age_days": ages,
            "manifest_days_to_expiry": None if renewal.stage == "undated" else renewal.days_left}


def _lab_values(store: LabJobStore, now: float) -> dict[str, object]:
    waiting = [record for record in store.records() if record.state in _WAITING_LAB_STATES]
    oldest = min((record.job.requested_at for record in waiting), default=now)
    return {"lab_queue_depth": len(waiting), "lab_oldest_job_age_seconds": int(max(0.0, now - oldest))}


def _own_heartbeat(log: SigningLog, now: float) -> Age:
    beats = [row.at for row in log.rows() if row.kind == CuratorStatement.HEARTBEAT.value]
    return int(max(0.0, now - max(beats))) if beats else NEVER


def _uptake_values(uptake: UpdateUptake, now: float) -> dict[str, object]:
    """The share counts only once the release is seven days old and some install reported."""
    measured = now - uptake.shipped_at >= UPTAKE_AFTER_SECONDS and uptake.installs_total > 0
    return {"reader_newest_release": uptake.release,
            "reader_update_uptake": round(uptake.installs_on_release / uptake.installs_total, 4) if measured else None}


# -- helpers -----------------------------------------------------------------------------------


def _read(what: str, reader: Optional[Callable[[], _T]]) -> Optional[_T]:
    """*reader*'s answer, or None (= unavailable) when it is not wired or fails.
    Logged by type only: a store's error text can carry paths or identifiers."""
    if reader is None:
        return None
    try:
        return reader()
    except Exception as exc:   # one broken store must never take the other metrics (or the console) down
        logger.warning("blackbox console: %s metrics unavailable (%s)", what, type(exc).__name__)
        return None


def _merge(values: dict[str, object], what: str, reader: Callable[[], dict[str, object]]) -> None:
    """Add *reader*'s metrics to *values*; when it fails they stay unavailable."""
    values.update(_read(what, reader) or {})





def _plain(value: object) -> object:
    """JSON-ready: Decimal → text, tuples → lists, mappings → dicts."""
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, Mapping):
        return {str(key): _plain(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_plain(item) for item in value]
    return value


__all__ = ["METRIC_NAMES", "NEVER", "UNAVAILABLE", "MetricsSources", "PipelineMetrics", "UpdateUptake",
           "WalletBalance", "collect_metrics", "open_queue_items"]
