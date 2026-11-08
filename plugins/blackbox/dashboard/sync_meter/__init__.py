"""The dashboard's verified-sync meter — how much of Umanitek's verified threat
graph this node holds, measured against the graph's real size.

Three numbers, each from the place that actually knows it:

* **graph size** — assets the node has downloaded + the backlog its own
  reconcile pass reports (``pending=N`` in daemon.log, via
  :func:`..sync.read_recovery_backlog`). No DKG API states the on-chain total,
  and the node's _meta lists only assets it already holds, so this sum is the
  only honest total. It is re-read on every poll: when Umanitek publishes new
  assets the total grows and the meter dips until the node catches up —
  "synced" means caught up with the graph as it is NOW, not a final state.
  The two parts must come from the SAME instant: ``pending`` is the last
  pass's (logged up to a minute ago), so adding the LIVE download count to it
  counts every asset fetched since that pass twice — on a fast first sync the
  size climbed 565 → 573 → 575 and fell back at each pass (KI-403).
  :class:`GraphSizeAnchor` therefore pins the download count seen when each
  new pass first appears, and the size is that count + the pass's
  ``pending`` until the next pass; once caught up it is exact (checked on
  mainnet 2026-10-08: 153 downloaded + 411 pending = 564).
* **downloaded** — assets + triples confirmed in the node's _meta, one
  aggregate query (:func:`..ruleset.verified_download_totals`).
* **compiled** — assets the last refresh turned into rules
  (:func:`..ruleset.verified_progress`), plus the live verified rule count.

A number nobody could read is reported as unknown, never as zero (LES-011):
the meter shows a percentage only when the graph size is known.

Registered by :func:`.server.create_app` through
:func:`register_sync_meter_routes` → ``GET /api/verified-sync``.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import asdict, dataclass, field, replace
from typing import Any, Callable, Dict, Optional

from ... import ruleset
from ...kernel.dkg_client import DkgClient
from ...sync import read_recovery_backlog
from .progress import STALL_SECONDS, WATCH, SyncProgress, SyncProgressWatch, sync_phase

logger = logging.getLogger(__name__)

#: Seconds one meter reading is reused — the page polls every few seconds and
#: the node only moves every minute or two, so the node is asked at most this often.
CACHE_SECONDS = 10.0
#: The _meta aggregate is small; a node that cannot answer in this long is busy,
#: and the meter says "could not tell" rather than wait.
QUERY_TIMEOUT_SECONDS = 5.0


@dataclass(frozen=True)
class SyncMeter:
    """One reading of the verified-sync meter, as served to the dashboard.

    ``state`` is one of:

    * ``synced`` — nothing left to download and every downloaded asset compiled;
    * ``syncing`` — the node is still downloading, or rules lag the download;
    * ``unknown`` — the node answered but its backlog is unknown, so there is
      no total to take a percentage of (counts are still shown);
    * ``unavailable`` — the node could not be read at all.

    ``graph_assets`` / ``percent_*`` are None whenever the total is unknown.
    ``checked_at`` is the node's own timestamp of the backlog it reported.
    """

    state: str
    graph_assets: Optional[int]
    downloaded_assets: Optional[int]
    downloaded_triples: Optional[int]
    compiled_assets: Optional[int]
    verified_rules: int
    percent_downloaded: Optional[float]
    percent_compiled: Optional[float]
    checked_at: str
    #: DKG-lookup: where verified answers come from right now — ``state`` ∈ live |
    #: fallback | paused | not-live, ``label`` the few words the panel shows next to its
    #: mark, ``text`` the full sentence (the hover) — see :func:`lookup_status`.
    lookups: dict[str, str] = field(default_factory=dict)
    #: The step the sync is on, for the "sit tight" line (:func:`.progress.sync_phase`): finding |
    #: queued | downloading | compiling | synced | stalled | "" (nothing to say), and its sentence.
    phase: str = ""
    phase_text: str = ""
    #: Epoch seconds: when the sync was first seen running, and when its counts last moved
    #: (:class:`.progress.SyncProgressWatch`); None when not syncing.
    running_since: Optional[float] = None
    last_progress: Optional[float] = None


def _percent(part: int, whole: int) -> float:
    """``part`` of ``whole`` as a percentage, one decimal, never above 100."""
    return round(min(100.0, 100.0 * part / whole), 1) if whole > 0 else 0.0


class GraphSizeAnchor:
    """Remembers how many assets the node held when its newest reconcile pass
    first appeared, so the graph size is read from ONE instant (KI-403).

    Holds the pass stamp (``RecoveryBacklog.logged_at``) and the download
    count seen at the first reading after that pass. One instance lives for
    the dashboard process (:func:`register_sync_meter_routes`); one lock
    guards it. Pattern: a small Memento of the last pass.

    Usage::

        anchor = GraphSizeAnchor()
        at_pass = anchor.downloaded_at_pass("2026-10-14 20:21:00", 253)   # 253
        anchor.downloaded_at_pass("2026-10-14 20:21:00", 261)             # still 253
        anchor.downloaded_at_pass("2026-10-14 20:22:00", 261)             # 261: a new pass
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._pass_stamp = ""
        self._downloaded = 0

    def downloaded_at_pass(self, pass_stamp: str, downloaded_now: int) -> int:
        """The download count to pair with the pass logged at *pass_stamp*.

        A new stamp re-anchors on *downloaded_now*. So does a count that fell
        below the anchor (the node rolled assets back or re-read them): the
        old anchor would then claim assets the node no longer holds.
        """
        with self._lock:
            if pass_stamp != self._pass_stamp or downloaded_now < self._downloaded:
                self._pass_stamp, self._downloaded = pass_stamp, downloaded_now
            return self._downloaded


def build_sync_meter(*, downloaded: Optional[ruleset.DownloadTotals], pending: Optional[int],
                     compiled_assets: Optional[int], verified_rules: int, checked_at: str = "",
                     downloaded_at_pass: Optional[int] = None) -> SyncMeter:
    """Combine the three readings into one :class:`SyncMeter` (pure — no I/O).

    *downloaded* None = the node could not be read; *pending* None = its
    backlog is unknown; *compiled_assets* None = nothing compiled yet;
    *downloaded_at_pass* = the node's download count when the *pending* pass
    was logged (from :class:`GraphSizeAnchor`), None = take the live count.
    The size is that count + *pending*, and never less than what the node
    already holds (assets published and fetched before the next pass).
    """
    if downloaded is None:
        return SyncMeter(state="unavailable", graph_assets=None, downloaded_assets=None, downloaded_triples=None,
                         compiled_assets=compiled_assets, verified_rules=verified_rules,
                         percent_downloaded=None, percent_compiled=None, checked_at=checked_at)
    # The compile record can trail a download that was rolled back or re-read;
    # rules never cover more assets than the node holds.
    compiled = min(compiled_assets, downloaded.assets) if compiled_assets is not None else None
    if pending is None:
        return SyncMeter(state="unknown", graph_assets=None, downloaded_assets=downloaded.assets,
                         downloaded_triples=downloaded.triples, compiled_assets=compiled, verified_rules=verified_rules,
                         percent_downloaded=None, percent_compiled=None, checked_at=checked_at)
    at_pass = downloaded.assets if downloaded_at_pass is None else downloaded_at_pass
    graph_assets = max(downloaded.assets, at_pass + pending)
    done = pending == 0 and compiled is not None and compiled >= downloaded.assets
    return SyncMeter(
        state="synced" if done else "syncing",
        graph_assets=graph_assets,
        downloaded_assets=downloaded.assets,
        downloaded_triples=downloaded.triples,
        compiled_assets=compiled,
        verified_rules=verified_rules,
        percent_downloaded=_percent(downloaded.assets, graph_assets),
        percent_compiled=_percent(compiled or 0, graph_assets),
        checked_at=checked_at,
    )


def lookup_status(scope: Any, health: Any, now: Optional[float] = None) -> dict[str, str]:
    """Where a verified check's answer comes from, for the panel and the status line (pure).

    *scope* — the generation's VerifiedScope (or None); *health* — ``live.HEALTH.read()``.
    live: the store answers. fallback: the store is down and the opt-in local index answers
    (hits only until it covers every asset). paused: the store is down and nothing answers —
    actions pass unchecked by the verified graph. not-live: no scope yet (compiled rules only).
    """
    if scope is None or not getattr(scope, "ready", False):
        return {"state": "not-live", "label": "Not live yet",
                "text": "Verified lookups are not live yet: the node has not reported its store."}
    if not getattr(health, "degraded", False):
        return {"state": "live", "label": "Live from graph",
                "text": "Verified checks are answered live from the graph on this node."}
    since = time.strftime("%H:%M UTC", time.gmtime(float(getattr(health, "since", 0) or 0)))
    reason = getattr(health, "reason", "") or "the store did not answer"
    if getattr(scope, "fallback", "off") == "index":
        return {"state": "fallback", "label": "Local index · graph down",
                "text": f"Graph store down since {since} ({reason}); verified checks are answered "
                        "from the local index until it is back."}
    return {"state": "paused", "label": "Checks paused · graph down",
            "text": f"Graph store down since {since} ({reason}); verified checks are PAUSED — "
                    "actions pass unchecked by the verified graph until it answers again."}


def verified_graph_still_arriving(cfg: Any) -> bool:
    """True while Umanitek's graph is still arriving on this node: its newest
    reconcile pass reported assets left to download, or the rules cover fewer
    assets than the node holds. The dashboard then says "syncing", never
    "VM synced" over a partial graph (PR #21 audit).

    Local reads only (the node's log tail and the compile record), so it is
    cheap on every status poll. No evidence either way reads as False, the
    label's previous behaviour.
    """
    backlog = read_recovery_backlog(cfg.dkg_home, cfg.context_graph_id)
    done = ruleset.verified_progress(cfg.context_graph_id) or {}
    compiled, total = done.get("assets_compiled"), done.get("assets_total")
    if backlog is not None and backlog.to_fetch(compiled if isinstance(compiled, int) else 0) > 0:
        return True
    return isinstance(compiled, int) and isinstance(total, int) and compiled < total


def read_sync_meter(cfg: Any, *, node_reachable: bool, verified_rules: int,
                    anchor: Optional[GraphSizeAnchor] = None) -> SyncMeter:
    """Take one live reading for *cfg*'s verified graph (``cfg.context_graph_id``).

    Pass the process's *anchor* so the graph size holds steady between the
    node's reconcile passes; without one the size uses the live count (a
    one-off reading).
    """
    graph_id = cfg.context_graph_id
    downloaded = None
    if node_reachable:
        client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home, config=cfg)
        downloaded = ruleset.verified_download_totals(client, graph_id, timeout=QUERY_TIMEOUT_SECONDS)
    backlog = read_recovery_backlog(cfg.dkg_home, graph_id)
    compiled = (ruleset.verified_progress(graph_id) or {}).get("assets_compiled")
    at_pass = None
    pending = backlog.pending if backlog else None
    if backlog is not None and backlog.head is not None and downloaded is not None:
        # The node states the graph's size: what is missing is head - held (a restart's re-check is not).
        pending = backlog.to_fetch(downloaded.assets)
    elif anchor is not None and backlog is not None and downloaded is not None:
        # Keyed by graph too: a config switch to another graph must not reuse this one's count.
        at_pass = anchor.downloaded_at_pass(f"{graph_id}@{backlog.logged_at}", downloaded.assets)
    meter = build_sync_meter(
        downloaded=downloaded,
        pending=pending,
        compiled_assets=compiled if isinstance(compiled, int) else None,
        verified_rules=verified_rules,
        checked_at=backlog.logged_at if backlog else "",
        downloaded_at_pass=at_pass,
    )
    if node_reachable:
        meter.lookups.update(lookup_status(getattr(ruleset.peek(cfg), "verified_scope", None), ruleset.live.HEALTH.read()))
    else:   # the last lookup's ✓ says nothing about a node that is not answering now (LES-011)
        meter.lookups.update({"state": "unknown", "label": "Node not answering",
                              "text": "The local DKG node is not answering, so it is unknown whether verified checks "
                                      "can be answered; the line updates when the node is back."})
    return meter


def register_sync_meter_routes(app: Any, *, load_config: Callable[[], Any],
                               node_reachable: Callable[[Any], bool],
                               verified_rules: Callable[[Any], int]) -> Callable[[], dict[str, Any]]:
    """Add ``GET /api/verified-sync`` to *app* (a FastAPI app); returns the handler.

    Each reading also feeds :data:`WATCH` and carries the sync's phase (:func:`sync_phase`).
    *node_reachable* is the server's cached liveness probe (never blocks);
    *verified_rules* maps cfg → the compiled verified-rule count. Readings are
    cached for :data:`CACHE_SECONDS` behind one lock, so concurrent polls
    trigger one node query, not one each.
    """
    lock = threading.Lock()
    cached: dict[str, Any] = {"at": -1e9, "body": None}
    anchor = GraphSizeAnchor()

    @app.get("/api/verified-sync")
    def verified_sync() -> dict[str, Any]:
        with lock:
            if cached["body"] is None or time.monotonic() - cached["at"] >= CACHE_SECONDS:
                cfg = load_config()
                meter = read_sync_meter(cfg, node_reachable=node_reachable(cfg), verified_rules=verified_rules(cfg),
                                        anchor=anchor)
                progress = WATCH.observe(meter)
                phase, phase_text = sync_phase(meter, progress.stalled)
                meter = replace(meter, phase=phase, phase_text=phase_text, running_since=progress.running_since,
                                last_progress=progress.last_progress)
                cached["body"], cached["at"] = asdict(meter), time.monotonic()
            return dict(cached["body"])

    _READER.handler = verified_sync
    return verified_sync


class _ReaderHolder:
    """The dashboard's one registered ``/api/verified-sync`` handler (one dashboard per process)."""

    handler: Optional[Callable[[], dict[str, Any]]] = None


_READER = _ReaderHolder()


def first_sync_state() -> str:
    """:meth:`SyncProgressWatch.first_sync` for the health checks, after one meter reading when this
    process has not read the meter yet — the first health poll of a fresh dashboard comes before the
    page's first meter poll, and an unread watch said "" (no sync running), so a first sync in progress
    showed "UNPROTECTED: run blackbox sync --wait" (KI-475). Reads the meter at most once per process."""
    if not WATCH.observed and _READER.handler is not None:
        try:
            _READER.handler()
        except Exception as exc:   # health: allow BLE001 -- a meter that cannot be read leaves the health check as it was
            logger.debug("blackbox: sync meter unreadable for the health check: %s", exc)
    return WATCH.first_sync()


__all__ = ["STALL_SECONDS", "WATCH", "GraphSizeAnchor", "SyncMeter", "SyncProgress", "SyncProgressWatch",
           "build_sync_meter", "first_sync_state", "lookup_status", "read_sync_meter", "register_sync_meter_routes", "sync_phase",
           "verified_graph_still_arriving"]
