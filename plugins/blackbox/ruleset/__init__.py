"""Ruleset — the locally compiled threat ruleset detection matches against.

SYNC compiles what the local DKG node holds (the verified graph, plus the
community tier merged in flag-only) into O(1) lookup dicts, caches it on disk,
and serves it to the hot path. Callers use this surface only:

* :class:`Ruleset` — the compiled lookups (``.dependency``, ``.ioc``, …).
* :func:`get` — the current ruleset (cached; refreshes in the background).
* :func:`peek` — the cached ruleset without ever fetching.
* :func:`refresh` — fetch + compile now (``blackbox sync``, the dashboard loop).
* :func:`verified_progress` — how much of the verified graph the last refresh
  compiled (assets compiled of assets confirmed), for status and health.
* :func:`verified_download_totals` — assets + triples the node has downloaded
  and confirmed (one aggregate query), for the dashboard's sync meter.
* :class:`GrowthWatch` + :func:`request_refresh_now` — refresh within ~30 s of new
  verified assets reaching the node instead of at the next hourly sync.
* :func:`fetch_local_records` — this node's private audit records (the Local tier).
* :func:`build_from_rows`, :func:`verified_identifiers`, :func:`fetch_tier` —
  compile / proof / paging entry points used by the dashboard and tests.
* ``RulesetRefresh*`` — refresh outcomes callers branch on.
* :mod:`.live` — the live verified lookups (DKG-lookup): ``rs.live_lookup()``
  asks the node's local store at check time instead of a compiled dict.

Internals: :mod:`.graph_queries` (SPARQL) → :mod:`.fetching` (paging) →
:mod:`.row_adapters` + :mod:`.compiler` (rows → rules) → :mod:`.disk_cache` /
:mod:`.locks` → :mod:`.refresh_cycle` (the cycle + in-memory generation).

Usage::

    from .. import ruleset
    rs = ruleset.get(cfg)
"""

from __future__ import annotations

from .compiler import Ruleset, build_from_rows, verified_identifiers
from .errors import RulesetRefreshIncomplete, RulesetRefreshLockUnavailable, RulesetRefreshUnavailable
from .fetching import fetch_local_records, fetch_tier
from . import live
from .partitions import DownloadTotals, GrowthWatch, verified_download_totals
from .partitions import progress as verified_progress
from .pulse_beat import pulse, request_refresh_now
from .refresh_cycle import get, peek, refresh

from .direct import DetectionRead, read_for_action, validate_config
from .direct.client import GraphReadUnavailable, LocalGraphClient
from .direct.view import ready_sample, page as graph_page, lookup as graph_lookup

from .direct.semantic import semantic_candidates, INDEX_SPEC as semantic_index_spec
from .direct.client import local_url as local_graph_url

__all__ = [
    "DetectionRead",
    "DownloadTotals",
    "GraphReadUnavailable",
    "GrowthWatch",
    "LocalGraphClient",
    "Ruleset",
    "RulesetRefreshIncomplete",
    "RulesetRefreshLockUnavailable",
    "RulesetRefreshUnavailable",
    "build_from_rows",
    "fetch_local_records",
    "fetch_tier",
    "get",
    "graph_lookup",
    "graph_page",
    "live",
    "local_graph_url",
    "peek",
    "pulse",
    "read_for_action",
    "ready_sample",
    "refresh",
    "request_refresh_now",
    "semantic_candidates",
    "semantic_index_spec",
    "validate_config",
    "verified_download_totals",
    "verified_identifiers",
    "verified_progress",
]
