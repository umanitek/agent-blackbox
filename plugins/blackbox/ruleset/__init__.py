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
* :func:`build_from_rows`, :func:`verified_identifiers`, :func:`fetch_tier` —
  compile / proof / paging entry points used by the dashboard and tests.
* ``RulesetRefresh*`` — refresh outcomes callers branch on.

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
from .fetching import fetch_tier
from .partitions import DownloadTotals, verified_download_totals
from .partitions import progress as verified_progress
from .pulse_beat import pulse
from .refresh_cycle import get, peek, refresh

from .direct import DetectionRead, read_for_action, validate_config
from .direct.client import GraphReadUnavailable
from .direct.view import ready_sample, page as graph_page, lookup as graph_lookup

__all__ = [
    "DetectionRead", "read_for_action", "validate_config", "GraphReadUnavailable",
    "ready_sample", "graph_page", "graph_lookup",
    "DownloadTotals",
    "Ruleset",
    "RulesetRefreshIncomplete",
    "RulesetRefreshLockUnavailable",
    "RulesetRefreshUnavailable",
    "build_from_rows",
    "fetch_tier",
    "get",
    "peek",
    "pulse",
    "refresh",
    "verified_download_totals",
    "verified_identifiers",
    "verified_progress",
]
