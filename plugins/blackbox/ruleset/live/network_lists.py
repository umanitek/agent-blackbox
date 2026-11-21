"""The verified graph's malicious domains and IP addresses, in full — what Network Shield enforces.

The live lookup answers one indicator at a time (fast enough for a tool call, ~100 ms per
question — far too slow in front of every DNS lookup). Network Shield's enforcer needs the
whole list in memory instead, so this reads every verified ``IocSignal`` of type ``domain`` or
``ip`` in one cursor-paged lane at the node's local store, with **exactly the live lookup's
scope** (:class:`.scope.VerifiedScope`):

* only rows from the scope's ``assertion_graphs`` — the confirmed, owner-pinned Verifiable
  Memory assets (a tentative, foreign or community asset never reaches the list);
* minus the subjects curator corrections suppress (``suppressed_subjects``);
* minus the identifiers the curator revoked (``revoked_identifiers``).

Values are normalised with :func:`~...kernel.threat_ids.normalize_ioc_value`, so the list holds
the same spelling the guard's own matches use. The result is cached per scope (the scope is
rebuilt on every ruleset refresh), so a dashboard asking every minute costs one read per
refresh, never per ask. Fails open: no store, no scope or a failed page answers None (the
caller keeps its last list), never an empty "nothing is malicious" list.

Usage::

    from plugins.blackbox import ruleset
    found = ruleset.network_indicators()          # None until the graph is synced
    found.domains, found.ips                      # frozensets of normalised values
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Optional

from ...kernel import threat_ids
from ...kernel.dkg_client import extract_binding
from ...kernel.store import StoreClient
from .. import fetching, graph_queries
from .scope import VerifiedScope

logger = logging.getLogger(__name__)

#: The indicator types Network Shield enforces at the network layer.
NETWORK_TYPES = ("domain", "ip")
#: The properties the lane reads: the type rides in ``?category``, the value in ``?iocValue``
#: (the column names :data:`~..graph_queries._SELECT_COLUMNS` already has).
_LANE_PROPERTIES = """    OPTIONAL { ?threat dp:iocType ?category . }
    OPTIONAL { ?threat dp:value ?iocValue . }"""


@dataclass(frozen=True)
class NetworkIndicators:
    """Every verified malicious domain and IP address, normalised, with where they came from.

    *assets* is how many confirmed verified assets were in scope; *built_at* is when the list
    was read (unix seconds).
    """

    domains: frozenset[str]
    ips: frozenset[str]
    assets: int
    built_at: float


_cache_lock = threading.Lock()
_cache: dict[str, Any] = {"key": None, "value": None}


def _scope_key(scope: VerifiedScope) -> tuple:
    return (scope.context_graph_id, scope.store_url, scope.assertion_graphs,
            scope.suppressed_subjects, scope.revoked_identifiers)


def network_indicators(scope: Optional[VerifiedScope],
                       store_factory: Optional[Callable[[str], Any]] = None) -> Optional[NetworkIndicators]:
    """The verified domains and IPs for *scope*; None when they cannot be read yet.

    *store_factory* builds the store client for a store URL (tests hand in a fake).
    """
    if scope is None or not scope.context_graph_id or not scope.store_url or not scope.assertion_graphs:
        return None
    key = _scope_key(scope)
    with _cache_lock:
        if _cache["key"] == key:
            return _cache["value"]
    found = _read(scope, store_factory or _store_lanes)
    if found is not None:
        with _cache_lock:
            _cache["key"], _cache["value"] = key, found
    return found


def _store_lanes(store_url: str) -> Any:
    return fetching._StoreLanes(StoreClient(store_url, timeout=fetching.STORE_LANE_TIMEOUT_SECONDS))


def _read(scope: VerifiedScope, store_factory: Callable[[str], Any]) -> Optional[NetworkIndicators]:
    vm_prefix = graph_queries.verifiable_memory_prefix(scope.context_graph_id)
    if not vm_prefix:
        return None
    try:
        rows = fetching._fetch_paged_lanes(
            store_factory(scope.store_url), scope.context_graph_id,
            lambda limit, after: (graph_queries._defender_page_sparql(
                "IocSignal", _LANE_PROPERTIES, limit, after, graph_prefix=vm_prefix),),
            view=None,
        )
    except Exception:   # fail open: an unreadable store keeps the caller's last list
        logger.warning("blackbox: could not read the verified network indicators", exc_info=True)
        return None
    if rows is None:
        return None
    return indicators_from_rows(rows, scope)


def indicators_from_rows(rows: list[dict[str, Any]], scope: VerifiedScope) -> NetworkIndicators:
    """Keeps the in-scope, uncorrected, unrevoked domain and IP rows of *rows*, normalised."""
    domains: set[str] = set()
    ips: set[str] = set()
    for row in rows:
        if extract_binding(row.get("g")) not in scope.assertion_graphs:
            continue
        if extract_binding(row.get("threat")) in scope.suppressed_subjects:
            continue
        ioc_type = extract_binding(row.get("category")).strip().lower()
        if ioc_type not in NETWORK_TYPES:
            continue
        value = threat_ids.normalize_ioc_value(ioc_type, extract_binding(row.get("iocValue")))
        if not value or threat_ids.ioc_identifier(ioc_type, value) in scope.revoked_identifiers:
            continue
        (domains if ioc_type == "domain" else ips).add(value)
    return NetworkIndicators(domains=frozenset(domains), ips=frozenset(ips),
                             assets=len(scope.assertion_graphs), built_at=time.time())


def forget() -> None:
    """Drops the cached list (tests, and a context-graph change)."""
    with _cache_lock:
        _cache["key"], _cache["value"] = None, None
