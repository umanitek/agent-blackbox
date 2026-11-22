"""The verified graph's malicious domains and IP addresses, in full — what Network Shield enforces.

The live lookup answers one indicator at a time (fast enough for a tool call, far too slow in front
of every DNS lookup). Network Shield's enforcer needs the whole list in memory, so this reads every
verified network indicator with **exactly the live lookup's scope** (:class:`.scope.VerifiedScope`):

* only the scope's ``assertion_graphs`` — the confirmed, owner-pinned Verifiable Memory assets
  (a tentative, foreign or community asset never reaches the list);
* minus the subjects curator corrections suppress (``suppressed_subjects``);
* minus the identifiers the curator revoked (``revoked_identifiers``).

Both kinds of verified indicator count, as in the compile (``row_adapters._row_identity``): a
``defender:IocSignal`` (``dp:iocType`` + ``dp:value``) and an *active* ``blackbox:SourceObservation``
(``bp:canonicalType`` + ``bp:normalizedValue``) — of type ``domain`` or ``ip``. Values carry the
guard's own spelling (:func:`~...kernel.threat_ids.normalize_ioc_value`).

**How it reads** (the pattern of :mod:`.asset_facts`): a verified asset never changes once
confirmed, so each asset's indicators are read ONCE — one plain query per asset, bound to its own
graph (``GRAPH <asset>``; measured 0.06 s for 1,000 rows on a test VM (2026-11-20), where a batched
``VALUES ?g`` join with a type FILTER timed out) — and kept; assets the scope's facts count no
indicators in are skipped; a later scope reads only its new assets. One build runs at a time, in the background
(:func:`network_indicators` with ``wait=False`` never blocks a page); reads stop at the
:data:`BUDGET_SECONDS` budget or the first query the store cannot answer, and the rest are read
next time. A partial list is served with ``complete=False`` — never presented as the whole graph.

Usage::

    from plugins.blackbox import ruleset
    found = ruleset.network_indicators()            # waits for a build (the enforcer's plan)
    found = ruleset.network_indicators(wait=False)  # what is known now, or None (a page)
    found.domains, found.ips, found.complete
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional

from ...kernel import threat_ids
from ...kernel.dkg_client import extract_binding
from ...kernel.store import StoreClient
from .scope import VerifiedScope

logger = logging.getLogger(__name__)

#: The indicator types Network Shield enforces at the network layer.
NETWORK_TYPES = ("domain", "ip")
#: The most time one build spends reading; the rest waits for the next build.
BUDGET_SECONDS = 240.0
QUERY_TIMEOUT_SECONDS = 30.0
#: How long :func:`network_indicators` with ``wait=True`` waits for a running build.
WAIT_SECONDS = BUDGET_SECONDS + 10.0


@dataclass(frozen=True)
class NetworkIndicators:
    """Every verified malicious domain and IP address read so far, normalised.

    *assets* is how many confirmed assets were in scope and *read* how many are in the lists;
    *complete* is True when every one was read; *built_at* is unix seconds.
    """

    domains: frozenset[str]
    ips: frozenset[str]
    assets: int
    read: int
    complete: bool
    built_at: float


#: One asset's indicators: (subject, type, normalised value).
Rows = tuple[tuple[str, str, str], ...]

_lock = threading.Lock()
_built = threading.Event()
_state: dict[str, Any] = {"assets": {}, "key": None, "value": None, "building": False}


def _query(graph: str) -> str:
    """Both kinds of verified indicator in one asset (types are filtered after reading)."""
    return (f"SELECT ?t ?type ?value WHERE {{ {{ GRAPH <{graph}> {{ ?t a <urn:defender:IocSignal> ; "
            f"<urn:defender:p:iocType> ?type ; <urn:defender:p:value> ?value }} }} UNION {{ GRAPH <{graph}> {{ "
            f'?t a <urn:blackbox:SourceObservation> ; <urn:blackbox:p:lifecycleStatus> "active" ; '
            f"<urn:blackbox:p:canonicalType> ?type ; <urn:blackbox:p:normalizedValue> ?value }} }} }}")


def _read_asset(store: Any, graph: str) -> Optional[Rows]:
    """One asset's domain and IP indicators; None when the store could not answer."""
    answer = store.select(_query(graph), timeout=QUERY_TIMEOUT_SECONDS)
    if not answer.known:
        logger.info("blackbox: verified network indicators not read (%s); the rest wait", answer.reason)
        return None
    rows = []
    for row in answer.rows or []:
        ioc_type = extract_binding(row.get("type")).strip().lower()
        if ioc_type not in NETWORK_TYPES:
            continue
        value = threat_ids.normalize_ioc_value(ioc_type, extract_binding(row.get("value")))
        if value:
            rows.append((extract_binding(row.get("t")), ioc_type, value))
    return tuple(rows)


def read_assets(store: Any, wanted: Iterable[str], known: dict[str, Rows],
                budget_seconds: float = BUDGET_SECONDS) -> dict[str, Rows]:
    """*known* rows for the assets still wanted, plus rows read now for the rest — one query per
    asset, within the budget, stopping at the first query the store cannot answer."""
    wanted = set(wanted)
    rows = {graph: found for graph, found in known.items() if graph in wanted}
    deadline = time.monotonic() + budget_seconds
    for graph in sorted(graph for graph in wanted if graph not in rows):
        if time.monotonic() >= deadline:
            break
        read = _read_asset(store, graph)
        if read is None:
            break
        rows[graph] = read
    return rows


def indicators_from(assets: dict[str, Rows], scope: VerifiedScope) -> NetworkIndicators:
    """The lists from per-asset *assets*, with the scope's corrections and revocations applied."""
    domains: set[str] = set()
    ips: set[str] = set()
    for graph, rows in assets.items():
        if graph not in scope.assertion_graphs:
            continue
        for subject, ioc_type, value in rows:
            if subject in scope.suppressed_subjects or threat_ids.ioc_identifier(ioc_type, value) in scope.revoked_identifiers:
                continue
            (domains if ioc_type == "domain" else ips).add(value)
    read = sum(1 for graph in assets if graph in scope.assertion_graphs)
    return NetworkIndicators(domains=frozenset(domains), ips=frozenset(ips), assets=len(scope.assertion_graphs),
                             read=read, complete=read == len(scope.assertion_graphs), built_at=time.time())


def _without_indicators(scope: VerifiedScope) -> set[str]:
    """Assets the scope's per-asset facts count no indicators in (nothing to read there)."""
    facts = getattr(scope, "asset_facts", None) or {}
    return {graph for graph, fact in facts.items()
            if graph in scope.assertion_graphs and not getattr(fact, "counts", {}).get("ioc", 1)}


def _scope_key(scope: VerifiedScope) -> tuple:
    return (scope.context_graph_id, scope.store_url, scope.assertion_graphs, scope.suppressed_subjects, scope.revoked_identifiers)


def _build(scope: VerifiedScope, store_factory: Callable[[str], Any]) -> None:
    try:
        with _lock:
            known = dict(_state["assets"])
        empty = {graph: () for graph in _without_indicators(scope) if graph not in known}
        assets = read_assets(store_factory(scope.store_url), scope.assertion_graphs, {**known, **empty})
        found = indicators_from(assets, scope)
        with _lock:
            _state["assets"] = assets
            _state["value"] = found
            _state["key"] = _scope_key(scope) if found.complete else None   # partial: build again next ask
    except Exception:   # fail open: a page keeps the last lists, never an empty "nothing is malicious"
        logger.warning("blackbox: could not build the verified network indicators", exc_info=True)
    finally:
        with _lock:
            _state["building"] = False
        _built.set()


def network_indicators(scope: Optional[VerifiedScope], store_factory: Optional[Callable[[str], Any]] = None,
                       wait: bool = True) -> Optional[NetworkIndicators]:
    """The verified domains and IPs for *scope*, or None before any could be read.

    A complete list for this scope is answered at once. Otherwise one background build starts
    (or the running one is joined); *wait* True waits for it (the enforcer's plan), False answers
    what is known now (a page). *store_factory* builds the store client (tests hand in a fake).
    """
    if scope is None or not scope.context_graph_id or not scope.store_url or not scope.assertion_graphs:
        return None
    with _lock:
        if _state["key"] == _scope_key(scope):
            return _state["value"]
        start = not _state["building"]
        if start:
            _state["building"] = True
            _built.clear()
    if start:
        factory = store_factory or (lambda url: StoreClient(url, timeout=QUERY_TIMEOUT_SECONDS))
        threading.Thread(target=_build, args=(scope, factory), name="blackbox-network-lists", daemon=True).start()
    if wait:
        _built.wait(WAIT_SECONDS)
    with _lock:
        return _state["value"]


def forget() -> None:
    """Drops everything read (tests, and a context-graph change)."""
    with _lock:
        _state.update(assets={}, key=None, value=None, building=False)
    _built.set()


#: How long one "can the threat graph be asked now?" answer is reused (pages ask every second or two).
REACHABLE_CACHE_SECONDS = 10.0
#: How long the probe waits for the local store: it is on this Mac, so a slow answer is a down one.
REACHABLE_TIMEOUT_SECONDS = 1.0
#: The cheapest question a SPARQL store can answer: no graph pattern, one constant row.
_PROBE_QUERY = "SELECT (1 AS ?ok) WHERE {}"
_reachable: dict[str, Any] = {"url": None, "at": 0.0, "value": None}


def graph_reachable(scope: Optional[VerifiedScope], store_factory: Optional[Callable[[str], Any]] = None,
                    now: Optional[float] = None) -> Optional[bool]:
    """True when the local store holding the threat graph answers now, False when it does not,
    None when no store is configured yet. Cached for :data:`REACHABLE_CACHE_SECONDS`.

    WHY (E2E recheck 2026-11-21): the lists above are kept in memory after the node goes down —
    rightly, so DNS Shield and the firewall keep blocking — and the overview said the graph was
    "ready" while the node was off. This answers the separate question "can it be read now?"."""
    if scope is None or not scope.store_url:
        return None
    moment = time.time() if now is None else now
    with _lock:
        if _reachable["url"] == scope.store_url and moment - _reachable["at"] < REACHABLE_CACHE_SECONDS:
            return _reachable["value"]
    factory = store_factory or (lambda url: StoreClient(url, timeout=REACHABLE_TIMEOUT_SECONDS))
    value = factory(scope.store_url).select(_PROBE_QUERY).known
    with _lock:
        _reachable.update(url=scope.store_url, at=moment, value=value)
    return value

