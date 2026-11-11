"""The optional on-disk fallback for live lookups — OFF by default, last resort.

Founder direction (2026-10-10): the graph is the rule store; an indexed file is
allowed only as a last resort an operator switches on
(``verified_lookup_fallback: index`` / ``BLACKBOX_VERIFIED_LOOKUP_FALLBACK=index``).

When enabled, the refresh cycle indexes each CONFIRMED asset once (an asset is
anchored on chain and never changes): its triples are read from the node and go
through the compiler's own row builders into a SQLite file
(``verified_index.sqlite``) keyed exactly as the compiled dicts were. A lookup
consults it ONLY after the store could not answer; the store's failure is still
recorded in :data:`.health.HEALTH`, so a degraded store never looks healthy.
An index that does not yet cover every asset in scope answers hits but never
"clean" (LES-011: absence from a partial index proves nothing).

Pattern: Cache-aside, opt-in. Usage::

    index = FallbackIndex.for_scope(scope)          # None unless the scope enables it
    answer = index.dependencies(candidates)          # LookupAnswer, outcome per completeness
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ...kernel import constants, threat_ids
from ...kernel.dkg_client import DkgClient, extract_binding
from .. import row_adapters
from ..partitions import rows_from_triples
from .lookup import CLEAN, COULD_NOT_TELL, HIT, LookupAnswer
from .scope import VerifiedScope

logger = logging.getLogger(__name__)

FALLBACK_OFF = "off"
FALLBACK_INDEX = "index"
FALLBACK_MODES = (FALLBACK_OFF, FALLBACK_INDEX)

#: Assets indexed per refresh at most this long; the rest wait for the next one.
INDEX_BUDGET_SECONDS = 600.0
#: Triples per page when reading one asset (DKG 10.0.21 returned the largest asset,
#: 15,032 triples, in one answer).
PAGE_TRIPLES = 50_000

_SCHEMA = (
    "CREATE TABLE IF NOT EXISTS asset (graph TEXT PRIMARY KEY, indexed_at REAL NOT NULL)",
    "CREATE TABLE IF NOT EXISTS dependency (key TEXT PRIMARY KEY, graph TEXT NOT NULL, rule TEXT NOT NULL)",
    "CREATE TABLE IF NOT EXISTS ioc (key TEXT PRIMARY KEY, graph TEXT NOT NULL, rule TEXT NOT NULL, value TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS ioc_value ON ioc (value)",
)


def index_path() -> Path:
    return constants.blackbox_home() / "verified_index.sqlite"


class FallbackIndex:
    """One SQLite file of the live tiers, keyed as the compiled dicts were."""

    def __init__(self, scope: VerifiedScope, path: Optional[Path] = None) -> None:
        self.scope = scope
        self.path = path or index_path()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(self.path), timeout=2.0)
        for statement in _SCHEMA:
            self._db.execute(statement)

    @classmethod
    def for_scope(cls, scope: Optional[VerifiedScope], path: Optional[Path] = None) -> Optional[FallbackIndex]:
        """The index when the scope enables the fallback, else None (the default)."""
        if scope is None or scope.fallback != FALLBACK_INDEX:
            return None
        try:
            return cls(scope, path)
        except sqlite3.Error as exc:  # pragma: no cover - fail open: no fallback is the default anyway
            logger.warning("blackbox: fallback index unavailable: %s", exc)
            return None

    # -- answering ---------------------------------------------------------

    def complete(self) -> bool:
        """True when every asset in scope is indexed (absence then means clean)."""
        indexed = {row[0] for row in self._db.execute("SELECT graph FROM asset")}
        return bool(self.scope.assertion_graphs) and self.scope.assertion_graphs <= indexed

    def dependencies(self, candidates: Sequence[tuple[str, str, str]]) -> LookupAnswer:
        keys = [threat_ids.dependency_key(ecosystem, name, version) for ecosystem, name, version in candidates]
        return self._answer("dependency", keys)

    def iocs(self, identifiers: Sequence[str]) -> LookupAnswer:
        return self._answer("ioc", list(identifiers))

    def ioc_values(self, values: Sequence[str]) -> LookupAnswer:
        """IOC rules by VALUE (what the live lookup asks the store by), keyed by identifier."""
        return self._answer("ioc", list(values), column="value")

    def _answer(self, table: str, keys: list[str], column: str = "key") -> LookupAnswer:
        rules: dict[str, dict[str, Any]] = {}
        for start in range(0, len(keys), 500):
            chunk = keys[start:start + 500]
            marks = ",".join("?" * len(chunk))
            for key, graph, rule in self._db.execute(
                    f"SELECT key, graph, rule FROM {table} WHERE {column} IN ({marks})", chunk):
                if graph in self.scope.assertion_graphs:
                    loaded = json.loads(rule)
                    allowed = self.scope.as_tier_allows(graph, table, key, loaded)   # same tier rule as the store lookup
                    if allowed is not None and loaded.get("identifier") not in self.scope.revoked_identifiers:
                        rules[key] = allowed
        if rules:
            return LookupAnswer(rules, HIT, "fallback index")
        return LookupAnswer({}, CLEAN if self.complete() else COULD_NOT_TELL, "fallback index")

    # -- building ----------------------------------------------------------

    def index_missing_assets(self, client: DkgClient, cg_id: str, *, budget_seconds: float = INDEX_BUDGET_SECONDS) -> int:
        """Index every asset in scope not indexed yet, within the budget; returns how many."""
        indexed = {row[0] for row in self._db.execute("SELECT graph FROM asset")}
        deadline = time.monotonic() + budget_seconds
        done = 0
        for graph in sorted(self.scope.assertion_graphs - indexed):
            if time.monotonic() >= deadline:
                break
            triples = _read_asset(client, cg_id, graph)
            if triples is None:
                break                                          # the node refused; the rest wait
            self._store(graph, triples)
            done += 1
        return done

    def _store(self, graph: str, triples: list[tuple[str, str, str]]) -> None:
        kept = [triple for triple in triples if triple[0] not in self.scope.suppressed_subjects]
        dependencies: list[tuple[str, str, str]] = []
        iocs: list[tuple[str, str, str, str]] = []
        for built in rows_from_triples(graph, kept):
            mapped = row_adapters._row_to_rule(built, "public")
            if mapped is None:
                continue
            category, key, rule = mapped
            if category == "dependency":
                dependencies.append((key, graph, json.dumps(rule)))
            elif category == "ioc":
                iocs.append((key, graph, json.dumps(rule), str(rule.get("value") or "")))
        with self._db:
            self._db.executemany("INSERT OR REPLACE INTO dependency (key, graph, rule) VALUES (?, ?, ?)", dependencies)
            self._db.executemany("INSERT OR REPLACE INTO ioc (key, graph, rule, value) VALUES (?, ?, ?, ?)", iocs)
            self._db.execute("INSERT OR REPLACE INTO asset (graph, indexed_at) VALUES (?, ?)", (graph, time.time()))

    def close(self) -> None:
        self._db.close()


class OnDemandIndex:
    """The fallback index as a lookup holds it (Proxy): SQLite is opened only when the store
    could not tell, and closed right after — a lookup is built per tool call, and opening the
    index (connect + schema) on every one, even while the store answered, cost two connections
    per call that were never closed. Same answering methods as :class:`FallbackIndex`."""

    def __init__(self, scope: VerifiedScope) -> None:
        self.scope = scope

    @classmethod
    def for_scope(cls, scope: Optional[VerifiedScope]) -> Optional[OnDemandIndex]:
        """The proxy when the scope enables the fallback, else None (the default)."""
        return cls(scope) if scope is not None and scope.fallback == FALLBACK_INDEX else None

    def dependencies(self, candidates: Sequence[tuple[str, str, str]]) -> LookupAnswer:
        return self._asking(lambda index: index.dependencies(candidates))

    def ioc_values(self, identifiers: Sequence[str]) -> LookupAnswer:
        return self._asking(lambda index: index.ioc_values(identifiers))

    def _asking(self, ask: Any) -> LookupAnswer:
        index = FallbackIndex.for_scope(self.scope)
        if index is None:
            return LookupAnswer({}, COULD_NOT_TELL, "fallback index unavailable")
        try:
            return ask(index)
        finally:
            index.close()


def _read_asset(client: DkgClient, cg_id: str, graph: str) -> Optional[list[tuple[str, str, str]]]:
    """Every triple of one asset's graph, cursor-paged by subject; None on failure."""
    failure = object()
    triples: list[tuple[str, str, str]] = []
    after = ""
    while True:
        cursor = f'FILTER(STR(?threat) > {json.dumps(after)})' if after else ""
        page = client.query(f"SELECT ?threat ?p ?o WHERE {{ GRAPH <{graph}> {{ ?threat ?p ?o }} {cursor} }} "
                            f"ORDER BY STR(?threat) ?p ?o LIMIT {PAGE_TRIPLES}", cg_id, view=None, on_error=failure)
        if page is failure:
            return None
        batch = [(extract_binding(row.get("threat")), extract_binding(row.get("p")), _raw(row.get("o"))) for row in page]
        if len(batch) < PAGE_TRIPLES:
            return triples + batch
        last = batch[-1][0]
        complete = [triple for triple in batch if triple[0] != last]
        if not complete:
            return None
        triples.extend(complete)
        after = complete[-1][0]


def _raw(cell: Any) -> str:
    """The object exactly as the node sent it (the row builders unwrap it themselves)."""
    if isinstance(cell, dict):
        value = cell.get("value")
        return "" if value is None else str(value)
    return "" if cell is None else str(cell)


def maintain(scope: Optional[VerifiedScope], client: DkgClient, cg_id: str, *,
             budget_seconds: float = INDEX_BUDGET_SECONDS) -> int:
    """What the refresh cycle calls: index the assets still missing when the scope
    enables the fallback; 0 otherwise. Fail-open — never costs the generation."""
    index = FallbackIndex.for_scope(scope)
    if index is None:
        return 0
    try:
        done = index.index_missing_assets(client, cg_id, budget_seconds=budget_seconds)
        if done:
            logger.info("blackbox: fallback index gained %d asset(s)", done)
        return done
    except (sqlite3.Error, OSError) as exc:  # pragma: no cover - fail open
        logger.warning("blackbox: fallback index not maintained this refresh: %s", exc)
        return 0
    finally:
        index.close()
