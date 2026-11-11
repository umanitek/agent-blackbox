"""Which graph migration a reader follows (reader policy, T2).

The migration FORMAT is :mod:`...kernel.signing.graph_migration`; this module
is what a reader does with the migrations it finds: keep only those a trusted
root signed away from its configured verified graph, and follow the newest one
under the SAME rules as a key manifest (:mod:`.manifests`, D30/D31):

* never one inside its time-lock (counted from ``issued_day``). A
  migration widens what counts, so there is no early path like a narrowing list;
* two different migrations at one ``(root_epoch, sequence)``, or a freeze-only
  one (a pinned root at another epoch), freeze that order and every order above
  it — any pinned root can stop an unwanted migration by signing a conflicting one;
* the migration this reader already followed once its time-lock passed is
  sticky: a conflict at or below its order never moves the reader back.

Why not reuse :mod:`.manifests` directly: its functions read a manifest's
content hash and its narrowing rule; a migration has neither. The rules are
the same, the subject is different — so the shape below mirrors it line for line.

Usage::

    migrations = trusted_migrations(rows, environment, graph, roots)
    followed = effective_migration(migrations, today, stored.order, sticky_hash=stored.content_hash)
    frozen_at = freeze_order(migrations, stored.order)              # SECURITY: frozen; the store keeps its rows
"""

from __future__ import annotations

import json
from datetime import date, timedelta
from typing import Any, Dict, Iterable, List, Mapping, Optional, Set, Tuple

from ...kernel import signing, sparql_text, threat_ids
from ...kernel.dkg_client import extract_binding
from ...kernel.signing import graph_migration
from ...kernel.signing import GraphMigration, MigrationVerdict
from ...kernel.signing import key_manifest
from ...kernel.signing import RootPins

Order = tuple[int, int]


def graph_migrations_sparql(after: str) -> str:
    """One page of graph-migration rows after the subject cursor *after*."""
    cursor = sparql_text.cursor_filter(after)
    return f"""
{sparql_text.GUARDIAN_PREFIX}
SELECT ?r ?signedStatement WHERE {{
  ?r a g:GraphMigration ;
     g:signedStatement ?signedStatement .
  {cursor}
}} ORDER BY STR(?r) LIMIT 500
"""


def verify_row(row: Mapping[str, Any], environment: str, graph: str, roots: RootPins) -> Optional[MigrationVerdict]:
    """The verdict on one row's migration when a trusted root signed it away
    from *graph* in *environment* (freeze-only included), else None."""
    envelope = signing.from_text(extract_binding(row.get("signedStatement")))
    return graph_migration.verify_migration(envelope, environment=environment, graph=graph, roots=roots)


def trusted_migrations(rows: Iterable[Mapping[str, Any]], environment: str, graph: str,
                       roots: RootPins) -> list[MigrationVerdict]:
    """The verdict on every migration in *rows* a trusted root signed away from
    *graph* in *environment* — freeze-only ones included (they may conflict,
    never be followed)."""
    verdicts = (verify_row(row, environment, graph, roots) for row in rows)
    return [verdict for verdict in verdicts if verdict is not None]


def content_hash(migration: GraphMigration) -> str:
    """What makes two migrations at one order the same statement or a conflict."""
    return threat_ids.stable_hash(json.dumps(migration.to_payload(), sort_keys=True), 20)


def is_pending(migration: GraphMigration, today: str) -> bool:
    """True while *migration* is inside its time-lock (the same time-lock as a list)."""
    effective = date.fromisoformat(migration.issued_day) + timedelta(days=key_manifest.MANIFEST_TIME_LOCK_DAYS)
    return today < effective.isoformat()


def conflict_orders(verdicts: Iterable[MigrationVerdict]) -> set[Order]:
    """The orders at which trusted migrations conflict: two different contents
    at one order (pending ones included — a counter-statement freezes at once),
    or any freeze-only verdict."""
    contents: dict[Order, set[str]] = {}
    conflicts: set[Order] = set()
    for verdict in verdicts:
        contents.setdefault(verdict.migration.order, set()).add(content_hash(verdict.migration))
        if verdict.freeze_only:
            conflicts.add(verdict.migration.order)
    return conflicts | {order for order, hashes in contents.items() if len(hashes) > 1}


def _freezing(conflicts: set[Order], sticky_order: Optional[Order]) -> set[Order]:
    """The conflicts that move the reader: those ABOVE its sticky order."""
    return {order for order in conflicts if sticky_order is None or order > sticky_order}


def effective_migration(verdicts: Iterable[MigrationVerdict], today: str, sticky_order: Optional[Order] = None, *,
                        sticky_hash: str = "") -> Optional[GraphMigration]:
    """The migration this reader follows (None: the configured graph stays active):
    the newest one past its time-lock, below the lowest freezing conflict. At the
    sticky order only the content with *sticky_hash* is followed; without a hash
    an ambiguous sticky order is skipped, never guessed."""
    verdicts = list(verdicts)
    conflicts = conflict_orders(verdicts)
    ceiling = min(_freezing(conflicts, sticky_order), default=None)

    def usable(migration: GraphMigration) -> bool:
        if ceiling is not None and migration.order >= ceiling:
            return False
        if migration.order == sticky_order and sticky_hash:
            return content_hash(migration) == sticky_hash
        return migration.order not in conflicts

    candidates = [v.migration for v in verdicts
                  if not v.freeze_only and usable(v.migration) and not is_pending(v.migration, today)]
    return max(candidates, key=lambda migration: migration.order, default=None)


def freeze_order(verdicts: Iterable[MigrationVerdict], sticky_order: Optional[Order] = None) -> Optional[Order]:
    """The lowest conflict above *sticky_order* (None: not frozen) — the trust
    store keeps its rows so a flood of conflicting higher orders cannot push it out."""
    return min(_freezing(conflict_orders(verdicts), sticky_order), default=None)


def ignored_conflict(verdicts: Iterable[MigrationVerdict], sticky_order: Optional[Order]) -> bool:
    """SECURITY: a conflict at or below the sticky order — it cannot move this
    reader, but someone with a root key is signing old orders."""
    return sticky_order is not None and any(order <= sticky_order for order in conflict_orders(verdicts))
