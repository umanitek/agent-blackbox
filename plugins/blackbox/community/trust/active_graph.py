"""Which verified graph is active — the configured one or its successor (T2).

The authority may name a successor graph with a root-signed graph migration
(:mod:`...kernel.signing.graph_migration`); readers follow it after the
waiting period (:mod:`.migrations` decides which one). :func:`active_verified_graph`
is called before a verified read: it reads the configured graph's migrations,
adds the ones this node already stored, verifies every row again against the
pinned roots, and stores the result (:meth:`.trust_store.TrustStore.remember_migrations`).

A migration read that fails changes nothing: the stored rows are verified and
followed as before (trust only moves forward). With no root pinned for the
network nothing is read and the configured graph stays active.

Pattern: Value Object (:class:`ActiveGraph`) + one resolving function.

Usage (through the package)::

    active = community.active_verified_graph(client, cfg)
    active.graph            # where NEW verified rows come from
    active.migration        # the GraphMigration followed (from_day = the cut-off), or None
    active.subscriptions    # the graphs the node keeps subscribed (old first)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from ...kernel import constants
from ...kernel.config import BlackboxConfig
from ...kernel.dkg_client import DkgClient
from ...kernel.signing import trust_anchors
from ...kernel.signing import GraphMigration
from ...kernel.sparql_text import page_rows
from ..report_signer import network_environment
from ..statements import curator_view
from . import bounded_read, migrations, trust_store

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ActiveGraph:
    """The verified graph a reader uses. ``configured`` — the node's configured
    verified graph (the old one, still holding legacy assets). ``migration`` —
    the graph migration followed (None: no successor). ``frozen`` — SECURITY: two
    root-signed migrations conflict above the one followed. ``conflict_ignored``
    — SECURITY: a conflict at or below it (cannot move this reader). ``unavailable``
    — the graph's migrations could not be read; the stored ones decided."""

    configured: str
    migration: Optional[GraphMigration] = None
    frozen: bool = False
    conflict_ignored: bool = False
    unavailable: bool = False

    @property
    def successor(self) -> str:
        """The successor graph in effect, or ""."""
        return self.migration.to_graph if self.migration else ""

    @property
    def graph(self) -> str:
        """Where new verified rows come from: the successor once one is in effect."""
        return self.successor or self.configured

    @property
    def subscriptions(self) -> tuple[str, ...]:
        """The graphs the node keeps subscribed: the configured one always (its
        legacy assets stay readable there), then the successor when active."""
        return tuple(graph for graph in (self.configured, self.successor) if graph)


def active_verified_graph(client: DkgClient, cfg: BlackboxConfig, environment: str = "") -> ActiveGraph:
    """The active verified graph for *cfg* — see the module docstring. Never
    raises: when the node cannot say which network it is on, no root can be
    chosen and the configured graph is returned (``unavailable``)."""
    configured = cfg.context_graph_id
    if not configured:
        return ActiveGraph(configured)
    try:
        environment = environment or network_environment(client.status())
    except Exception as exc:  # node unreachable: the verified read fails anyway
        logger.debug("blackbox: graph migration read skipped (%s)", exc)
        environment = ""
    roots = trust_anchors.RootPins.for_environment(environment) if environment else trust_anchors.RootPins()
    if not roots:
        return ActiveGraph(configured, unavailable=not environment)
    store = trust_store.TrustStore()
    stored = store.load(configured)
    fresh = page_rows(client, configured, constants.VIEW_VERIFIABLE_MEMORY, migrations.graph_migrations_sparql)
    trusted = [(row, verdict) for row in bounded_read.fold([*stored.migrations, *(fresh or [])])
               if (verdict := migrations.verify_row(row, environment, configured, roots)) is not None]
    verdicts = [verdict for _, verdict in trusted]
    sticky = stored.successor
    sticky_order = sticky.order if sticky else None
    followed = migrations.effective_migration(verdicts, curator_view.today_utc(), sticky_order,
                                              sticky_hash=sticky.content_hash if sticky else "")
    frozen_at = migrations.freeze_order(verdicts, sticky_order)
    # The store keeps the followed migration only when it moves forward, and the
    # rows at the freeze, so a flood of conflicting higher orders cannot erase it.
    store.remember_migrations(configured, [row for row, _ in trusted], _stored(followed),
                              keep_orders=[frozen_at] if frozen_at else [])
    if fresh is None:
        logger.warning("blackbox: graph migrations unreadable in %s — following the stored ones", configured)
    return ActiveGraph(configured, followed, frozen=frozen_at is not None,
                       conflict_ignored=migrations.ignored_conflict(verdicts, sticky_order), unavailable=fresh is None)


def _stored(followed: Optional[GraphMigration]) -> Optional[trust_store.StoredSuccessor]:
    if followed is None:
        return None
    return trust_store.StoredSuccessor(followed.order, migrations.content_hash(followed),
                                       followed.to_graph, followed.from_day)
