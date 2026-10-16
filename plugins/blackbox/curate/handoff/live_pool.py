"""The confirmed pool as THIS node sees it, ready to hand on (Community Curation C8).

``community.pool`` is pure; this module feeds it from the live node: the
verified reports and the curators' statements this node holds, with the same
restrictions every reader applies — a threat the verified authority rejected
or revoked is not in the pool (the most restrictive word wins), a threat that
is already in the verified graph has nothing left to hand over, and a
confirmation this reader is still holding back under its daily cap is not
acted on yet.

Pattern: a function returning a tagged result (:class:`LivePool`).

Usage::

    pool = read_live_pool(ctx)
    if pool.unavailable: ...say why...
    text = bundle_text(ctx, pool)                  # the export file
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Tuple

from ... import community
from ...kernel.signing.statement_order import CuratorStatement
from ..context import CurateContext, verified_identifiers


@dataclass(frozen=True)
class LivePool:
    """``entries`` — the pool. ``unavailable`` — non-empty when it could not be
    read (never treat that as an empty pool). ``withheld`` — threats the
    community curators confirmed that are NOT in the pool because the verified
    authority said otherwise or already lists them."""

    entries: tuple[community.pool.PoolEntry, ...] = ()
    unavailable: str = ""
    withheld: int = 0


def read_live_pool(ctx: CurateContext) -> LivePool:
    """The confirmed pool from this node's verified reports and curator statements."""
    graph = ctx.verified_graph
    read = community.read_verified_reports(ctx.client, ctx.cfg)
    if not read.available:
        return LivePool(unavailable=f"the community graph could not be read ({read.reason})")
    own = read.curator.community
    if own is None or own.manifest is None:
        return LivePool(unavailable="no community authority is trusted on this node for this graph")
    confirmed = [identifier for identifier, record in own.verdicts.items() if record.kind is CuratorStatement.CONFIRMATION]
    already = verified_identifiers(ctx.compiled, confirmed)
    standing = {identifier for identifier in confirmed
                if read.curator.verdict(identifier) is CuratorStatement.CONFIRMATION and identifier not in already}
    reports = [report for report in read.reports if report.identifier in standing]
    interest = [*sorted(standing), *sorted({f"author:{report.author}" for report in reports})]
    rows = [row for _graph, row in community.known_curator_statements(ctx.client, ctx.cfg, interest)]
    entries = community.pool.confirmed_pool(own.manifest, rows, reports, graph=graph)
    return LivePool(entries=tuple(entry for entry in entries if entry.identifier in standing),
                    withheld=len(confirmed) - len(standing))


def bundle_text(ctx: CurateContext, pool: LivePool) -> str:
    """The export file for *pool*: its entries and the key manifests this node holds for the graph."""
    graph = ctx.verified_graph
    return community.pool.Bundle(environment=ctx.environment, graph=graph,
                                 manifests=community.pool.held_manifest_texts(graph), entries=pool.entries).to_text()
