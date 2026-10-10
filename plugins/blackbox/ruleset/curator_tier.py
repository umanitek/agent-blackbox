"""The curator overlay on the verified ruleset — revocations (Refine R2).

A curator revocation withdraws a verified rule. It REDUCES enforcement, so it
always applies, on every refresh path and whether or not a community graph is
configured (asymmetric safety, LES-016). Only revocations this node can
verify count: signed by the trusted key manifest's curator keys, in the
verified graph (:func:`..community.read_curator_view`). Fail-open: a curator
read problem never degrades the verified ruleset; it simply removes nothing.

A re-promotion (a higher-sequence promotion after a revocation) takes effect
at the next full compile of the verified graph. Delaying an un-revoke is the
safe direction, because it raises enforcement.

Usage (from the refresh cycle)::

    curator_tier.apply_curator_tier(rs, client, config)
"""

from __future__ import annotations

import logging
import time
from typing import Any

from .. import community, killlist
from ..kernel import constants, signing
from ..kernel.config import BlackboxConfig
from ..kernel.dkg_client import DkgClient
from . import compiler

logger = logging.getLogger(__name__)


def apply_curator_tier(rs: compiler.Ruleset, client: DkgClient, config: BlackboxConfig) -> int:
    """Drop the verified rules the curator revoked; returns how many."""
    try:
        view = community.read_curator_view(client, config)
    except Exception as exc:  # pragma: no cover - fail open (an outer boundary)
        logger.warning("blackbox: curator revocations not applied this refresh: %s", exc)
        rs.curator_read_unavailable = True
        return 0
    rs.curator_read_unavailable = bool(view.unavailable or view.lookup_incomplete or view.manifest_conflict)
    _apply_kill_list(rs, client, config, view)
    rs.curator_manifest_state = ({"stale": "STALE since ", "pending": "PENDING until "}.get(view.manifest_state, "")
                                 + view.manifest_state_day) if view.manifest_state else ""
    removed = rs.drop_identifiers(view.revoked)
    if removed:
        logger.info("blackbox: %d verified rule(s) withdrawn by curator revocation", removed)
    return removed


def _popular(entry: killlist.KillEntry) -> bool:
    """A kill on an allowlisted / popular artifact (R9 tables, keyed registry:name) needs the root + a 24 h hold."""
    return community.allowlist.load().is_warninglisted_package(entry.registry, entry.identifier)


def _apply_kill_list(rs: compiler.Ruleset, client: DkgClient, config: BlackboxConfig, view: Any) -> None:
    """R14: the newest kill list that passes its signatures and the blast-radius
    gates becomes the ruleset's; on any failure the LAST-GOOD list stays. Fail-open."""
    store = killlist.LastGoodStore()
    previous = store.current()
    rs.kill_list_refused = ""
    if view.manifest is None:   # nothing can verify a list without a trusted manifest: no read, last-good stays
        rs.kill_list = previous.as_cache() if previous is not None else {}
        return
    try:
        rows = community.page_rows(client, config.context_graph_id, constants.VIEW_VERIFIABLE_MEMORY,
                                   killlist.kill_list_sparql) or []
        parsed = [p for p in (killlist.parse_kill_list(row, view.manifest, graph=config.context_graph_id) for row in rows)
                  if p is not None]
        newest = max(parsed, key=lambda p: p[1].version, default=None)
        if newest is not None:
            envelope, kill_list = newest
            signers = view.manifest.curator_signers(envelope, statement_type=killlist.KILL_LIST_STATEMENT)
            roots = signing.verified_signers(envelope, statement_type=killlist.KILL_LIST_STATEMENT,
                                             environment=view.manifest.environment, graph=config.context_graph_id)
            roots &= community.curator_trusted_roots(view.manifest.environment)
            decision = killlist.admit(kill_list, signers=signers, root_signers=roots, previous=previous,
                                      now=time.time(), is_popular=_popular)
            if decision.refused:
                rs.kill_list_refused = decision.refused
                logger.warning("blackbox: kill list v%d refused — last-good kept: %s", kill_list.version, decision.refused)
            else:
                store.remember(decision, kill_list.day)
                previous = store.current()
                for entry, why in decision.dropped:
                    logger.warning("blackbox: kill-list entry %s not applied: %s", entry.key, why)
    except Exception as exc:  # pragma: no cover - never degrade the refresh; last-good stays
        logger.warning("blackbox: kill list not refreshed this cycle (last-good kept): %s", exc)
    rs.kill_list = previous.as_cache() if previous is not None else {}
