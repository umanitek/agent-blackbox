"""The community pulse — "did the community change?" between full refreshes (R16, KI-202).

Before R16 the community tier was re-read only when the WHOLE ruleset
refreshed: a 15-minute floor on the dashboard, one hour by default. The
near-real-time arrival the benches showed came from a watcher that existed
only in the sandbox. Now one cheap probe — a single aggregate query over the
community's shared memory (the verified graph's, sub-graph
``constants.COMMUNITY_SUB_GRAPH``), count plus newest subject — runs at most
every ``cfg.community_poll_interval`` seconds (default 20, 0 = off) while the
agent is active, and only when its answer differs from last time does the
ruleset re-apply the community tier (see ``ruleset.pulse``). Reading stays
the reader's job; this module only says whether there is anything new.

Pattern: one stateful object with one lock (the last fingerprint and the
last probe time), module-level because the state is per process like the
node it talks to.

Usage::

    if community.PULSE.due(interval_s) and community.PULSE.changed(client, cfg): ...re-apply the tier...
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Callable, Optional

from ..kernel import constants, sparql_text
from ..kernel.dkg_client import DkgClient, extract_binding

logger = logging.getLogger(__name__)

#: One grouped aggregate over the community's shared memory: per statement
#: kind (reports, retractions, disputes, digests, curator statements such as
#: stage attestations — R3-attest) how many there are and the
#: newest subject — so a retraction or a dispute changes the fingerprint too,
#: not only a new report (bench finding 2026-10-02). Key manifests are counted
#: too (Community Curation: a community authority's manifest would live there,
#: so a new one must be picked up within a pulse, KI-248). Kinds absent simply
#: return no row.
_STATEMENT_KINDS = ("ThreatReport", "Retraction", "FalsePositive", "SightingDigest", "CuratorStatement", "KeyManifest")
_FINGERPRINT_SPARQL = (
    "PREFIX g: <http://umanitek.ai/ontology/guardian/> "
    "SELECT ?t (COUNT(DISTINCT ?r) AS ?n) (MAX(STR(?r)) AS ?last) WHERE { "
    "VALUES ?t { " + " ".join(f"g:{kind}" for kind in _STATEMENT_KINDS) + " } ?r a ?t } GROUP BY ?t"
)


def fingerprint(client: DkgClient, cfg: Any) -> Optional[str]:
    """``"ThreatReport=<count>:<newest subject>;Retraction=…"`` (kinds sorted,
    absent kinds omitted; ``""`` for an empty graph), or None when the probe
    failed or timed out (fail-open: no change is ever inferred from a failed
    probe, and a timed-out probe looks like an empty graph — KI-262)."""
    graph = str(getattr(cfg, "context_graph_id", "") or "")
    if not graph:
        return None
    rows = sparql_text.query_rows(client, _FINGERPRINT_SPARQL, graph, constants.VIEW_SHARED_WORKING_MEMORY)
    if rows is None:
        return None
    parts = []
    for row in rows:
        kind = extract_binding(row.get("t")).rsplit("/", 1)[-1]
        parts.append(f"{kind}={extract_binding(row.get('n')) or '0'}:{extract_binding(row.get('last')) or ''}")
    return ";".join(sorted(parts))


class CommunityPulse:
    """Remembers when the graph was last probed and what it looked like."""

    def __init__(self, clock: Callable[[], float] = time.time) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._last_probe = 0.0
        self._fingerprint: Optional[str] = None
        self._baselined_now = False

    def due(self, interval_s: float) -> bool:
        """Claim the next probe slot when *interval_s* has passed (atomic)."""
        if interval_s <= 0:
            return False
        now = self._clock()
        with self._lock:
            if now - self._last_probe < interval_s:
                return False
            self._last_probe = now
            return True

    def changed(self, client: DkgClient, cfg: Any, applied: Optional[str] = None) -> bool:
        """Probe the graph; True when its fingerprint differs from the last
        successful probe. With no probe yet in this process, *applied* — the
        fingerprint the cached community tier was applied against (KI-208) —
        is the baseline instead, so a process that starts after reports arrived
        sees them as a change; only without either does the first probe merely
        set the baseline."""
        current = fingerprint(client, cfg)
        if current is None:
            return False
        with self._lock:
            previous = self._fingerprint
            if previous is None and applied:
                previous = applied          # the cached tier's baseline stands in for this process's first probe
            self._fingerprint = current
            self._baselined_now = previous is None
        if previous is None:
            return False
        if previous != current:
            logger.debug("blackbox: community graph changed (%s -> %s)", previous, current)
            return True
        return False

    @property
    def baselined_now(self) -> bool:
        """True right after the probe that SET the baseline (a process that just
        started, or the first probe after a reset) — the beat uses it to apply
        the reports that already exist when the cached tier has none yet."""
        with self._lock:
            return self._baselined_now

    @property
    def last_fingerprint(self) -> str:
        """What the last successful probe saw (``""`` before any) — the value a
        tier applied right after that probe records as its baseline (KI-208)."""
        with self._lock:
            return self._fingerprint or ""

    @property
    def report_count(self) -> int:
        """How many reports the last successful probe counted (0 before any)."""
        with self._lock:
            parts = (self._fingerprint or "").split(";")
        for part in parts:
            if part.startswith("ThreatReport="):
                try:
                    return int(part[len("ThreatReport="):].split(":", 1)[0])
                except ValueError:
                    return 0
        return 0

    def reset(self) -> None:
        """Forget the baseline (tests, and after a full refresh re-read everything)."""
        with self._lock:
            self._last_probe = 0.0
            self._fingerprint = None
            self._baselined_now = False


#: The per-process pulse.
PULSE = CommunityPulse()
