"""The facts the operator-health rules read — :class:`HealthInputs`, one frozen record.

Moved out of :mod:`kernel.health` unchanged (that module reached its size limit);
:mod:`kernel.health` re-exports it, so ``health.HealthInputs`` is still the name
every caller uses. Build one with ``health.gather(...)``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping, Optional

# Imported under their own names: two HealthInputs fields are called community_authority and
# manifest_watch, and a class body that reads a module through a name it is defining works only
# by evaluation order.
from . import community_authority as community_alarms
from . import manifest_watch as manifest_watcher


@dataclass(frozen=True)
class HealthInputs:
    """Everything the health rules look at (plain facts, gathered by the caller).

    ``node_reachable``; ``ruleset_age_s`` (seconds since the ruleset was
    compiled; None = never); ``sync_interval_s``; ``rule_count``;
    ``community_configured``; ``community_paused``; ``read_unavailable_reason``
    ("" when the last community read was fine); ``curator_trusted`` (a key
    manifest this network trusts); ``backlog`` (lanes text, "" when none);
    ``away_keys``; ``revoked`` ({identifier: actions it BLOCKED here});
    ``held_back`` (statements over the per-author budget); ``pending_shares``
    (this node's reports waiting to be retried, R16); ``shares_given_up``
    (reports abandoned after the retry window).
    """

    node_reachable: bool
    ruleset_age_s: Optional[float]
    sync_interval_s: float
    rule_count: int
    community_configured: bool = False
    community_paused: bool = False
    read_unavailable_reason: str = ""
    curator_trusted: bool = False
    backlog: str = ""
    away_keys: int = 0
    revoked: Mapping[str, int] = None  # type: ignore[assignment]
    held_back: int = 0
    pending_shares: int = 0
    shares_given_up: int = 0
    #: R10b (plan §12): the full operator set.
    curators_last_day: str = ""          # newest day any curator statement carries ("" = none)
    today: str = ""                      # UTC day the inputs were gathered
    heartbeat_missing_keys: int = 0      # curator keys with no heartbeat in HEARTBEAT_SILENCE_DAYS
    manifest_conflict: bool = False      # two trusted manifests, one order, different content
    manifest_conflict_ignored: bool = False   # T1: a conflict at/below the sticky order, ignored
    min_reader_version: str = ""         # the manifest's floor; my_version is constants.__version__
    my_version: str = ""
    env_mismatch_rows: int = 0           # rows signed for another network / graph
    future_dated_rows: int = 0           # rows dated after tomorrow
    kill_list_version: int = 0           # the kill list in force (0 = none)
    kill_list_refused: str = ""          # why the newest kill list was refused (last-good kept)
    manifest_state: str = ""             # R7b: "" | "pending" | "stale"
    manifest_state_day: str = ""         # the day it takes effect / expired
    manifest_expires_day: str = ""       # the 30-day-ahead key-expiry alarm
    #: False on a machine with no DKG node for Blackbox (``health.node_installed``) — a Hermes
    #: plugin-catalog install brings the plugin only; the alarms then say how to install the node.
    node_installed: bool = True
    #: DKG-lookup B5: why live verified lookups are degraded ("" = answering). The
    #: caller passes ``ruleset.live.HEALTH.read().problem()`` (the kernel reads no feature).
    verified_lookup_problem: str = ""
    #: The first verified sync, as the dashboard's progress watch sees it: "running" (its
    #: counts are moving), "stalled", or "" (not syncing, or nobody watching — the CLI).
    first_sync: str = ""
    #: Whether the graph's owner has admitted this node, as the node's own listing says
    #: (``community.Admission`` value: owner / approved / waiting / open / unknown; "" = not read).
    admission: str = ""
    #: The node's process is running but younger than the restart grace (``sync.node_starting``):
    #: an unreachable node is then starting up, not stale.
    node_starting: bool = False
    #: Community sharing is on (``cfg.community_enabled``): a "waiting" node's shares are refused.
    sharing_enabled: bool = False
    #: trust-and-threat-lab R1: why the shipped legacy asset list was refused ("" = fine) — the
    #: caller passes ``rs.verified_scope.legacy_refused``; the last-good asset tiers stay in force.
    legacy_list_refused: str = ""
    #: Community Curation C11: why sharing is stopped by consent ("" = in force or sharing off) — the
    #: caller passes ``community.consent.why_not()`` only when `report: true`.
    sharing_consent_problem: str = ""
    #: Community Curation: the same facts for the COMMUNITY authority (its own manifest and curators).
    community_authority: community_alarms.CommunityAuthorityInputs = field(
        default_factory=community_alarms.CommunityAuthorityInputs)
    #: trust-and-threat-lab W1: the manifest watcher's facts (``manifest_watch.watch_inputs``); shown with or without a community.
    manifest_watch: manifest_watcher.ManifestWatchInputs = field(default_factory=manifest_watcher.ManifestWatchInputs)
