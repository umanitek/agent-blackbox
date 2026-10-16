"""Operator health — ONE health item for both surfaces (Refine R10, plan §12 alarms).

Every alarm is a :class:`HealthItem`: ``audience`` (operator | curator),
``klass`` (ACTION — do something; SECURITY — something is wrong with trust;
INFO — nothing to do, protection unchanged), ``message`` and ``what_to_do``.
INFO never renders red. The SAME items feed ``blackbox status`` and the
dashboard banner, so the two can never disagree (one Value Object, two views).

Phase 1 states (the plan's operator list, those the code can decide today):
stale node / old ruleset (ACTION), empty ruleset (ACTION), community read
unavailable (INFO), community ingest paused (INFO), curator backlog (INFO), curator key away (INFO), revoked threat
(INFO, + ACTION when it blocked here), statements held by the budget (INFO).
Signing-key revocation, manifest conflicts, minReaderVersion and heartbeat
arrive with reader policy (R7b). The community authority's own alarms
(Community Curation C10) are :mod:`.community_authority`; the manifest watcher
(a new root-signed list, curator heartbeat gaps, renewal reminders —
trust-and-threat-lab W1) is :mod:`.manifest_watch`.

A kernel sub-package (the kernel folder is at its file limit).

Usage::

    items = health.operator_health(health.HealthInputs(...))
    for line in health.render_lines(items): print(line)
"""

from __future__ import annotations

import os
from datetime import date, datetime, timezone, UTC

from .. import constants
# Imported under these names to match inputs.py, where HealthInputs has fields called community_authority
# and manifest_watch.
from . import community_authority as community_alarms
from . import manifest_watch as manifest_watcher
from .inputs import HealthInputs   # the facts the rules read; its own module (this file is at its size limit)
from dataclasses import dataclass
from enum import Enum
from typing import Any, List, Mapping, Optional


class HealthClass(Enum):
    ACTION = "action"
    SECURITY = "security"
    INFO = "info"


@dataclass(frozen=True)
class HealthItem:
    """One alarm. ``klass`` INFO is never rendered red by any surface."""

    audience: str
    klass: HealthClass
    message: str
    what_to_do: str

    def as_dict(self) -> dict:
        return {"audience": self.audience, "class": self.klass.value, "message": self.message, "what_to_do": self.what_to_do}


#: A ruleset older than this many sync intervals is stale.
STALE_INTERVALS = 2.0
#: Curators silent this long → INFO (verified rules still enforce).
CURATOR_SILENCE_DAYS = 14
#: A curator key without a heartbeat this long → INFO (plan §09: >48 h).
HEARTBEAT_SILENCE_DAYS = 2
#: What to do without a DKG node for Blackbox: a Hermes plugin-catalog install brings the plugin
#: only, and `blackbox setup` installs the rest (the same installer curl runs).
NODE_INSTALL_HINT = ("finish the install: hermes blackbox setup — until then the built-in rules "
                     "(protected paths, secrets, Trader Shield) still protect")

_CURATOR = "curator"

_OPERATOR = "operator"


def operator_health(inputs: HealthInputs) -> list[HealthItem]:
    """The operator's alarms for *inputs*, ACTION and SECURITY first."""
    items: list[HealthItem] = []
    items += _node_and_ruleset(inputs)
    items += _wrap(manifest_watcher.alarms(inputs.manifest_watch))
    if inputs.community_configured:
        items += _community(inputs)
        items += _trust(inputs)
        items += _wrap(community_alarms.alarms(inputs.community_authority))
    return sorted(items, key=lambda item: (item.klass is HealthClass.INFO, item.message))


def _wrap(alarms: list[community_alarms.Alarm]) -> list[HealthItem]:
    """A sub-module's (class, message, what to do) tuples as operator items."""
    return [HealthItem(_OPERATOR, HealthClass(klass), message, what_to_do) for klass, message, what_to_do in alarms]


def _version_tuple(text: str) -> tuple:
    return tuple(int(part) for part in text.split(".") if part.isdigit())


def _days_between(earlier: str, later: str) -> int:
    try:
        return (date.fromisoformat(later) - date.fromisoformat(earlier)).days
    except ValueError:
        return 0


def _trust(inputs: HealthInputs) -> list[HealthItem]:
    """R10b: the states about the curators and the trust layer (plan §12)."""
    items = []
    if inputs.curator_trusted and inputs.curators_last_day and inputs.today \
            and _days_between(inputs.curators_last_day, inputs.today) > CURATOR_SILENCE_DAYS:
        items.append(HealthItem(_OPERATOR, HealthClass.INFO, f"curators have not published since {inputs.curators_last_day}",
                                "nothing to do — protection unchanged; verified rules still enforce"))
    if inputs.heartbeat_missing_keys:
        items.append(HealthItem(_OPERATOR, HealthClass.INFO, f"curator heartbeat missing for {inputs.heartbeat_missing_keys} key(s)",
                                "nothing to do — new promotions and appeals may pause; flags and blocks unaffected"))
    if inputs.manifest_conflict:
        items.append(HealthItem(_OPERATOR, HealthClass.SECURITY, "curator key manifest CONFLICT: two trusted manifests disagree",
                                "the graph is frozen at the last trusted version; blocks still enforce — update Blackbox and tell the curators"))
    if inputs.manifest_conflict_ignored:
        items.append(HealthItem(_OPERATOR, HealthClass.SECURITY,
                                "curator key manifest conflict IGNORED: a root-signed list contradicts one this node already acts on",
                                "nothing changes on this node — it keeps the list it acts on; tell the curators a root key may be compromised"))
    if inputs.min_reader_version and _version_tuple(inputs.min_reader_version) > _version_tuple(inputs.my_version):
        items.append(HealthItem(_OPERATOR, HealthClass.ACTION,
                                f"the curators require Blackbox {inputs.min_reader_version}; this node runs {inputs.my_version}",
                                "update Blackbox to read the curators' newer statements; current rules keep enforcing"))
    if inputs.env_mismatch_rows:
        items.append(HealthItem(_OPERATOR, HealthClass.ACTION, f"{inputs.env_mismatch_rows} community row(s) signed for another network or graph",
                                "check the community graph id and the node URL in the Blackbox config"))
    if inputs.future_dated_rows:
        items.append(HealthItem(_OPERATOR, HealthClass.SECURITY, f"{inputs.future_dated_rows} future-dated community row(s) ignored",
                                "nothing to do — a modified client is on the graph; its rows are ignored"))
    if inputs.manifest_state == "stale":
        items.append(HealthItem(_OPERATOR, HealthClass.ACTION, f"curator key manifest STALE since {inputs.manifest_state_day}",
                                "verified rules still block and reductions still apply; new enforcement-raising statements are frozen — update Blackbox or wait for a fresh manifest"))
    if inputs.manifest_state == "pending":
        items.append(HealthItem(_OPERATOR, HealthClass.INFO, f"a new curator key manifest takes effect on {inputs.manifest_state_day} (time-lock)",
                                "nothing to do — the previous manifest stays in force until then"))
    if inputs.manifest_expires_day and inputs.today and 0 <= _days_between(inputs.today, inputs.manifest_expires_day) <= 30:
        items.append(HealthItem(_OPERATOR, HealthClass.INFO, f"the curator key manifest expires on {inputs.manifest_expires_day}",
                                "nothing to do — the curators publish a new manifest; rules keep enforcing either way"))
    if inputs.kill_list_refused:
        items.append(HealthItem(_OPERATOR, HealthClass.SECURITY, f"the newest kill list was refused: {inputs.kill_list_refused}",
                                f"nothing to do — the last-good kill list (v{inputs.kill_list_version}) stays in force; tell the curators"))
    return items


def _node_and_ruleset(inputs: HealthInputs) -> list[HealthItem]:
    if not inputs.node_installed:   # nothing to sync and nothing to restart: the alarms below would mislead
        return [HealthItem(_OPERATOR, HealthClass.ACTION, "Blackbox setup has not run: no DKG node, so the verified "
                           "threat graph is not loaded", NODE_INSTALL_HINT)]
    items = []
    stale = inputs.ruleset_age_s is None or inputs.ruleset_age_s > STALE_INTERVALS * max(1.0, inputs.sync_interval_s)
    if not inputs.node_reachable or stale:
        why = "the DKG node is unreachable" if not inputs.node_reachable else "the local ruleset is old"
        items.append(HealthItem(_OPERATOR, HealthClass.ACTION, f"my node is stale: {why}",
                                "run `blackbox sync --wait`; check the DKG node is running"))
    if inputs.rule_count == 0:
        items.append(HealthItem(_OPERATOR, HealthClass.ACTION, "UNPROTECTED: the threat ruleset is empty",
                                "run `blackbox sync --wait` to load the threat graph"))
    if inputs.verified_lookup_problem:
        items.append(HealthItem(_OPERATOR, HealthClass.ACTION,
                                f"DEGRADED: verified rules cannot be looked up — {inputs.verified_lookup_problem}",
                                "actions pass unchecked by the verified graph; check the DKG node and its store, "
                                "then run `blackbox sync --wait`"))
    if inputs.legacy_list_refused:
        items.append(HealthItem(_OPERATOR, HealthClass.SECURITY, f"legacy asset list refused: {inputs.legacy_list_refused}",
                                "nothing to do — the last-good asset tiers stay in force; reinstall Blackbox from the "
                                "official release and tell the curators"))
    return items


def _community(inputs: HealthInputs) -> list[HealthItem]:
    items = []
    if inputs.read_unavailable_reason:
        items.append(HealthItem(_OPERATOR, HealthClass.INFO, f"community graph could not be read: {inputs.read_unavailable_reason}",
                                "nothing to do — the last good community tier is kept; verified rules still enforce"))
    if inputs.community_paused:
        items.append(HealthItem(_OPERATOR, HealthClass.INFO, "community ingest is paused by the curator",
                                "nothing to do — verified rules still enforce"))
    # No "no trusted curator keys" item: a network without a pinned manifest is the normal state, it asks
    # nothing of the operator and changes no protection, so it is not an alarm (removed 2026-10-12).
    if inputs.backlog:
        items.append(HealthItem(_OPERATOR, HealthClass.INFO, f"curator BACKLOG (lanes {inputs.backlog})",
                                "nothing to do — review times are extended; disputes and revocations still honoured"))
    if inputs.away_keys:
        items.append(HealthItem(_OPERATOR, HealthClass.INFO, f"{inputs.away_keys} curator key(s) away",
                                "nothing to do — new promotions may wait; flags and blocks unaffected"))
    for identifier, blocked in sorted((inputs.revoked or {}).items()):
        klass = HealthClass.ACTION if blocked else HealthClass.INFO
        todo = (f"it blocked {blocked} action(s) on this machine — review those findings; the rule is now withdrawn"
                if blocked else "nothing to do — the rule is withdrawn everywhere")
        items.append(HealthItem(_OPERATOR, klass, f"threat REVOKED by the curator: {identifier}", todo))
    if inputs.held_back:
        items.append(HealthItem(_OPERATOR, HealthClass.INFO, f"{inputs.held_back} community statement(s) held by the per-author daily budget",
                                "nothing to do — a flooding author is being rate-limited by every reader"))
    if inputs.pending_shares:
        items.append(HealthItem(_OPERATOR, HealthClass.INFO,
                                f"{inputs.pending_shares} report(s) waiting for the network to accept this node's writes",
                                "nothing to do — a newly subscribed node is refused for a few minutes; they are retried automatically"))
    if inputs.sharing_consent_problem:
        items.append(HealthItem(_OPERATOR, HealthClass.ACTION, f"`report` is true in the settings but sharing is stopped: {inputs.sharing_consent_problem}",
                                "turn sharing on with `blackbox report --enable-sharing` (or the dashboard toggle), which records your agreement, or set `report: false`"))
    if inputs.shares_given_up:
        items.append(HealthItem(_OPERATOR, HealthClass.ACTION,
                                f"{inputs.shares_given_up} report(s) could not be shared within 24 h",
                                "run `blackbox sync --wait`; check the node is subscribed to the community graph, then `blackbox report --status`"))
    return items


@dataclass(frozen=True)
class CuratorInputs:
    """R10b curator-audience facts (gathered on the curator node): ``lane_depth``
    ({lane number: items}), ``lane_over_sla`` ({lane number: items older than
    the lane's SLA}), ``established_below_floor`` / ``established_total``
    (reputation drift), ``reports_today`` with ``velocity_mean`` and
    ``velocity_sigma`` over the recent days, ``shares_given_up``, and
    ``expiring_keys`` (counted authors whose listing ends within 30 days)."""

    lane_depth: Mapping[int, int] = None  # type: ignore[assignment]
    lane_over_sla: Mapping[int, int] = None  # type: ignore[assignment]
    established_below_floor: int = 0
    established_total: int = 0
    reports_today: int = 0
    velocity_mean: float = 0.0
    velocity_sigma: float = 0.0
    shares_given_up: int = 0
    expiring_keys: int = 0


#: Per-lane review SLA in days (plan §09 tiers: disputes/revocations and blockable-with-evidence first).
LANE_SLA_DAYS = {1: 2, 2: 2, 3: 7, 4: 14, 5: 14}
#: Reputation drift: this share of established reporters under the floor alarms.
DRIFT_SHARE = 0.25


def curator_health(inputs: CuratorInputs) -> list[HealthItem]:
    """The curator-audience alarms (plan §12 'Curator-only'); delivered to the
    curator webhook only, never to an operator surface."""
    items: list[HealthItem] = []
    over = {lane: n for lane, n in (inputs.lane_over_sla or {}).items() if n}
    if over:
        text = ", ".join(f"lane {lane}: {n}" for lane, n in sorted(over.items()))
        items.append(HealthItem(_CURATOR, HealthClass.ACTION, f"queue items beyond their lane SLA ({text})",
                                "review the oldest items first, or publish a BACKLOG notice for the lanes you cannot serve"))
    depth = sum((inputs.lane_depth or {}).values())
    if depth:
        items.append(HealthItem(_CURATOR, HealthClass.INFO, f"queue depth {depth} across {len(inputs.lane_depth or {})} lane(s)", "nothing to do"))
    if inputs.established_total and inputs.established_below_floor / inputs.established_total >= DRIFT_SHARE:
        items.append(HealthItem(_CURATOR, HealthClass.ACTION,
                                f"reputation drift: {inputs.established_below_floor} of {inputs.established_total} established reporters are under the floor",
                                "review the graduation rule and the recent rejections (`curate graduate`)"))
    if inputs.velocity_sigma > 0 and inputs.reports_today > inputs.velocity_mean + 3 * inputs.velocity_sigma:
        items.append(HealthItem(_CURATOR, HealthClass.SECURITY,
                                f"report velocity {inputs.reports_today} today is more than 3σ above the recent mean ({inputs.velocity_mean:.1f})",
                                "look for a flood or a ring before counting anything; consider a PAUSE notice"))
    if inputs.shares_given_up:
        items.append(HealthItem(_CURATOR, HealthClass.ACTION, f"{inputs.shares_given_up} of this node's shares failed after retries",
                                "check the node's subscription to the community graph"))
    if inputs.expiring_keys:
        items.append(HealthItem(_CURATOR, HealthClass.INFO, f"{inputs.expiring_keys} counted-author listing(s) expire within 30 days",
                                "renew with `curate propose --nominate` before they lapse"))
    return sorted(items, key=lambda item: (item.klass is HealthClass.INFO, item.message))


def render_lines(items: list[HealthItem]) -> list[str]:
    """The CLI view: one line per item, class first, what-to-do after a dash."""
    if not items:
        return ["  health:            ok — nothing to do"]
    return [f"  health:            [{item.klass.value.upper()}] {item.message} — {item.what_to_do}" for item in items]


def red(item: HealthItem) -> bool:
    """Whether a surface may render *item* in red: never for INFO."""
    return item.klass is not HealthClass.INFO


def node_installed(cfg: Any, node_reachable: bool) -> bool:
    """Whether this machine has a DKG node for Blackbox: one answers at ``cfg.dkg_url``, or
    Blackbox's own DKG command (``cfg.dkg_bin``) is installed and can start one.

    False after a Hermes plugin-catalog install (the plugin only): ``blackbox sync`` and the
    alarms then say how to install the node instead of waiting on one that is not there.
    """
    return node_reachable or os.path.isfile(os.path.expanduser(str(getattr(cfg, "dkg_bin", "") or "")))


def gather(cfg: Any, rs: Any, node_reachable: bool, read: Optional[Any], blocked_by_identifier: Mapping[str, int],
           now: float, *, pending_shares: int = 0, shares_given_up: int = 0, sharing_consent_problem: str = "",
           verified_lookup_problem: str = "",
           watch: Optional[manifest_watcher.ManifestWatchInputs] = None) -> HealthInputs:
    """Build :class:`HealthInputs` from a config, a compiled ruleset, node
    reachability, the last community read (or None), how many actions each
    threat blocked here (``audit.blocked_counts_by_identifier()``) and the
    share-retry counts (``community.share_retry_stats()``); *watch* is the
    manifest watcher's facts (``manifest_watch.watch_inputs``), None = not watched."""
    view = getattr(read, "curator", None)
    revoked = {ident: int(blocked_by_identifier.get(ident, 0)) for ident in (view.revoked if view is not None else ())}
    kill_list = getattr(rs, "kill_list", None) or {}
    return HealthInputs(
        node_reachable=node_reachable,
        node_installed=node_installed(cfg, node_reachable),
        ruleset_age_s=(now - getattr(rs, "synced_at", 0)) if getattr(rs, "synced_at", 0) else None,
        sync_interval_s=float(getattr(cfg, "sync_interval", 0) or 0),
        rule_count=sum(int(v) for k, v in rs.counts().items() if k != "community"),
        community_configured=bool(getattr(cfg, "context_graph_id", "")),
        community_paused=bool(getattr(rs, "community_paused", False)),
        read_unavailable_reason=("" if read is None or read.available else str(read.reason)),
        curator_trusted=bool(view is not None and view.manifest is not None),
        backlog=(view.backlog.field("lanes") if view is not None and view.backlog else ""),
        away_keys=len(view.away) if view is not None else 0,
        revoked=revoked,
        held_back=int(getattr(read, "held_back", 0) or 0),
        pending_shares=int(pending_shares),
        sharing_consent_problem=sharing_consent_problem if getattr(cfg, "community_enabled", False) else "",
        verified_lookup_problem=verified_lookup_problem,
        shares_given_up=int(shares_given_up),
        curators_last_day=(view.last_statement_day if view is not None else ""),
        today=datetime.fromtimestamp(now, UTC).date().isoformat(),
        heartbeat_missing_keys=_heartbeat_missing(view, now),
        manifest_conflict=bool(view is not None and view.manifest_conflict),
        manifest_conflict_ignored=bool(view is not None and view.manifest_conflict_ignored),
        min_reader_version=(view.manifest.min_reader_version if view is not None and view.manifest is not None else ""),
        my_version=constants.__version__,
        env_mismatch_rows=int(getattr(read, "env_mismatch", 0) or 0),
        future_dated_rows=int(getattr(read, "future_dated", 0) or 0),
        kill_list_version=int(kill_list.get("version", 0) or 0) if isinstance(kill_list, dict) else 0,
        kill_list_refused=str(getattr(rs, "kill_list_refused", "") or ""),
        legacy_list_refused=str(getattr(getattr(rs, "verified_scope", None), "legacy_refused", "") or ""),
        manifest_state=(view.manifest_state if view is not None else ""),
        manifest_state_day=(view.manifest_state_day if view is not None else ""),
        manifest_expires_day=(view.manifest_expires_day if view is not None else ""),
        community_authority=community_alarms.gather(
            getattr(view, "community", None), datetime.fromtimestamp(now, UTC).date().isoformat()),
        manifest_watch=watch or manifest_watcher.ManifestWatchInputs(),
    )


def _heartbeat_missing(view: Any, now: float) -> int:
    """Curator keys in the trusted manifest with no heartbeat inside HEARTBEAT_SILENCE_DAYS."""
    if view is None or view.manifest is None:
        return 0
    today = datetime.fromtimestamp(now, UTC).date().isoformat()
    missing = 0
    for key in view.manifest.curator_keys:
        last = view.heartbeats.get(key, "")
        if not last or _days_between(last, today) > HEARTBEAT_SILENCE_DAYS:
            missing += 1
    return missing


def ruleset_age_text(age_s: Optional[float]) -> str:
    if age_s is None:
        return "never compiled"
    minutes = int(age_s // 60)
    return f"{minutes} min ago" if minutes < 120 else f"{int(age_s // 3600)} h ago"
