"""The community tier of a ruleset: merging community reports in, and making
the matchable ones O(1)-lookup rules.

Owns :func:`apply_community_tier` (called by the refresh cycle after the
verified build, so public rules already hold their keys — public beats
community structurally) and :func:`materialize_community_rules`. Community
rules match by identifier equality only; nothing community-sourced ever
reaches a pattern compile (KI-004). Fail-open at every boundary.

Usage (inside ruleset/): ``community_tier.apply_community_tier(rs, client, cfg, prior)``.
"""

from __future__ import annotations

import logging
import time
from typing import AbstractSet, Any, Dict, Optional, Set

from .. import community
from ..kernel import threat_ids
from ..kernel.config import BlackboxConfig
from ..kernel.dkg_client import DkgClient
from . import compiler, row_adapters

logger = logging.getLogger(__name__)


def apply_community_tier(rs: compiler.Ruleset, client: DkgClient, cfg: BlackboxConfig,
                         prior: Optional[compiler.Ruleset] = None) -> None:
    """Enrich a freshly built ruleset with the community tier. Fail-open.

    Populates ``rs.community`` (the corroboration/display store, keyed by
    identifier literal) and materializes MATCHABLE community rules into the
    ``dependency``/``ioc`` O(1) lookup dicts and the ``skill`` rules —
    identifier-equality matching, never pattern execution (KI-004). Public
    rules always win a key collision (merge precedence).
    Injection/escalation/fileaccess community reports stay
    display-and-corroboration only: their local detections derive the same
    deterministic identifiers, so corroboration works without ever
    interpreting community content.

    *prior* is this node's previous ruleset generation (first-seen history and
    the last-good fallback); the refresh cycle passes it in.
    """
    if not cfg.context_graph_id:
        return
    previous = dict(prior.community) if prior is not None else {}   # captured first: *prior* may be *rs* itself
    try:
        # KI-034: updated existing installs must join without a manual sync —
        # but only when the node says it is not subscribed, and at most once
        # per retry window (R0, KI-064/114; community/membership.py).
        community.ensure_community_subscription(client, cfg)
        # R0c/R0d: only reports whose signature verifies for THIS network and
        # graph are counted; the self-described reporter field never is.
        read = community.read_verified_reports(client, cfg, held=tuple(previous))   # KI-275: ask about what it holds too
        if not read.available:   # could not read is never "no threats" (KI-112): keep last-good
            _keep_last_good(rs, prior)
            return
        withdrawn = _withdrawn(read)
        if (_signed_pause(rs, read) or _legacy_pause(rs, read, client, cfg)
                or _empty_read_not_believed(rs, prior, read, previous, client, cfg)):
            # Paused, or an empty read not yet believed: keep last-good — minus what
            # this read shows was rejected, revoked or retracted, because reductions
            # always get through (KI-275, LES-016).
            _keep_last_good(rs, prior, withdrawn=withdrawn)
            return
        rules = community.aggregate_community_reports(read.reports, _first_seen_history(prior))
        rs.community = {rule.identifier: {**rule.as_rule(), **_stage_fields(rule, read), "networkLive": "yes"}
                        for rule in rules}
        _carry_kept_locally(rs, previous, time.time(), withdrawn=withdrawn)
        if getattr(cfg, "community_shadow", False):   # R15: stages logged, only MONITOR enforced
            community.shadow.clamp_to_monitor(rs.community)
        materialize_community_rules(rs)
    except Exception as exc:  # pragma: no cover - fail open at the tier boundary
        logger.debug("blackbox: community tier skipped: %s", exc)


def _legacy_pause(rs: compiler.Ruleset, read: Any, client: DkgClient, cfg: BlackboxConfig) -> bool:
    """The pre-manifest UNSIGNED pause flag (KI-036) — honoured ONLY while this
    network has no trusted key manifest. The moment a manifest exists, the
    2-of-3 signed pause is the only pause (KI-213: an unsigned flag beside it
    let anyone who writes the verified graph pause ingest indefinitely)."""
    if getattr(read.curator, "manifest", None) is not None:
        return False
    if not community.community_pause_active(client, cfg):
        return False
    logger.warning("blackbox: community ingest PAUSED by the unsigned curator flag (pre-manifest era)")
    rs.community_paused = True
    return True


def _signed_pause(rs: compiler.Ruleset, read: Any) -> bool:
    """A 2-of-3 signed curator PAUSE in force today suppresses ingest (the legacy unsigned flag stays beside it, KI-213)."""
    if not read.curator.pause_active(community.curator_today()):
        return False
    logger.warning("blackbox: community ingest PAUSED by a signed curator pause until %s", read.curator.pause_until)
    rs.community_paused = True
    return True


def _graph_still_has_reports(client: DkgClient, cfg: BlackboxConfig) -> bool:
    """KI-210 (bench 2026-10-02): a catalog replay after a peer reconnect empties the
    shared-memory view for a few minutes while the graph still holds every report; an
    "authorised empty" read in that window must not wipe the tier. One aggregate probe —
    does the graph still count any report? A failed probe answers False (never invent reports)."""
    try:
        if community.community_fingerprint(client, cfg) in (None, ""):
            return False
        logger.warning("blackbox: community read came back empty while the graph still holds reports — transient replay; last-good kept")
        return True
    except Exception:  # pragma: no cover - fail open to the read
        return False


#: KI-262: how long a "no reports" read must persist before this node believes it and
#: clears a tier that still holds threats (a store busy with a flood answered empty for
#: up to 18 minutes on the bench; the pulse re-reads every 20 s, so this is many reads).
EMPTY_READ_WITNESS_SECONDS = 1800.0


def _empty_read_not_believed(rs: compiler.Ruleset, prior: Optional[compiler.Ruleset], read: Any,
                             previous: dict[str, dict[str, Any]], client: DkgClient, cfg: BlackboxConfig) -> bool:
    """KI-210 / KI-262: a read with no reports while this node still holds some is not
    believed at once — a replay window or a timed-out store looks exactly like an empty
    graph. True = keep last-good: the graph still counts reports, or the emptiness has
    not yet lasted ``EMPTY_READ_WITNESS_SECONDS``. A read WITH reports ends the spell.
    (What the read shows was withdrawn is dropped from the kept tier by the caller, KI-275.)"""
    if read.reports:
        rs.community_empty_since = 0.0
        return False
    return _graph_still_has_reports(client, cfg) or not _empty_read_witnessed(rs, prior, time.time())


def _empty_read_witnessed(rs: compiler.Ruleset, prior: Optional[compiler.Ruleset], now: float) -> bool:
    """True once reads have come back empty for ``EMPTY_READ_WITNESS_SECONDS``.
    The first empty read only starts the clock (carried on the ruleset)."""
    since = float(getattr(prior, "community_empty_since", 0.0) or 0.0) or now
    rs.community_empty_since = since
    return now - since >= EMPTY_READ_WITNESS_SECONDS


#: R5 reader persistence: a counted threat whose network copies expired stays
#: in this node's tier this long after it was last read, so a slow-burn threat
#: survives its author's silence on the reader side too (plan §06: ≤90 d).
KEPT_LOCALLY_DAYS = 90
_DAY_SECONDS = 86_400.0


def _withdrawn(read: Any) -> set[str]:
    """Threats the read itself says are gone on purpose: a curator rejection
    or revocation, or a retraction this reader honoured. Their reports are
    left out of the read, so they "vanish" — and a vanished threat must not be
    mistaken for one whose network copies merely expired (KI-275, LES-016:
    reductions always get through)."""
    curator = read.curator
    terminal = {identifier for identifier in curator.verdicts if curator.rejected(identifier)} | set(curator.revoked)
    return terminal | {retraction.identifier for retraction in read.retractions}


def _carry_kept_locally(rs: compiler.Ruleset, previous: dict[str, dict[str, Any]], now: float, *,
                        withdrawn: AbstractSet[str] = frozenset()) -> None:
    """Carry over entries the fresh read no longer has — only threats with at
    least one counted cluster, within their type's lifetime (decay on this
    node's observation time, never the sender's), gone for ≤ KEPT_LOCALLY_DAYS.
    They keep their last stage and are marked ``networkLive: no`` so the
    dashboard shows "kept locally" apart from what the network still carries.
    A threat in *withdrawn* (rejected, revoked or retracted) is never carried:
    it left the network on purpose."""
    for identifier, rule in previous.items():
        if identifier in rs.community or identifier in withdrawn or int(rule.get("counted") or 0) < 1:
            continue
        gone_since = float(rule.get("keptSince") or now)
        first_seen = float(rule.get("firstSeen") or now)
        if now - gone_since > KEPT_LOCALLY_DAYS * _DAY_SECONDS:
            continue
        if now - first_seen > community.lifetime_days(identifier) * _DAY_SECONDS:
            continue
        rs.community[identifier] = {**rule, "networkLive": "no", "keptSince": gone_since}


def reapply_community_tier(rs: compiler.Ruleset, client: DkgClient, cfg: BlackboxConfig) -> None:
    """Refresh the community tier of a ruleset the refresh cycle is REUSING
    (the verified tier came back empty or failed, so last-good is kept).

    Without this the community tier would silently stop refreshing on those
    paths (R0 tri-state: "the community tier refreshes on every verified-tier
    path"). Community entries materialized last time are removed first —
    materializing only ever adds — then the tier is applied as usual, with
    the ruleset itself as the first-seen history and last-good fallback.
    """
    for table in (rs.dependency, rs.ioc):
        for key in [k for k, rule in table.items() if _is_community_entry(rule)]:
            del table[key]
    rs.skill = [rule for rule in rs.skill if rule.get("source") != "community"]
    apply_community_tier(rs, client, cfg, rs)
    rs._graph_entries_cache.clear()


def _is_community_entry(rule: dict[str, Any]) -> bool:
    """True for a rule the community tier materialized — NOT a verified rule
    served flag-only (R4: it shares the ``community`` source but carries
    ``asset_tier: flag``, and only the next full refresh may drop it)."""
    return rule.get("source") == "community" and rule.get("asset_tier") != row_adapters.FLAG_TIER


def _stage_fields(rule: community.CommunityRule, read: community.CommunityRead) -> dict[str, str]:
    """R3: the threat's local stage, from the same inputs every node has —
    its signers, the curator view, counted disputes and the current verdict."""
    dispute_weight = community.counted_dispute_weight(read.disputes, read.curator).get(rule.identifier, 0)
    verdict_record = read.curator.verdicts.get(rule.identifier)
    result = community.stage_for(rule.identifier, rule.authors, rule.first_seen, read.curator, dispute_weight,
                                 read.curator.verdict(rule.identifier), time.time(), dict(rule.fields),
                                 verdict_day=verdict_record.day if verdict_record is not None else "")
    # How many of its reporters are not on the trusted list: the curator's queue
    # shows threats whose confirmation would credit a newcomer (the graduation lane).
    unlisted = sum(1 for author in set(rule.authors) if not read.curator.is_counted(author))
    return {**result.as_fields(), "unlistedReporters": str(unlisted)}


def _first_seen_history(prior: Optional[compiler.Ruleset]) -> dict[str, float]:
    """identifier -> when THIS node first saw it (KI-012: our observation,
    never a reporter-supplied date), carried over from the previous generation."""
    if prior is None:
        return {}
    return {
        ident: float(rule.get("firstSeen", 0) or 0)
        for ident, rule in prior.community.items()
        if rule.get("firstSeen")
    }


def _keep_last_good(rs: compiler.Ruleset, prior: Optional[compiler.Ruleset], *,
                    withdrawn: AbstractSet[str] = frozenset()) -> None:
    """Keep the previous community tier — except the threats in *withdrawn*
    (rejected, revoked or retracted according to a read this node DID make)."""
    if prior is not None and prior.community:
        rs.community = {identifier: rule for identifier, rule in prior.community.items() if identifier not in withdrawn}
        materialize_community_rules(rs)


def materialize_community_rules(rs: compiler.Ruleset) -> None:
    """Copy matchable community rules into the dependency/ioc lookup dicts.

    Only identifier-keyed O(1) structures — nothing community-sourced ever
    reaches a pattern compile or scan list. Public rules keep precedence.
    R3: only rules whose local stage allows FLAG are matchable; MONITOR-level
    ones (unlisted authors only, held, deferred, rejected, revoked, expired)
    stay in the display store and never fire in the hot path.
    """
    for identifier, rule in rs.community.items():
        if rule.get("enforcement") == "monitor":
            continue
        if identifier.startswith("dep:"):
            eco = str(rule.get("packageEcosystem") or "").lower()
            pkg = str(rule.get("packageName") or "").lower()
            ver = str(rule.get("packageVersion") or "")
            if not (eco and pkg and ver):
                try:
                    _, rest = identifier.split(":", 1)
                    eco, tail = rest.split(":", 1)
                    pkg, ver = tail.rsplit("@", 1)
                    eco, pkg = eco.lower(), pkg.lower()
                except ValueError:
                    continue
            key = threat_ids.dependency_key(eco, pkg, ver)
            if key not in rs.dependency:  # public beats community
                rs.dependency[key] = {
                    **rule,
                    "ecosystem": eco,
                    "packageName": pkg,
                    "packageVersion": ver,
                    "advisoryId": "",
                    "kind": rule.get("kind") or None,
                }
        elif identifier.startswith("ioc:"):
            if identifier not in rs.ioc:  # public beats community
                parts = identifier.split(":", 2)
                fallback_type = parts[1] if len(parts) >= 3 else ""
                rs.ioc[identifier] = {**rule, "iocType": str(rule.get("iocType") or fallback_type)}
        elif identifier.startswith("skill:"):
            _materialize_skill(rs, identifier, rule)


def _materialize_skill(rs: compiler.Ruleset, identifier: str, rule: dict[str, Any]) -> None:
    """A FLAG-stage community skill report as a skill rule matched by EXACT
    identifier: a registry skill by its name and version, a local one by its
    code hash and danger shape (the same identifier every node derives from
    the artifact). A skill report without a version is not materialized, and a
    public rule for the same identifier wins."""
    if any(existing.get("identifier") == identifier for existing in rs.skill):
        return
    if identifier.startswith("skill:artifact:"):
        rs.skill.append({**rule, "skillName": "", "skillVersion": ""})   # matched by identifier in detection
        return
    name, _, version = identifier[len("skill:"):].rpartition("@")
    if name and version:
        rs.skill.append({**rule, "skillName": name, "skillVersion": version})


# ---------------------------------------------------------------------------
# The community beat the refresh cycle runs after the tier is applied (moved
# from refresh_cycle, which sat at the file-size alarm): digests, keep-alive,
# shadow metrics. Each is fail-open on its own.
# ---------------------------------------------------------------------------


def record_shadow_metrics(rs: compiler.Ruleset, config: BlackboxConfig) -> None:
    """R15: in the shadow phase every refresh logs the §12 numbers it computed. Fail-open."""
    if not getattr(config, "community_shadow", False):
        return
    try:
        community.shadow.write_snapshot(community.shadow.build_snapshot(rs, time.time()))
    except Exception as exc:  # pragma: no cover - never degrade the refresh
        logger.debug("blackbox: shadow metrics skipped this refresh: %s", exc)


def keep_reports_alive(client: DkgClient, config: BlackboxConfig) -> None:
    """R5: the refresh cycle is the publish step for keep-alive — this node's
    own live reports get this epoch's copy here (when sharing is on). Fail-open."""
    try:
        community.publish_due_copies(client, config)
    except Exception as exc:  # pragma: no cover - never degrade the refresh
        logger.warning("blackbox: keep-alive copies not published this refresh: %s", exc)


def publish_digests(client: DkgClient, config: BlackboxConfig) -> None:
    """R2b: the refresh cycle is the one periodic beat, so a completed week's
    sighting digest leaves here (when sharing is on). Fail-open."""
    try:
        community.publish_due_digests(client, config)
    except Exception as exc:  # pragma: no cover - never degrade the refresh
        logger.warning("blackbox: sighting digest not published this refresh: %s", exc)
