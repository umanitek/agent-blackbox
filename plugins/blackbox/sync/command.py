"""``blackbox sync`` — bring this node's copy of the verified graph up to date.

Drives the local node's catch-up of the verified graph (curator peer first,
generic peers as fallback), joins the community graph, then compiles the
ruleset. ``_cmd_sync_impl`` and ``_catchup_authoritative_vm`` are the two
long functions quality item G4 will turn into an explicit state machine.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import queue
import sys
import threading
import time
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from .. import ruleset
from .. import community
from . import state as sync_state
from ..kernel import constants
from ..kernel.config import BlackboxConfig, load_blackbox_config
from ..kernel.dkg_client import DkgClient, DkgError
from .progress import capture_durable_progress_cursor, read_durable_progress
from ..kernel import display_safety
from . import managed_node, native, direct_preflight
from .catchup_job import _catchup_denied, _catchup_job_id, _catchup_status

logger = logging.getLogger(__name__)
_MAX_EMPTY_PUBLIC_PASSES = 3

def cmd_sync(args: argparse.Namespace) -> int:
    """Run a ruleset sync, translating an interactive cancellation cleanly."""
    try:
        cfg = load_blackbox_config()
        if not direct_preflight.valid(cfg):
            return 2
        if managed_node._uses_managed_dkg(cfg, args):
            return _cmd_sync_with_managed_dkg(cfg, args)
        if getattr(args, "wait", False):
            with managed_node._managed_sync_lock() as acquired:
                if not acquired:
                    print("Blackbox sync is already running; no second transfer was queued.")
                    return 2 if getattr(args, "require_rules", False) else 0
                return native.route(cfg, _cmd_sync_impl)(args)
        return native.route(cfg, _cmd_sync_impl)(args)
    except KeyboardInterrupt:
        try:
            current_transfer = sync_state.read()
            try:
                owns_transfer = int(current_transfer.get("pid") or 0) == os.getpid()
            except (TypeError, ValueError):
                owns_transfer = False
            if current_transfer.get("status") == "running" and owns_transfer:
                sync_state.write(
                    "cancelled",
                    context_graph_id=current_transfer.get("context_graph_id"),
                    graph_peer_id=current_transfer.get("graph_peer_id"),
                    phase=str(current_transfer.get("phase") or "cancelled"),
                    public_entries=int(current_transfer.get("public_entries") or 0),
                    expected_public_entries=int(
                        current_transfer.get("expected_public_entries") or 0
                    ),
                    community_entries=int(current_transfer.get("community_entries") or 0),
                    error="sync cancelled by user",
                )
        except Exception as exc:  # cancellation must never print a traceback
            logger.debug("blackbox: failed to record sync cancellation: %s", exc)
        print("Blackbox sync cancelled.", file=sys.stderr)
        return 130


def _terminal_sync_details(state: Dict[str, Any]) -> Dict[str, Any]:
    return {
        key: value
        for key, value in state.items()
        if key not in {"status", "started_at", "updated_at", "pid"}
    }


def _last_sync_counts(context_graph_id: str = "") -> tuple[int, int]:
    previous = (
        sync_state.read_for_graph(context_graph_id)
        if context_graph_id
        else sync_state.read()
    )
    try:
        public = max(0, int(previous.get("public_entries") or 0))
    except (TypeError, ValueError):
        public = 0
    try:
        community = max(0, int(previous.get("community_entries") or 0))
    except (TypeError, ValueError):
        community = 0
    return public, community


def _complete_local_release_ruleset(
    cfg: BlackboxConfig,
    client: DkgClient,
) -> Optional[ruleset.Ruleset]:
    """Return a fully verified local release snapshot, if already present.

    The DKG source-pinned endpoint can lack an idempotent EOF marker after its
    checkpoint is cleaned up. Check the release's raw VM floor first, then
    rebuild from explicitly confirmed assertion graphs. Both conditions must
    hold, so tentative or legacy Defender-only data cannot bypass recovery.
    """
    try:
        verified_threats = client.threat_count(cfg.context_graph_id)
    except (DkgError, AttributeError, TypeError, ValueError):
        return None
    if verified_threats < constants.DEFAULT_GRAPH_RELEASE_THREAT_FLOOR:
        return None
    try:
        local_rules = ruleset.refresh(cfg, client, force_query=True)
    except ruleset.RulesetRefreshUnavailable:
        return None
    if (
        _ruleset_graph_count(local_rules, "public")
        < constants.DEFAULT_GRAPH_RELEASE_RULE_FLOOR
    ):
        return None
    return local_rules


def _cmd_sync_with_managed_dkg(cfg: BlackboxConfig, args: argparse.Namespace) -> int:
    """Run foreground recovery while leaving native reconciliation resumable.

    A running steady-state node may already be advancing a durable checkpoint.
    Do not restart it merely to reserve the single sync slot: the pinned request
    can wait behind that work, while the existing transfer keeps making progress.
    A restart is required only to repair an unreachable node or an installation
    left in the obsolete bootstrap-only mode by an interrupted older command.
    """
    with managed_node._managed_sync_lock() as acquired:
        if not acquired:
            print("Blackbox sync is already running; no second transfer was queued.")
            return 2 if getattr(args, "require_rules", False) else 0

        known_public, known_community = _last_sync_counts(cfg.context_graph_id)
        sync_state.write(
            "running",
            context_graph_id=cfg.context_graph_id,
            graph_peer_id=cfg.graph_peer_id,
            phase="preparing-managed-sync",
            public_entries=known_public,
            community_entries=known_community,
        )
        terminal_state: Dict[str, Any] = {}
        profile_changed = managed_node._set_persisted_dkg_sync_state(cfg)
        if profile_changed or not managed_node._managed_dkg_sync_mode_matches(
            cfg, managed_node.expected_node_settings(cfg)
        ):
            managed_node._restart_managed_dkg(cfg)
        result = native.route(cfg, _cmd_sync_impl)(args)
        terminal_state = sync_state.read_for_graph(cfg.context_graph_id)
        status = str(terminal_state.get("status") or "")
        if status == "running" or not status:
            status = "done" if result == 0 else "failed"
        final_details = _terminal_sync_details(terminal_state)
        if status == "failed" and not final_details.get("error"):
            final_details["error"] = "required threat graph sync did not complete"
        sync_state.write(status, **final_details)
        return result


def _cmd_sync_impl(args: argparse.Namespace) -> int:
    cfg = load_blackbox_config()
    client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    private_graph = _should_request_private_join(cfg)
    release_graph = cfg.context_graph_id == constants.DEFAULT_CONTEXT_GRAPH_ID
    managed_graph = private_graph or release_graph
    authoritative_available = bool(
        cfg.graph_peer_id and callable(getattr(client, "catchup_from_peer", None))
    )
    admitted = not private_graph
    pending_approval = private_graph
    # The pinned curator remains the preferred foreground source, but the DKG
    # subscription is still persisted below. That durable subscription is what
    # lets DKG continue reconciling after this command exits or the node restarts.
    subscribed = False
    catchup_restarted = False
    baseline_catchup_known = False
    baseline_catchup_job_id = ""
    fresh_catchup_seen = False
    fresh_catchup_job_id = ""
    refreshed_catchup_job_id = ""
    catchup_retry_attempts = 0
    next_catchup_retry_at = 0.0
    authoritative_attempted = False
    authoritative_recovered = False
    authoritative_cache_refreshed = False
    authoritative_complete = False
    authoritative_target = 0
    sync_complete = False
    last_join_attempt = float("-inf")
    deadline = time.monotonic() + max(1, int(getattr(args, "timeout", 180) or 180))
    track_sync = bool(getattr(args, "wait", False))

    if (
        release_graph
        and getattr(args, "wait", False)
        and getattr(args, "require_rules", False)
        and not authoritative_available
    ):
        print("  Required curator-pinned VM recovery is unavailable in this DKG build.")
        return 2

    if track_sync:
        known_public, known_community = _last_sync_counts(cfg.context_graph_id)
        sync_state.write(
            "running",
            context_graph_id=cfg.context_graph_id,
            graph_peer_id=cfg.graph_peer_id,
            phase="joining" if private_graph else "network-catchup",
            public_entries=known_public,
            community_entries=known_community,
        )

    agent_address = ""
    try:
        identity = client.agent_identity()
        agent_address = str(identity.get("agentAddress") or "")
    except (DkgError, AttributeError):
        pass

    if getattr(args, "wait", False):
        try:
            baseline_catchup = client.catchup_status(cfg.context_graph_id)
            baseline_catchup_known = True
            baseline_catchup_job_id = _catchup_job_id(baseline_catchup)
        except (DkgError, AttributeError):
            pass

    if private_graph:
        status, admitted = _request_join(client, cfg.context_graph_id, cfg.graph_peer_id)
        pending_approval = not admitted
        last_join_attempt = time.monotonic()
        if status:
            print(status)

    rs = ruleset.Ruleset()
    public_count = 0
    community_count = 0
    initial_rules_ready = False
    attempt = 0
    last_subscribe_error = ""
    last_catchup: Dict[str, Any] = {}

    if release_graph and getattr(args, "wait", False):
        local_release = _complete_local_release_ruleset(cfg, client)
        if local_release is not None:
            rs = local_release
            counts = rs.counts()
            public_count = _ruleset_graph_count(rs, "public")
            initial_rules_ready = public_count > 0
            authoritative_attempted = True
            authoritative_recovered = True
            authoritative_cache_refreshed = True
            authoritative_complete = initial_rules_ready
            authoritative_target = public_count
            print(
                "Local confirmed VM already contains the complete "
                f"release ({public_count:,} enforceable threats)."
            )

    def _record_verified_pass(_inserted_triples: int) -> None:
        """Publish only locally committed threat counts between DKG passes."""
        nonlocal rs, public_count, authoritative_target, initial_rules_ready
        previous_public = public_count
        became_ready = False
        count_threats = getattr(client, "threat_count", None)
        if callable(count_threats):
            public_count = max(public_count, int(count_threats(cfg.context_graph_id) or 0))
        if public_count > 0 and not initial_rules_ready:
            # The DKG request has settled and its atomic store commit is now
            # queryable. Build one partial verified cache before announcing
            # readiness so an installer can safely open a useful dashboard
            # while the same single-flight transfer continues.
            try:
                partial_rules = ruleset.refresh(cfg, client)
            except Exception as exc:
                logger.debug("blackbox: initial verified rules cache is not ready: %s", exc)
            else:
                cached_public = _ruleset_graph_count(partial_rules, "public")
                if cached_public > 0:
                    rs = partial_rules
                    public_count = max(public_count, cached_public)
                    initial_rules_ready = True
                    became_ready = True
        authoritative_target = max(authoritative_target, public_count)
        sync_state.write(
            "running",
            context_graph_id=cfg.context_graph_id,
            graph_peer_id=cfg.graph_peer_id,
            phase="recovering-verifiable-memory",
            public_entries=public_count,
            community_entries=community_count,
        )
        if initial_rules_ready and (public_count != previous_public or became_ready):
            print(f"  {public_count:,} verified threats ready")

    while True:
        now = time.monotonic()
        if (
            private_graph
            and not admitted
            and getattr(args, "wait", False)
            and now - last_join_attempt >= 10.0
        ):
            status, curator_confirmed = _request_join(
                client, cfg.context_graph_id, cfg.graph_peer_id
            )
            admitted = admitted or curator_confirmed
            if curator_confirmed:
                pending_approval = False
            last_join_attempt = time.monotonic()
            if status and attempt % 10 == 0:
                print(status)

        # The release graph has one known complete source peer. A fresh node
        # asks it first instead of downloading unrelated durable graphs from
        # every generic peer and only falling back minutes later.
        # If the direct path fails, the ordinary subscription/catch-up path
        # below remains available for compatibility and recovery.
        if (
            release_graph
            and getattr(args, "wait", False)
            and authoritative_available
            and not authoritative_attempted
        ):
            authoritative_attempted = True
            authoritative_recovered = _catchup_authoritative_vm(
                client,
                cfg.context_graph_id,
                cfg.graph_peer_id,
                deadline,
                on_progress=_record_verified_pass,
            )
            if not authoritative_recovered and getattr(args, "require_rules", False):
                print(
                    "  Foreground curator recovery did not complete; "
                    "persisting the DKG subscription for native reconciliation."
                )
            # Successful DKG passes already refreshed the verified cache via
            # ``_record_verified_pass``. If the pinned source failed before a
            # pass settled, do not launch a competing full-store query merely
            # to decide whether to persist the background subscription.
            if authoritative_recovered:
                try:
                    rs = ruleset.refresh(cfg, client, force_query=True)
                except ruleset.RulesetRefreshUnavailable:
                    rs = ruleset.peek(cfg)
                else:
                    authoritative_cache_refreshed = True
            else:
                rs = ruleset.peek(cfg)
            counts = rs.counts()
            cached_public = _ruleset_graph_count(rs, "public")
            public_count = (
                cached_public
                if authoritative_cache_refreshed
                else max(public_count, cached_public)
            )
            community_count = _ruleset_graph_count(rs, "community")
            authoritative_target = (
                public_count
                if authoritative_cache_refreshed
                else max(authoritative_target, public_count)
            )
            if authoritative_recovered:
                # The pinned pass established a complete foreground snapshot.
                # Still flow through the subscription call below so that DKG
                # owns future updates and restart-safe reconciliation.
                fresh_catchup_seen = True
                authoritative_complete = (
                    authoritative_cache_refreshed
                    and authoritative_target > 0
                    and public_count >= authoritative_target
                )

        may_probe_private = private_graph and not getattr(args, "wait", False)
        # Community graph rides the same sync: idempotent, fail-open, never
        # blocks or fails the verified-graph transfer (B4).
        if cfg.community_graph_id:
            community.ensure_community_subscription(client, cfg)
        if not subscribed and (admitted or not private_graph or may_probe_private):
            try:
                subscription = client.subscribe_context_graph(cfg.context_graph_id)
                subscribed = True
                subscription_job_id = _catchup_job_id(subscription)
                if subscription_job_id and (
                    not baseline_catchup_known
                    or subscription_job_id != baseline_catchup_job_id
                ):
                    fresh_catchup_seen = True
                    fresh_catchup_job_id = subscription_job_id
                if not private_graph:
                    admitted = True
                    pending_approval = False
                if private_graph:
                    if track_sync:
                        sync_state.write(
                            "running",
                            context_graph_id=cfg.context_graph_id,
                            graph_peer_id=cfg.graph_peer_id,
                            phase="network-catchup",
                            public_entries=public_count,
                            community_entries=community_count,
                        )
                    print(
                        f"Requested subscription to {cfg.context_graph_id}; "
                        "verifying private-graph catch-up authorization."
                    )
                else:
                    print(f"Subscribed to {cfg.context_graph_id}; DKG catch-up started.")
            except DkgError as exc:
                last_subscribe_error = str(exc)
                if not private_graph:
                    print(f"warning: could not subscribe to {cfg.context_graph_id}: {exc}")

        catchup_state = ""
        catchup_includes_swm = False
        catchup_job_id = ""
        exact_job_status = False
        if getattr(args, "wait", False) and subscribed:
            try:
                catchup, exact_job_status = _catchup_status(
                    client,
                    cfg.context_graph_id,
                    fresh_catchup_job_id,
                )
                last_catchup = catchup
                catchup_state = str(catchup.get("status") or "").lower()
                catchup_includes_swm = catchup.get("includeSharedMemory") is True
                catchup_job_id = _catchup_job_id(catchup)
                if catchup_job_id and (
                    not baseline_catchup_known
                    or catchup_job_id != baseline_catchup_job_id
                ):
                    fresh_catchup_seen = True
                    if not fresh_catchup_job_id or not exact_job_status:
                        fresh_catchup_job_id = catchup_job_id
                if _catchup_denied(catchup):
                    pending_approval = True
                    admitted = False
            except DkgError:
                pass
        retryable_catchup = (
            not authoritative_recovered
            and getattr(args, "wait", False)
            and subscribed
            and (catchup_restarted or fresh_catchup_seen)
            and catchup_state in {"deferred", "unreachable"}
        )
        if retryable_catchup and now >= next_catchup_retry_at and now < deadline:
            catchup_retry_attempts += 1
            next_catchup_retry_at = now + min(
                10.0,
                float(2 ** min(catchup_retry_attempts - 1, 3)),
            )
            try:
                replacement = client.subscribe_context_graph(cfg.context_graph_id)
                replacement_job_id = _catchup_job_id(replacement)
                fresh_catchup_seen = True
                fresh_catchup_job_id = replacement_job_id
                last_catchup = replacement if isinstance(replacement, dict) else {}
                print(
                    "Retrying DKG catch-up after "
                    f"{catchup_state} state (attempt {catchup_retry_attempts})."
                )
                continue
            except DkgError as exc:
                last_subscribe_error = str(exc)
        fresh_job_complete = catchup_state == "done" and (
            exact_job_status
            or not fresh_catchup_job_id
            or catchup_job_id == fresh_catchup_job_id
        )
        barrier_job_id = catchup_job_id or fresh_catchup_job_id or "<unscoped>"
        catchup_pending = not authoritative_recovered and (
            catchup_state in {"queued", "running"}
            or (
                getattr(args, "wait", False)
                and (catchup_restarted or fresh_catchup_seen)
                and not fresh_job_complete
                and catchup_state not in {"failed", "cancelled", "denied"}
            )
        )
        catchup_failed = (
            not authoritative_recovered
            and (catchup_restarted or fresh_catchup_seen)
            and catchup_state in {"failed", "cancelled", "denied"}
        )
        if subscribed:
            if catchup_pending or catchup_failed:
                # DKG applies durable catch-up atomically. A full VM query here
                # cannot expose useful partial rules and competes with the
                # Blazegraph write that must finish first. Poll only the cheap
                # job status until the transfer reaches a terminal state.
                rs = ruleset.peek(cfg)
            else:
                force_catchup_query = (
                    fresh_job_complete
                    and barrier_job_id != refreshed_catchup_job_id
                )
                force_authoritative_query = (
                    authoritative_recovered
                    and not authoritative_cache_refreshed
                )
                force_query = force_catchup_query or force_authoritative_query
                try:
                    rs = ruleset.refresh(cfg, client, force_query=force_query)
                except ruleset.RulesetRefreshUnavailable:
                    rs = ruleset.peek(cfg)
                else:
                    if force_catchup_query:
                        refreshed_catchup_job_id = barrier_job_id
                    if force_authoritative_query:
                        authoritative_cache_refreshed = True
        counts = rs.counts()
        public_count = _ruleset_graph_count(rs, "public")
        community_count = _ruleset_graph_count(rs, "community")

        if (
            managed_graph
            and subscribed
            and not release_graph
            and not catchup_restarted
            and (
                catchup_includes_swm
                or (not fresh_catchup_seen and catchup_state == "done")
            )
            and not (
                authoritative_available
                and getattr(args, "wait", False)
                and public_count > 0
            )
        ):
            try:
                client.restart_context_graph_catchup(cfg.context_graph_id)
                catchup_restarted = True
                if catchup_includes_swm:
                    print("Replaced a legacy SWM catch-up with VM-only sync.")
                elif private_graph:
                    print("Restarted DKG catch-up after approval; waiting for threat rows.")
                else:
                    print("Restarted DKG catch-up; waiting for public threat rows.")
                if getattr(args, "wait", False):
                    continue
            except DkgError as exc:
                logger.debug("blackbox: catch-up restart failed: %s", exc)

        # A terminal generic catch-up is not success by itself.  A completed,
        # idempotent source-pinned recovery is: it has independently
        # verified the durable VM snapshot and may satisfy this gate on the
        # following loop iteration.
        authoritative_fallback_ready = (
            authoritative_recovered and authoritative_cache_refreshed
        )
        catchup_active = catchup_state in {"queued", "running"}
        catchup_cache_refreshed = (
            not fresh_job_complete
            or refreshed_catchup_job_id == barrier_job_id
        )
        fresh_catchup_complete = authoritative_fallback_ready or (
            not getattr(args, "wait", False)
            or (
                not catchup_active
                and catchup_cache_refreshed
                and (
                    not (catchup_restarted or fresh_catchup_seen)
                    or fresh_job_complete
                )
            )
        )
        base_sync_complete = public_count > 0 and fresh_catchup_complete
        # A clean local store has no public rows yet.  Waiting for
        # ``base_sync_complete`` before contacting the configured release
        # source deadlocks that exact first-sync case when generic peers do
        # not hold the graph.  Once the release graph is subscribed, pin the
        # authoritative source immediately; the recovery helper already
        # waits through DKG backpressure and verifies completion atomically.
        authoritative_recovery_ready = base_sync_complete or release_graph
        if (
            authoritative_recovery_ready
            and managed_graph
            and getattr(args, "wait", False)
            and authoritative_available
            and not authoritative_attempted
        ):
            authoritative_attempted = True
            authoritative_recovered = _catchup_authoritative_vm(
                client,
                cfg.context_graph_id,
                cfg.graph_peer_id,
                deadline,
                on_progress=_record_verified_pass,
            )
            if authoritative_recovered:
                try:
                    rs = ruleset.refresh(cfg, client, force_query=True)
                except ruleset.RulesetRefreshUnavailable:
                    rs = ruleset.peek(cfg)
                else:
                    authoritative_cache_refreshed = True
            else:
                rs = ruleset.refresh(cfg, client)
            counts = rs.counts()
            cached_public = _ruleset_graph_count(rs, "public")
            public_count = (
                cached_public
                if authoritative_cache_refreshed
                else max(public_count, cached_public)
            )
            community_count = _ruleset_graph_count(rs, "community")
            authoritative_target = (
                public_count
                if authoritative_cache_refreshed
                else max(authoritative_target, public_count)
            )
        if authoritative_recovered and public_count > authoritative_target:
            authoritative_target = public_count
        if authoritative_recovered:
            authoritative_complete = (
                authoritative_cache_refreshed
                and authoritative_target > 0
                and public_count >= authoritative_target
            )
            if authoritative_target <= 0:
                error = "authoritative VM returned no public threat entries"
                sync_state.write(
                    "failed",
                    context_graph_id=cfg.context_graph_id,
                    graph_peer_id=cfg.graph_peer_id,
                    phase="empty-verifiable-memory",
                    public_entries=0,
                    expected_public_entries=0,
                    community_entries=community_count,
                    error=error,
                )
                print(
                    "  authoritative VM returned zero public threat entries; "
                    "the required ruleset is unavailable."
                )
                break
        subscription_ready = subscribed
        sync_complete = (
            base_sync_complete
            and (not authoritative_attempted or authoritative_complete)
            and subscription_ready
        )
        if authoritative_recovered and not sync_complete:
            sync_state.write(
                "running",
                context_graph_id=cfg.context_graph_id,
                graph_peer_id=cfg.graph_peer_id,
                phase=(
                    "persisting-subscription"
                    if not subscription_ready
                    else (
                        "refreshing-verifiable-memory"
                        if not authoritative_complete
                        else "network-catchup"
                    )
                ),
                public_entries=public_count,
                expected_public_entries=authoritative_target,
                community_entries=community_count,
            )
        if sync_complete:
            break
        if (
            not authoritative_recovered
            and (catchup_restarted or fresh_catchup_seen)
            and catchup_state in {
                "failed", "cancelled", "denied"
            }
        ):
            break

        now = time.monotonic()
        if not getattr(args, "wait", False) or now >= deadline:
            if not subscribed:
                error = "required DKG subscription could not be persisted"
                if last_subscribe_error:
                    error = f"{error}: {last_subscribe_error}"
                sync_state.write(
                    "failed",
                    context_graph_id=cfg.context_graph_id,
                    graph_peer_id=cfg.graph_peer_id,
                    phase="persisting-subscription",
                    public_entries=public_count,
                    expected_public_entries=authoritative_target or public_count,
                    community_entries=community_count,
                    error=error,
                )
            elif authoritative_recovered and not authoritative_complete:
                sync_state.write(
                    "failed",
                    context_graph_id=cfg.context_graph_id,
                    graph_peer_id=cfg.graph_peer_id,
                    phase="refreshing-verifiable-memory",
                    public_entries=public_count,
                    expected_public_entries=authoritative_target,
                    community_entries=community_count,
                    error="public VM reconciliation deadline reached",
                )
            break
        attempt += 1
        if attempt == 1 or attempt % 10 == 0:
            if private_graph and pending_approval:
                suffix = f" for agent {agent_address}" if agent_address else ""
                print(f"Waiting for private graph membership confirmation{suffix}...")
            elif authoritative_recovered and not authoritative_complete:
                print(
                    "Waiting for public VM reconciliation "
                    f"({public_count:,}/{authoritative_target:,} entries)..."
                )
            else:
                state = catchup_state or "syncing"
                print(f"Waiting for DKG catch-up ({state})...")
        time.sleep(min(3.0, max(0.2, deadline - now)))

    if track_sync:
        current_transfer = sync_state.read_for_graph(cfg.context_graph_id)
        if sync_complete:
            sync_state.write(
                "done",
                context_graph_id=cfg.context_graph_id,
                graph_peer_id=cfg.graph_peer_id,
                phase="complete",
                public_entries=public_count,
                expected_public_entries=authoritative_target or public_count,
                community_entries=community_count,
            )
        elif current_transfer.get("status") == "running":
            sync_state.write(
                "failed",
                context_graph_id=cfg.context_graph_id,
                graph_peer_id=cfg.graph_peer_id,
                phase=str(current_transfer.get("phase") or "network-catchup"),
                public_entries=public_count,
                community_entries=community_count,
                error="required threat graph sync did not complete before the deadline",
            )

    print(f"Ruleset synced from {cfg.context_graph_id}:")
    print(f"  {counts['injection']} injection, {counts['escalation']} escalation, "
          f"{counts['dependency']} dependency")
    print(f"  {public_count:,} public VM (curated)")
    if cfg.community_graph_id:
        print(f"  Community graph: {display_safety.term_safe(cfg.community_graph_id)} "
              f"[sharing {'on' if cfg.community_enabled else 'off'}]")
    else:
        print("  Community graph: not configured (community sharing dormant)")
    if not sync_complete:
        if private_graph and (pending_approval or not subscribed):
            print("  This graph is not supported; Agent Blackbox only uses its public VM graph.")
            if agent_address:
                print(f"  Ask the curator to approve agent address: {agent_address}")
            if last_subscribe_error:
                logger.debug("blackbox: subscribe pending: %s", last_subscribe_error)
            if _catchup_denied(last_catchup):
                print("  DKG catch-up is denied until the curator confirms this node.")
        elif not subscribed:
            print("  Required public VM subscription could not be persisted.")
            if last_subscribe_error:
                print(f"  DKG subscription error: {last_subscribe_error}")
            print("  Retry with `hermes blackbox sync --wait`.")
        elif (catchup_restarted or fresh_catchup_seen) and str(
            last_catchup.get("status") or ""
        ).lower() in {
            "failed", "cancelled", "denied"
        }:
            detail = last_catchup.get("error") or (last_catchup.get("result") or {}).get("error")
            print(f"  Fresh DKG catch-up failed{f': {detail}' if detail else '.'}")
        elif authoritative_attempted and authoritative_target == 0:
            print("  The authoritative curator VM returned zero public threat entries.")
            print("  No rules are available to protect this node.")
        elif authoritative_attempted and not authoritative_complete:
            print("  Authoritative curator VM transfer is incomplete.")
            print("  Retry with `hermes blackbox sync --wait`.")
        else:
            print("  0 rules — DKG has not made curated VM threat rows queryable yet.")
            print("  Retry with `hermes blackbox sync --wait`.")
        if getattr(args, "require_rules", False):
            print("  Required ruleset sync is incomplete.")
            return 2
    return 0


def _ruleset_graph_count(rs: Any, source: str) -> int:
    for name in ("graph_count", "source_count"):
        counter = getattr(rs, name, None)
        if callable(counter):
            return int(counter(source) or 0)
    return sum(int(value or 0) for value in rs.counts().values())


def _catchup_authoritative_vm(
    client: DkgClient,
    context_graph_id: str,
    graph_peer_id: str,
    deadline: float,
    *,
    on_progress: Optional[Callable[[int], None]] = None,
) -> bool:
    """Recover and verify the public graph's durable VM snapshot."""
    catchup = getattr(client, "catchup_from_peer", None)
    if not callable(catchup) or not graph_peer_id:
        return False
    sync_state.write(
        "running",
        context_graph_id=context_graph_id,
        graph_peer_id=graph_peer_id,
        phase="recovering-verifiable-memory",
    )
    print("Syncing the complete verifiable VM snapshot...")
    backpressure_notice_printed = False
    backpressure_retries = 0
    empty_public_passes = 0
    incomplete_empty_passes = 0
    last_incomplete_safe_current: Optional[int] = None
    heartbeat_seconds = 10.0

    try:
        _connect_verifiable_source(
            client,
            context_graph_id,
            graph_peer_id,
            deadline,
        )
    except DkgError as exc:
        error = f"verifiable graph source is unreachable: {exc}"
        sync_state.write(
            "failed",
            context_graph_id=context_graph_id,
            graph_peer_id=graph_peer_id,
            error=error,
        )
        print(f"  {error}")
        return False

    # Legacy DKG builds report durable completion only in daemon.log. Bound
    # that compatibility signal to this recovery invocation so a completed
    # transfer from an earlier command cannot satisfy a new request.
    progress_cursor = capture_durable_progress_cursor(
        str(getattr(client, "dkg_home", "") or "")
    )

    # DKG authenticates the configured graph id against its on-chain name-hash
    # commitment. Request that graph directly instead of making VM availability
    # depend on a separately materialized ontology graph.
    public_progress_seen = False

    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 1:
            sync_state.write(
                "failed",
                context_graph_id=context_graph_id,
                graph_peer_id=graph_peer_id,
                error="authoritative sync deadline reached",
            )
            return False
        pass_budget_ms = (
            constants.DEFAULT_GRAPH_SYNC_PASS_BUDGET_MS
            if public_progress_seen
            else constants.INITIAL_GRAPH_SYNC_PASS_BUDGET_MS
        )
        budget_ms = max(
            1_000,
            min(
                pass_budget_ms,
                int(max(1.0, remaining - 10) * 1_000),
            ),
        )
        request_still_active = False
        try:
            # The DKG endpoint is synchronous and its final verification/store
            # phase can outlive a socket inactivity timeout. Run it behind a
            # daemon-thread wall-clock guard so a misbehaving daemon cannot pin
            # a fresh install forever. Polling also gives operators visible
            # proof of life while the request is legitimately busy.
            outcome: "queue.Queue[tuple[str, Any]]" = queue.Queue(maxsize=1)

            def _recover() -> None:
                try:
                    outcome.put(("ok", catchup(
                        context_graph_id,
                        graph_peer_id,
                        budget_ms=budget_ms,
                    )))
                except BaseException as exc:  # delivered back to the caller
                    outcome.put(("error", exc))

            worker = threading.Thread(
                target=_recover,
                name="blackbox-curator-vm-recovery",
                daemon=True,
            )
            worker.start()
            request_started = time.monotonic()
            request_deadline = min(
                deadline,
                request_started
                + max(
                    (budget_ms / 1_000) + 60.0,
                    constants.GRAPH_SYNC_SETTLEMENT_TIMEOUT_S
                    + constants.GRAPH_SYNC_WATCHDOG_HEADROOM_S,
                ),
            )
            request_timeout_seconds = max(
                1,
                int(request_deadline - request_started),
            )
            heartbeat = 0
            while True:
                wait_for = min(
                    heartbeat_seconds,
                    max(0.0, request_deadline - time.monotonic()),
                )
                if wait_for <= 0:
                    request_still_active = worker.is_alive()
                    raise DkgError(
                        "verifiable VM sync watchdog reached its "
                        f"{request_timeout_seconds}s settlement deadline"
                        + (
                            " while the DKG request remains active"
                            if request_still_active
                            else ""
                        )
                    )
                try:
                    outcome_kind, outcome_value = outcome.get(timeout=wait_for)
                    break
                except queue.Empty:
                    heartbeat += 1
                    elapsed = int(heartbeat * heartbeat_seconds)
                    print(
                        f"  verifiable VM sync is still active "
                        f"({elapsed}s elapsed)...",
                        flush=True,
                    )
                    sync_state.write(
                        "running",
                        context_graph_id=context_graph_id,
                        graph_peer_id=graph_peer_id,
                        phase="recovering-verifiable-memory",
                    )
            if outcome_kind == "error":
                raise outcome_value
            result = outcome_value
        except DkgError as exc:
            error = str(exc)
            normalized_error = error.lower()
            compact_error = "".join(normalized_error.split())
            retryable = not request_still_active and (
                '"retryable":true' in compact_error
                or any(
                    marker in normalized_error
                    for marker in (
                        "backpressure",
                        "store scheduler",
                        "queue wait timeout",
                        "queue wait exceeded",
                        "request aborted",
                        "timed out",
                        "exceeded its",
                        "totaltimeoutms",
                        # A node restart window (~20-40s) is transient: the
                        # API refuses connections, or a fronting proxy
                        # answers 502. Retrying within the deadline beats
                        # failing the whole sync and leaving the ruleset
                        # stale until the next hourly run (KI-065).
                        "connection refused",
                        "connection reset",
                        "upstream node unreachable",
                    )
                )
            )
            if retryable and deadline - time.monotonic() > 4:
                backpressure_retries += 1
                sync_state.write(
                    "running",
                    context_graph_id=context_graph_id,
                    graph_peer_id=graph_peer_id,
                    phase="waiting-for-dkg-capacity",
                )
                if not backpressure_notice_printed:
                    print("DKG graph sync is pausing briefly before a safe resume...")
                    backpressure_notice_printed = True
                retry_delay = min(
                    constants.GRAPH_SYNC_RETRY_BACKOFF_MAX_S,
                    constants.GRAPH_SYNC_RETRY_BACKOFF_INITIAL_S
                    * (2 ** min(backpressure_retries - 1, 4)),
                )
                time.sleep(
                    min(retry_delay, max(0.2, deadline - time.monotonic()))
                )
                continue
            sync_state.write(
                "failed",
                context_graph_id=context_graph_id,
                graph_peer_id=graph_peer_id,
                error=error,
            )
            logger.debug("blackbox: verifiable graph recovery failed: %s", exc)
            return False
        results = result.get("results") if isinstance(result, dict) else None
        peer_result = next(
            (
                item
                for item in (results or [])
                if isinstance(item, dict)
                and str(item.get("peerId") or "") == graph_peer_id
            ),
            None,
        )
        peer_error = ""
        if isinstance(peer_result, dict):
            peer_error = str(
                peer_result.get("durableError")
                or peer_result.get("error")
                or peer_result.get("errors")
                or ""
            )
        explicit_incomplete = bool(
            isinstance(result, dict)
            and result.get("durableComplete") is False
            and result.get("retryable") is True
            and str(result.get("errorCode") or "")
            == "DURABLE_CATCHUP_INCOMPLETE"
        )
        attempted = bool(
            isinstance(result, dict)
            and (result.get("ok") is True or explicit_incomplete)
            and result.get("includeDurable") is True
            and result.get("includeSharedMemory") is False
            and int(result.get("peersAttempted") or 0) >= 1
            and isinstance(peer_result, dict)
            and not peer_error
        )
        if not attempted:
            error = str(
                (result or {}).get("error")
                or peer_error
                or "graph source did not accept durable VM recovery"
            )
            sync_state.write(
                "failed",
                context_graph_id=context_graph_id,
                graph_peer_id=graph_peer_id,
                error=error,
            )
            logger.debug("blackbox: graph source did not attempt VM recovery: %s", error)
            return False
        backpressure_retries = 0
        inserted = int(result.get("totalDurableInsertedTriples") or 0)
        durable_progress = read_durable_progress(
            str(getattr(client, "dkg_home", "") or ""),
            context_graph_id,
            after=progress_cursor,
        )
        # Newer DKG releases report the request's completion contract directly.
        # Retain daemon-log parsing as a compatibility fallback for 10.0.9.
        if result.get("durableComplete") is True:
            durable_progress["snapshot_complete"] = True
        elif result.get("durableComplete") is False:
            durable_progress["snapshot_complete"] = False
        sync_state.write(
            "running",
            context_graph_id=context_graph_id,
            graph_peer_id=graph_peer_id,
            phase=(
                "recovering-verifiable-memory"
                if inserted > 0
                else "refreshing-verifiable-memory"
            ),
            inserted_durable_triples=inserted,
            **durable_progress,
        )
        durable_progress = read_durable_progress(
            str(getattr(client, "dkg_home", "") or ""),
            context_graph_id,
        )
        if inserted <= 0:
            expected = int(durable_progress.get("expected_triples") or 0)
            safe_current = int(durable_progress.get("safe_current_triples") or 0)
            if expected > 0 and safe_current < expected:
                public_progress_seen = public_progress_seen or safe_current > 0
                if (
                    last_incomplete_safe_current is None
                    or safe_current > last_incomplete_safe_current
                ):
                    incomplete_empty_passes = 1
                else:
                    incomplete_empty_passes += 1
                last_incomplete_safe_current = safe_current
                if incomplete_empty_passes >= _MAX_EMPTY_PUBLIC_PASSES:
                    error = (
                        "public VM manifest made no durable progress after "
                        f"{incomplete_empty_passes} pinned passes "
                        f"({safe_current:,}/{expected:,})"
                    )
                    sync_state.write(
                        "failed",
                        context_graph_id=context_graph_id,
                        graph_peer_id=graph_peer_id,
                        phase="stalled-verifiable-memory",
                        inserted_durable_triples=0,
                        error=error,
                        **durable_progress,
                    )
                    print(f"  {error}")
                    return False
                sync_state.write(
                    "running",
                    context_graph_id=context_graph_id,
                    graph_peer_id=graph_peer_id,
                    phase="recovering-verifiable-memory",
                    inserted_durable_triples=0,
                    **durable_progress,
                )
                print(
                    "  verifiable VM pass settled without committed triples; "
                    f"snapshot remains incomplete ({safe_current:,}/{expected:,}); "
                    "retrying the pinned source"
                )
                time.sleep(min(2.0, max(0.2, deadline - time.monotonic())))
                continue
            count_threats = getattr(client, "threat_count", None)
            local_threats: Optional[int] = None
            if callable(count_threats):
                try:
                    local_threats = int(count_threats(context_graph_id) or 0)
                except (DkgError, TypeError, ValueError):
                    local_threats = None
            if (
                context_graph_id == constants.DEFAULT_CONTEXT_GRAPH_ID
                and local_threats is not None
                and local_threats >= constants.DEFAULT_GRAPH_RELEASE_THREAT_FLOOR
            ):
                print(
                    "  verifiable VM release floor is complete "
                    f"({local_threats:,} threats verified and stored)"
                )
                return True
            if durable_progress.get("snapshot_complete") is True:
                expected = int(durable_progress.get("expected_triples") or 0)
                if expected > 0:
                    print(
                        f"  verifiable VM snapshot complete "
                        f"({expected:,} triples verified and stored)"
                    )
                else:
                    print("  verifiable VM snapshot complete")
                print("  verifiable VM sync settled (no new triples)")
                return True

            # A failed graph-scoped batch may have committed earlier KAs before
            # a later KA failed chain authentication.  Those rows are useful as
            # a partial ruleset, but their presence is not evidence that the
            # authoritative manifest settled.  Only the safe manifest boundary
            # above may turn a zero-insert response into success.
            empty_public_passes += 1
            safe_current = int(durable_progress.get("safe_current_triples") or 0)
            expected = int(durable_progress.get("expected_triples") or 0)
            if safe_current > 0:
                public_progress_seen = True
            if (
                empty_public_passes < _MAX_EMPTY_PUBLIC_PASSES
                and deadline - time.monotonic() > 4
            ):
                if expected > 0:
                    print(
                        "  public VM snapshot remains incomplete "
                        f"({safe_current:,}/{expected:,} safe triples"
                        + (
                            f", {local_threats:,} local threats"
                            if local_threats is not None and local_threats > 0
                            else ""
                        )
                        + "); retrying the pinned source"
                    )
                else:
                    print(
                        "  public VM returned no complete manifest boundary; "
                        "retrying the pinned source"
                    )
                time.sleep(min(2.0, max(0.2, deadline - time.monotonic())))
                continue
            if expected > 0:
                error = (
                    "public VM snapshot remains incomplete after "
                    f"{empty_public_passes} pinned passes "
                    f"({safe_current}/{expected} safe triples)"
                )
                phase = "incomplete-verifiable-memory"
            else:
                error = (
                    "public VM returned no complete manifest boundary after "
                    f"{empty_public_passes} pinned passes"
                )
                phase = "empty-verifiable-memory"
            sync_state.write(
                "failed",
                context_graph_id=context_graph_id,
                graph_peer_id=graph_peer_id,
                phase=phase,
                error=error,
                **durable_progress,
            )
            print(f"  {error}")
            return False
        empty_public_passes = 0
        incomplete_empty_passes = 0
        last_incomplete_safe_current = int(
            durable_progress.get("safe_current_triples") or 0
        )
        print(f"  verifiable VM sync advanced ({inserted:,} triples inserted)")
        if on_progress is not None:
            on_progress(inserted)
        public_progress_seen = True
        if context_graph_id == constants.DEFAULT_CONTEXT_GRAPH_ID:
            count_threats = getattr(client, "threat_count", None)
            if callable(count_threats):
                try:
                    local_threats = int(count_threats(context_graph_id) or 0)
                except (DkgError, TypeError, ValueError):
                    local_threats = 0
                if local_threats >= constants.DEFAULT_GRAPH_RELEASE_THREAT_FLOOR:
                    print(
                        "  verifiable VM release floor is complete "
                        f"({local_threats:,} threats verified and stored)"
                    )
                    return True
        # DKG's bounded rootless recovery deletes its transient page checkpoint
        # after the safe offset reaches the manifest total. Reissuing the full
        # snapshot request then starts a new scan at offset zero; it is not a
        # required idempotent EOF round. The HTTP response above is delivered
        # only after verification and store materialization settle, so combine
        # that successful response with the managed daemon's safe graph boundary
        # to recognize completion without downloading the snapshot again.
        if durable_progress.get("snapshot_complete") is True:
            expected = int(durable_progress.get("expected_triples") or 0)
            sync_state.write(
                "running",
                context_graph_id=context_graph_id,
                graph_peer_id=graph_peer_id,
                phase="refreshing-verifiable-memory",
                inserted_durable_triples=inserted,
                **durable_progress,
            )
            if expected > 0:
                print(
                    f"  verifiable VM snapshot complete "
                    f"({expected:,} triples verified and stored)"
                )
            else:
                print("  verifiable VM snapshot complete")
            return True
        # A transport interruption can yield a verified prefix and a successful
        # HTTP response. Repeat the pinned pass until the safe manifest boundary
        # is complete. The zero-insert path remains a compatibility fallback for
        # DKG builds that do not emit rootless durable progress.
        time.sleep(min(2.0, max(0.2, deadline - time.monotonic())))


def _peer_discovery_pending(exc: DkgError) -> bool:
    detail = str(exc).lower()
    return any(
        marker in detail
        for marker in (
            "peer_not_found",
            "peerresolver returned no addresses",
            "no addresses for",
            "failed to find peer",
            "dial_failed",
            "all multiaddr dials failed",
            "transport error: timed out",
        )
    )


def _configured_publisher_circuits(client: DkgClient, peer_id: str) -> List[str]:
    """Build deterministic relay routes for a publisher on a cold peerstore."""
    try:
        config = json.loads(
            (Path(client.dkg_home) / "config.json").read_text(encoding="utf-8")
        )
    except (AttributeError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return []
    circuits: List[str] = []
    for relay in config.get("relayPeers") or []:
        address = str(relay or "").rstrip("/")
        if "/p2p/" not in address:
            continue
        circuits.append(f"{address}/p2p-circuit/p2p/{peer_id}")
    return circuits


def _connect_verifiable_source(
    client: DkgClient,
    context_graph_id: str,
    graph_peer_id: str,
    deadline: float,
) -> None:
    """Resolve a publisher reliably during a fresh node's DHT warm-up."""
    connect = getattr(client, "connect_peer", None)
    if not callable(connect):
        return
    discovery_deadline = min(deadline, time.monotonic() + 120.0)
    notice_printed = False
    last_error: Optional[DkgError] = None
    while time.monotonic() < discovery_deadline:
        try:
            connect(graph_peer_id)
            return
        except DkgError as exc:
            if not _peer_discovery_pending(exc):
                raise
            last_error = exc

        # DHT routing tables are intentionally empty on a brand-new node.
        # Try the configured core relays as circuit routes while discovery
        # warms up; the publisher may hold a reservation on any one of them.
        connect_multiaddr = getattr(client, "connect_multiaddr", None)
        if callable(connect_multiaddr):
            for circuit in _configured_publisher_circuits(client, graph_peer_id):
                try:
                    connect_multiaddr(circuit)
                    return
                except DkgError:
                    continue

        remaining = discovery_deadline - time.monotonic()
        if remaining <= 0:
            break
        sync_state.write(
            "running",
            context_graph_id=context_graph_id,
            graph_peer_id=graph_peer_id,
            phase="discovering-verifiable-source",
        )
        if not notice_printed:
            print("  discovering the verifiable graph publisher (fresh-node warm-up)...")
            notice_printed = True
        time.sleep(min(5.0, max(0.2, remaining)))
    if last_error is not None:
        raise last_error
    raise DkgError("publisher discovery deadline reached")


def _should_request_private_join(cfg: BlackboxConfig) -> bool:
    """Private graph membership is never part of Agent Blackbox."""
    return False


def _request_join(client: DkgClient, cg_id: str, graph_peer_id: str) -> tuple[Optional[str], bool]:
    """Submit one native private-graph join request.

    The boolean reports that the curator itself confirmed current membership
    and refreshed the signed peer-key delegation.  A local participant list
    can be stale after a store migration or curator restart, so it must not be
    used as the authorization signal for starting private catch-up.
    """
    if not graph_peer_id:
        return None, False
    try:
        result = client.request_join(cg_id, graph_peer_id)
    except DkgError as exc:
        return f"warning: could not request join for {cg_id}: {exc}", False
    if not isinstance(result, dict):
        return f"Join request submitted for {cg_id}; curator approval is still required.", False
    if result.get("alreadyMember") or result.get("already_member"):
        return (
            f"Join request: the curator confirmed membership for {cg_id} "
            "and refreshed this node's peer binding.",
            True,
        )
    delivered = result.get("delivered")
    if isinstance(delivered, list):
        delivered_count = len(delivered)
    elif isinstance(delivered, bool):
        delivered_count = 1 if delivered else 0
    elif isinstance(delivered, str) and delivered.lower() == "local":
        delivered_count = 1
    else:
        try:
            delivered_count = int(delivered or result.get("deliveredCount") or 0)
        except (TypeError, ValueError):
            delivered_count = 0
    if delivered_count:
        return (
            f"Join request sent for {cg_id}: delivered to {delivered_count} curator host(s); "
            "approval is pending.",
            False,
        )
    return f"Join request could not reach a graph host for {cg_id}; retrying.", False
