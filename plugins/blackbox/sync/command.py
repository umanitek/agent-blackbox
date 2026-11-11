"""``blackbox sync`` — bring this node's copy of the verified graph up to date.

Drives the local node's catch-up of the verified graph (curator peer first,
generic peers as fallback; the subscription includes the shared memory the
community's reports live in), then compiles the ruleset. The catch-up route is one
:class:`_CatchupSync` run (its state and its steps); ``_catchup_authoritative_vm`` is the
remaining long function of quality item G4.
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
from . import state as sync_state
from ..kernel import constants
from ..kernel.config import BlackboxConfig, load_blackbox_config
from ..kernel.dkg_client import DkgClient, DkgError
from .progress import apply_completion_contract, capture_durable_progress_cursor, read_durable_progress
from ..kernel import display_safety
from . import managed_node, native, direct_preflight, side_subscriptions
from .catchup_job import _catchup_job_id, _catchup_status

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


def _terminal_sync_details(state: dict[str, Any]) -> dict[str, Any]:
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
    Do not restart it merely to reserve a sync slot: the pinned request
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
        terminal_state: dict[str, Any] = {}
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
    """The catch-up route of ``blackbox sync`` (custom graph / peer, or no native route)."""
    cfg = load_blackbox_config()
    return _CatchupSync(cfg, DkgClient.for_config(cfg), args).run()


_FAILED_JOB_STATES = frozenset({"failed", "cancelled", "denied"})


class _CatchupSync:
    """One ``blackbox sync`` over the node's catch-up (State, as one object: the fields are the
    run's state, each method one step of the loop in :meth:`run`).

    The steps, in loop order: recover from the pinned curator first (release graph, ``--wait``);
    persist the subscription (DKG keeps reconciling after this command exits); poll the
    catch-up job, retrying a deferred/unreachable one; refresh the rules once its job is done;
    decide whether the sync is complete. The pinned curator stays the preferred foreground
    source; the durable subscription is what lets DKG continue after exit or a restart.
    """

    def __init__(self, cfg: BlackboxConfig, client: DkgClient, args: argparse.Namespace) -> None:
        self.cfg, self.client, self.args = cfg, client, args
        self.wait = bool(getattr(args, "wait", False))
        self.require_rules = bool(getattr(args, "require_rules", False))
        self.release_graph = cfg.context_graph_id == constants.DEFAULT_CONTEXT_GRAPH_ID
        self.authoritative_available = bool(cfg.graph_peer_id and callable(getattr(client, "catchup_from_peer", None)))
        self.deadline = time.monotonic() + max(1, int(getattr(args, "timeout", 180) or 180))
        # The catch-up job and the subscription.
        self.subscribed = False
        self.baseline_known, self.baseline_job_id = False, ""
        self.fresh_seen, self.fresh_job_id, self.refreshed_job_id = False, "", ""
        self.retry_attempts, self.next_retry_at = 0, 0.0
        self.last_subscribe_error, self.last_catchup = "", {}
        self.catchup_state, self.catchup_job_id, self.exact_job_status = "", "", False
        # The pinned curator's recovery.
        self.auth_attempted = self.auth_recovered = self.auth_cache_refreshed = self.auth_complete = False
        self.auth_target = 0
        # The rules.
        self.rs: Any = ruleset.Ruleset()
        self.public_count = self.community_count = 0
        self.initial_rules_ready = self.sync_complete = False
        self.attempt = 0

    def run(self) -> int:
        """Run the sync to completion, failure or the deadline; the exit code (2 = required rules missing)."""
        if self.release_graph and self.wait and self.require_rules and not self.authoritative_available:
            print("  Required curator-pinned VM recovery is unavailable in this DKG build.")
            return 2
        self._start()
        while True:
            outcome = self._step()
            if outcome == "stop":
                break
            if outcome == "wait":
                time.sleep(min(3.0, max(0.2, self.deadline - time.monotonic())))
        self._finish_tracking()
        return self._report()

    def _start(self) -> None:
        cfg = self.cfg
        if self.wait:
            known_public, known_community = _last_sync_counts(cfg.context_graph_id)
            sync_state.write("running", context_graph_id=cfg.context_graph_id, graph_peer_id=cfg.graph_peer_id,
                             phase="network-catchup", public_entries=known_public, community_entries=known_community)
            try:
                self.baseline_job_id = _catchup_job_id(self.client.catchup_status(cfg.context_graph_id))
                self.baseline_known = True
            except (DkgError, AttributeError):
                pass
        if self.release_graph and self.wait:
            local_release = _complete_local_release_ruleset(cfg, self.client)
            if local_release is not None:
                self.rs = local_release
                self.public_count = _ruleset_graph_count(self.rs, "public")
                self.initial_rules_ready = self.public_count > 0
                self.auth_attempted = self.auth_recovered = self.auth_cache_refreshed = True
                self.auth_complete = self.initial_rules_ready
                self.auth_target = self.public_count
                print(f"Local confirmed VM already contains the complete release ({self.public_count:,} enforceable threats).")

    def _write_running(self, phase: str, **fields: Any) -> None:
        sync_state.write("running", context_graph_id=self.cfg.context_graph_id, graph_peer_id=self.cfg.graph_peer_id,
                         phase=phase, public_entries=self.public_count, community_entries=self.community_count, **fields)

    def _record_verified_pass(self, _inserted_triples: int) -> None:
        """Between DKG passes: publish only locally committed threat counts, and build one
        partial verified cache before announcing readiness (an installer may then open a
        useful dashboard while the same single-flight transfer continues)."""
        previous_public, became_ready = self.public_count, False
        count_threats = getattr(self.client, "threat_count", None)
        if callable(count_threats):
            self.public_count = max(self.public_count, int(count_threats(self.cfg.context_graph_id) or 0))
        if self.public_count > 0 and not self.initial_rules_ready:
            try:
                partial_rules = ruleset.refresh(self.cfg, self.client)
            except Exception as exc:   # health: allow BLE001 -- a partial cache that cannot build waits for the next pass
                logger.debug("blackbox: initial verified rules cache is not ready: %s", exc)
            else:
                cached_public = _ruleset_graph_count(partial_rules, "public")
                if cached_public > 0:
                    self.rs, self.public_count = partial_rules, max(self.public_count, cached_public)
                    self.initial_rules_ready = became_ready = True
        self.auth_target = max(self.auth_target, self.public_count)
        self._write_running("recovering-verifiable-memory")
        if self.initial_rules_ready and (self.public_count != previous_public or became_ready):
            print(f"  {self.public_count:,} verified threats ready")

    def _recover(self, *, on_failure_refresh: bool) -> None:
        """Ask the pinned curator for the verified graph (once per run), then take the rules it
        left. A failed recovery reads the cache as it is (*on_failure_refresh*: refresh it)."""
        cfg, client = self.cfg, self.client
        self.auth_attempted = True
        self.auth_recovered = _catchup_authoritative_vm(client, cfg.context_graph_id, cfg.graph_peer_id,
                                                        self.deadline, on_progress=self._record_verified_pass)
        if self.auth_recovered:
            try:
                self.rs = ruleset.refresh(cfg, client, force_query=True)
            except ruleset.RulesetRefreshUnavailable:
                self.rs = ruleset.peek(cfg)
            else:
                self.auth_cache_refreshed = True
        else:
            self.rs = ruleset.refresh(cfg, client) if on_failure_refresh else ruleset.peek(cfg)
        cached_public = _ruleset_graph_count(self.rs, "public")
        self.public_count = cached_public if self.auth_cache_refreshed else max(self.public_count, cached_public)
        self.community_count = _ruleset_graph_count(self.rs, "community")
        self.auth_target = self.public_count if self.auth_cache_refreshed else max(self.auth_target, self.public_count)

    def _recover_first(self) -> None:
        """The release graph has one known complete source peer: a fresh node asks it first
        instead of downloading unrelated graphs from every generic peer. If that fails, the
        ordinary subscription / catch-up below stays available."""
        if not (self.release_graph and self.wait and self.authoritative_available and not self.auth_attempted):
            return
        # Successful passes already refreshed the cache via _record_verified_pass; a failure
        # before any pass settled does not launch a competing full-store query (peek).
        self._recover(on_failure_refresh=False)
        if not self.auth_recovered and self.require_rules:
            print("  Foreground curator recovery did not complete; persisting the DKG subscription for native reconciliation.")
        if self.auth_recovered:
            # A complete foreground snapshot; the subscription below still lets DKG own future updates.
            self.fresh_seen = True
            self.auth_complete = (self.auth_cache_refreshed and self.auth_target > 0
                                  and self.public_count >= self.auth_target)

    def _is_new_job(self, job_id: str) -> bool:
        return bool(job_id) and (not self.baseline_known or job_id != self.baseline_job_id)

    def _subscribe(self) -> None:
        if self.subscribed:
            return
        # An active successor graph (T2) rides the same sync, fail-open — not on every poll.
        side_subscriptions.ensure_side_subscriptions(self.client, self.cfg)
        try:
            job_id = _catchup_job_id(self.client.subscribe_context_graph(self.cfg.context_graph_id))
            self.subscribed = True
            if self._is_new_job(job_id):
                self.fresh_seen, self.fresh_job_id = True, job_id
            print(f"Subscribed to {self.cfg.context_graph_id}; DKG catch-up started.")
        except DkgError as exc:
            self.last_subscribe_error = str(exc)
            print(f"warning: could not subscribe to {self.cfg.context_graph_id}: {exc}")

    def _poll_catchup(self) -> None:
        self.catchup_state, self.catchup_job_id, self.exact_job_status = "", "", False
        if not (self.wait and self.subscribed):
            return
        try:
            catchup, self.exact_job_status = _catchup_status(self.client, self.cfg.context_graph_id, self.fresh_job_id)
        except DkgError:
            return
        self.last_catchup = catchup
        self.catchup_state = str(catchup.get("status") or "").lower()
        self.catchup_job_id = _catchup_job_id(catchup)
        if self._is_new_job(self.catchup_job_id):
            self.fresh_seen = True
            if not self.fresh_job_id or not self.exact_job_status:
                self.fresh_job_id = self.catchup_job_id

    def _retried_deferred_job(self, now: float) -> bool:
        """Replace a deferred / unreachable fresh catch-up (backing off); True when one was asked."""
        retryable = (not self.auth_recovered and self.wait and self.subscribed and self.fresh_seen
                     and self.catchup_state in {"deferred", "unreachable"})
        if not (retryable and self.next_retry_at <= now < self.deadline):
            return False
        self.retry_attempts += 1
        self.next_retry_at = now + min(10.0, float(2 ** min(self.retry_attempts - 1, 3)))
        try:
            replacement = self.client.subscribe_context_graph(self.cfg.context_graph_id)
        except DkgError as exc:
            self.last_subscribe_error = str(exc)
            return False
        self.fresh_seen, self.fresh_job_id = True, _catchup_job_id(replacement)
        self.last_catchup = replacement if isinstance(replacement, dict) else {}
        print(f"Retrying DKG catch-up after {self.catchup_state} state (attempt {self.retry_attempts}).")
        return True

    def _fresh_job_complete(self) -> bool:
        return self.catchup_state == "done" and (
            self.exact_job_status or not self.fresh_job_id or self.catchup_job_id == self.fresh_job_id)

    def _refresh_rules(self, fresh_job_complete: bool, barrier_job_id: str) -> None:
        """Refresh the rules once the catch-up job is done; while it is pending or failed only the
        cheap job status is polled (DKG applies catch-up atomically: a full VM query then cannot
        see useful partial rules and competes with the store write that must finish first)."""
        if not self.subscribed:
            return
        pending = not self.auth_recovered and (
            self.catchup_state in {"queued", "running"}
            or (self.wait and self.fresh_seen and not fresh_job_complete and self.catchup_state not in _FAILED_JOB_STATES))
        failed = not self.auth_recovered and self.fresh_seen and self.catchup_state in _FAILED_JOB_STATES
        if pending or failed:
            self.rs = ruleset.peek(self.cfg)
            return
        force_catchup = fresh_job_complete and barrier_job_id != self.refreshed_job_id
        force_authoritative = self.auth_recovered and not self.auth_cache_refreshed
        try:
            self.rs = ruleset.refresh(self.cfg, self.client, force_query=force_catchup or force_authoritative)
        except ruleset.RulesetRefreshUnavailable:
            self.rs = ruleset.peek(self.cfg)
        else:
            if force_catchup:
                self.refreshed_job_id = barrier_job_id
            if force_authoritative:
                self.auth_cache_refreshed = True

    def _base_sync_complete(self, fresh_job_complete: bool, barrier_job_id: str) -> bool:
        """Rules are here and the fresh catch-up has landed. A terminal generic catch-up is not
        success by itself; a completed, idempotent pinned recovery is (it verified the snapshot)."""
        authoritative_ready = self.auth_recovered and self.auth_cache_refreshed
        cache_refreshed = not fresh_job_complete or self.refreshed_job_id == barrier_job_id
        catchup_complete = authoritative_ready or (not self.wait or (
            self.catchup_state not in {"queued", "running"} and cache_refreshed
            and (not self.fresh_seen or fresh_job_complete)))
        return self.public_count > 0 and catchup_complete

    def _authoritative_empty(self) -> bool:
        """After a pinned recovery: update its target / completeness; True (stop, failed) when
        the curator's VM holds no public threat at all."""
        if self.auth_recovered and self.public_count > self.auth_target:
            self.auth_target = self.public_count
        if not self.auth_recovered:
            return False
        self.auth_complete = self.auth_cache_refreshed and self.auth_target > 0 and self.public_count >= self.auth_target
        if self.auth_target > 0:
            return False
        sync_state.write("failed", context_graph_id=self.cfg.context_graph_id, graph_peer_id=self.cfg.graph_peer_id,
                         phase="empty-verifiable-memory", public_entries=0, expected_public_entries=0,
                         community_entries=self.community_count, error="authoritative VM returned no public threat entries")
        print("  authoritative VM returned zero public threat entries; the required ruleset is unavailable.")
        return True

    def _step(self) -> str:
        """One pass of the loop: "again" (go round at once), "wait" (sleep first) or "stop"."""
        now = time.monotonic()
        self._recover_first()
        self._subscribe()
        self._poll_catchup()
        if self._retried_deferred_job(now):
            return "again"
        fresh_job_complete = self._fresh_job_complete()
        barrier_job_id = self.catchup_job_id or self.fresh_job_id or "<unscoped>"
        self._refresh_rules(fresh_job_complete, barrier_job_id)
        self.public_count = _ruleset_graph_count(self.rs, "public")
        self.community_count = _ruleset_graph_count(self.rs, "community")
        base_complete = self._base_sync_complete(fresh_job_complete, barrier_job_id)
        # A clean local store has no public rows yet: waiting for base_complete before asking
        # the release source would deadlock that first sync, so the release graph asks at once.
        if ((base_complete or self.release_graph) and self.release_graph and self.wait
                and self.authoritative_available and not self.auth_attempted):
            self._recover(on_failure_refresh=True)
        if self._authoritative_empty():
            return "stop"
        self.sync_complete = base_complete and (not self.auth_attempted or self.auth_complete) and self.subscribed
        if self.auth_recovered and not self.sync_complete:
            phase = ("persisting-subscription" if not self.subscribed
                     else "refreshing-verifiable-memory" if not self.auth_complete else "network-catchup")
            self._write_running(phase, expected_public_entries=self.auth_target)
        if self.sync_complete or (not self.auth_recovered and self.fresh_seen and self.catchup_state in _FAILED_JOB_STATES):
            return "stop"
        return self._at_deadline() or self._waiting()

    def _at_deadline(self) -> str:
        """"stop" (recording why) when this run may not wait any longer, else ""."""
        if self.wait and time.monotonic() < self.deadline:
            return ""
        cfg = self.cfg
        if not self.subscribed:
            error = "required DKG subscription could not be persisted"
            error = f"{error}: {self.last_subscribe_error}" if self.last_subscribe_error else error
            sync_state.write("failed", context_graph_id=cfg.context_graph_id, graph_peer_id=cfg.graph_peer_id,
                             phase="persisting-subscription", public_entries=self.public_count,
                             expected_public_entries=self.auth_target or self.public_count,
                             community_entries=self.community_count, error=error)
        elif self.auth_recovered and not self.auth_complete:
            sync_state.write("failed", context_graph_id=cfg.context_graph_id, graph_peer_id=cfg.graph_peer_id,
                             phase="refreshing-verifiable-memory", public_entries=self.public_count,
                             expected_public_entries=self.auth_target, community_entries=self.community_count,
                             error="public VM reconciliation deadline reached")
        return "stop"

    def _waiting(self) -> str:
        self.attempt += 1
        if self.attempt == 1 or self.attempt % 10 == 0:
            if self.auth_recovered and not self.auth_complete:
                print(f"Waiting for public VM reconciliation ({self.public_count:,}/{self.auth_target:,} entries)...")
            else:
                print(f"Waiting for DKG catch-up ({self.catchup_state or 'syncing'})...")
        return "wait"

    def _finish_tracking(self) -> None:
        if not self.wait:
            return
        cfg = self.cfg
        current_transfer = sync_state.read_for_graph(cfg.context_graph_id)
        if self.sync_complete:
            sync_state.write("done", context_graph_id=cfg.context_graph_id, graph_peer_id=cfg.graph_peer_id,
                             phase="complete", public_entries=self.public_count,
                             expected_public_entries=self.auth_target or self.public_count,
                             community_entries=self.community_count)
        elif current_transfer.get("status") == "running":
            sync_state.write("failed", context_graph_id=cfg.context_graph_id, graph_peer_id=cfg.graph_peer_id,
                             phase=str(current_transfer.get("phase") or "network-catchup"),
                             public_entries=self.public_count, community_entries=self.community_count,
                             error="required threat graph sync did not complete before the deadline")

    def _report(self) -> int:
        counts = self.rs.counts()
        print(f"Ruleset synced from {self.cfg.context_graph_id}:")
        print(f"  {counts['injection']} injection, {counts['escalation']} escalation, {counts['dependency']} dependency")
        print(f"  {self.public_count:,} public VM (curated)")
        print(f"  Community reports: shared memory of {display_safety.term_safe(self.cfg.context_graph_id)} "
              f"[sharing {'on' if self.cfg.community_enabled else 'off'}]")
        if self.sync_complete:
            return 0
        if not self.subscribed:
            print("  Required public VM subscription could not be persisted.")
            if self.last_subscribe_error:
                print(f"  DKG subscription error: {self.last_subscribe_error}")
            print("  Retry with `hermes blackbox sync --wait`.")
        elif self.fresh_seen and str(self.last_catchup.get("status") or "").lower() in _FAILED_JOB_STATES:
            detail = self.last_catchup.get("error") or (self.last_catchup.get("result") or {}).get("error")
            print(f"  Fresh DKG catch-up failed{f': {detail}' if detail else '.'}")
        elif self.auth_attempted and self.auth_target == 0:
            print("  The authoritative curator VM returned zero public threat entries.")
            print("  No rules are available to protect this node.")
        elif self.auth_attempted and not self.auth_complete:
            print("  Authoritative curator VM transfer is incomplete.")
            print("  Retry with `hermes blackbox sync --wait`.")
        else:
            print("  0 rules — DKG has not made curated VM threat rows queryable yet.")
            print("  Retry with `hermes blackbox sync --wait`.")
        if self.require_rules:
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
            outcome: queue.Queue[tuple[str, Any]] = queue.Queue(maxsize=1)

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
        request_progress = read_durable_progress(
            str(getattr(client, "dkg_home", "") or ""),
            context_graph_id,
            after=progress_cursor,
        )
        apply_completion_contract(request_progress, result)
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
            **request_progress,
        )
        # The whole log gives the cumulative numbers; completion comes only from THIS
        # invocation (its log lines or the node's answer), never an earlier run's lines.
        durable_progress = read_durable_progress(str(getattr(client, "dkg_home", "") or ""), context_graph_id)
        durable_progress["snapshot_complete"] = request_progress.get("snapshot_complete") is True
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


def _configured_publisher_circuits(client: DkgClient, peer_id: str) -> list[str]:
    """Build deterministic relay routes for a publisher on a cold peerstore."""
    try:
        config = json.loads(
            (Path(client.dkg_home) / "config.json").read_text(encoding="utf-8-sig")
        )
    except (AttributeError, OSError, TypeError, ValueError, json.JSONDecodeError):
        return []
    circuits: list[str] = []
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
