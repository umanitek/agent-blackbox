"""Observe shipped DKG VM recovery and expose locally verified rules.

The native reconciler owns fetching and per-asset chain verification. A usable
local rule cache is an availability result; it does not certify a complete
context graph or the latest version of every collection.
"""

from __future__ import annotations

import time
from typing import Any

from . import constants, ruleset, sync_state
from .config import BlackboxConfig
from .dkg_client import DkgClient, DkgError, classify_catchup_error

_POLL_SECONDS = 5.0


def handles_default_public(config: BlackboxConfig) -> bool:
    """Keep explicitly selected graph/source pairs on their existing path."""
    return (
        config.context_graph_id == constants.DEFAULT_CONTEXT_GRAPH_ID
        and config.graph_peer_id == constants.DEFAULT_GRAPH_PEER_ID
    )


class _ObservationExpired(RuntimeError):
    pass


class _QueryWindow:
    """Bound every query in one cache refresh by the observation deadline."""

    def __init__(self, client: DkgClient, deadline: float) -> None:
        self.client = client
        self.deadline = deadline
        self.failed = False
        self.queries = 0

    def query(self, sparql: str, cg_id: str, **kwargs: Any) -> Any:
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise _ObservationExpired()
        requested = kwargs.pop("timeout", None) or 30.0
        result = self.client.query(
            sparql, cg_id, timeout=min(float(requested), remaining), **kwargs,
        )
        self.queries += 1
        if "on_error" in kwargs and result is kwargs["on_error"]:
            self.failed = True
        # Do not publish a cache generation whose last read outlived this run.
        if time.monotonic() >= self.deadline:
            raise _ObservationExpired()
        return result


def run(client: DkgClient, config: BlackboxConfig, args: Any) -> int:
    """Subscribe, observe native recovery, and return when rules are usable.

    This never invokes the legacy whole-graph durable catch-up route, reconnects
    a source, changes node configuration, or changes the node's authority mode.
    Ctrl-C stops this observer; the durable subscription remains resumable.
    """
    if not handles_default_public(config):
        raise ValueError("native observation requires the default public graph/source")
    wait = bool(getattr(args, "wait", False))
    required = bool(getattr(args, "require_rules", False))
    budget = max(0.01, float(getattr(args, "timeout", 3600)))
    if not wait:
        budget = min(budget, 150.0)
    deadline = time.monotonic() + budget
    subscribed = False
    subscription_terminal = False
    last_error = ""
    last_freshness = "cached"
    current = ruleset.peek(config)

    def record(status: str, phase: str, error: str = "") -> None:
        usable = current.source_count("public")
        sync_state.write(
            status,
            context_graph_id=config.context_graph_id,
            graph_peer_id=config.graph_peer_id,
            phase=phase,
            public_entries=usable,
            public_graph_entries=len(current.graph_entries("public")),
            community_entries=0,
            detection_ready=usable > 0,
            graph_complete=False,
            complete=False,
            subscribed=subscribed,
            freshness=last_freshness,
            error=error,
        )

    try:
        record("running", "observing-native-vm")
        while time.monotonic() < deadline:
            last_error = ""
            if not subscribed:
                try:
                    subscription = client.subscribe_context_graph(
                        config.context_graph_id,
                        include_shared_memory=False,
                        timeout=min(150.0, max(0.01, deadline - time.monotonic())),
                    )
                    subscribed = (
                        isinstance(subscription, dict)
                        and subscription.get("subscribed") == config.context_graph_id
                    )
                    if subscribed:
                        print("Subscribed to the public threat graph; observing DKG VM recovery.")
                    else:
                        subscription_terminal = True
                        last_error = "DKG did not acknowledge the requested graph subscription"
                except DkgError as exc:
                    subscription_terminal = classify_catchup_error(exc) == "terminal"
                    last_error = "DKG subscription unavailable; graph sync remains incomplete"

            disabled = False
            remaining = deadline - time.monotonic()
            if remaining > 0:
                try:
                    status = client.status(timeout=min(3.0, remaining / 2))
                    lifecycle = status.get("syncLifecycle") if isinstance(status, dict) else None
                    lifecycle = lifecycle if isinstance(lifecycle, dict) else {}
                    disabled = lifecycle.get("vmReconcilerEnabled") is False
                    if disabled:
                        last_error = "Native VM reconciliation is disabled on this node"
                except DkgError:
                    last_error = "DKG status unavailable; graph sync remains incomplete"

            window = _QueryWindow(client, deadline)
            try:
                current = ruleset.refresh(config, window, wait_for_lock=False)
            except _ObservationExpired:
                current = ruleset.peek(config)
                last_error = "Timed out observing verified VM rules; graph sync remains incomplete"
                break
            last_freshness = "queried" if window.queries and not window.failed else "cached"
            if window.failed:
                last_error = "Local VM query unavailable; retaining last verified rules"
            usable = current.source_count("public")
            if usable > 0:
                record("partial", "verified-rules-available", last_error)
                qualifier = "cached " if last_freshness == "cached" else ""
                print(f"Loaded {usable} {qualifier}verified public detection rules. Graph sync remains incomplete.")
                return 0
            record("running", "observing-native-vm", last_error)
            if disabled or subscription_terminal or not wait:
                break
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(_POLL_SECONDS, remaining))
    except KeyboardInterrupt:
        record("cancelled", "observing-native-vm", "sync cancelled by user")
        print("Blackbox sync cancelled. Background DKG recovery may continue.")
        return 130

    if current.source_count("public") > 0:
        record("partial", "verified-rules-available", last_error)
        print(f"Retained {current.source_count('public')} cached verified public detection rules. Graph sync remains incomplete.")
        return 0
    error = last_error or "No actionable verified rules are available yet; graph sync remains incomplete"
    record("failed" if required or wait else "partial", "waiting-for-verified-rules", error)
    print(error)
    return 2 if required or wait else 0
