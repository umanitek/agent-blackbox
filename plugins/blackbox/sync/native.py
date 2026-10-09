"""The native route for Umanitek's default public graph (DKG 10.0.21+).

From DKG 10.0.21 a node recovers a public context graph by itself: once it is
subscribed, its VM reconciler fetches every registered asset and verifies it
against the chain. With the exact-batch stream and recovery prefetch switched on
(see :mod:`.managed_node`), a fresh node holds Umanitek's whole graph in about
35 minutes; the older durable catch-up job Blackbox used to request instead sat
at "waiting-for-dkg-capacity" for an hour on the same release (KI-282).

So for the default graph, ``blackbox sync`` no longer drives the transfer. It
**observes** it (an Observer, in pattern terms): subscribe once, then compile
the rules the node already holds, until the first usable verified rules exist.
The node keeps fetching after this command returns; the ordinary hourly refresh
and the dashboard's refresh worker compile the rest as it lands.

What this route never does: request the durable catch-up job, reconnect a
source, or change the node's authority mode. Explicitly chosen graph/source
pairs keep the older route (:func:`handles` is the one switch).

Usage::

    from . import native
    return native.route(cfg, older_route)(args)   # the one routing decision
"""

from __future__ import annotations

import argparse
import logging
import time
from dataclasses import dataclass
from typing import Callable

from .. import ruleset
from ..kernel import constants
from ..kernel.config import BlackboxConfig, load_blackbox_config
from ..kernel.dkg_client import DkgClient, DkgError
from . import state as sync_state

logger = logging.getLogger(__name__)

#: How often the observer re-reads what the node holds while it waits.
POLL_SECONDS = 5.0
#: Without ``--wait`` the observer gives the node this long, then returns.
NO_WAIT_BUDGET_SECONDS = 150.0
#: A single subscribe request never waits longer than this.
SUBSCRIBE_TIMEOUT_SECONDS = 150.0


def handles(cfg: BlackboxConfig) -> bool:
    """True for Umanitek's default graph and source — the only pair the native
    route serves. Any other graph/source an operator chose keeps the older
    route, so this change cannot alter a custom setup."""
    return (
        cfg.context_graph_id == constants.DEFAULT_CONTEXT_GRAPH_ID
        and cfg.graph_peer_id == constants.DEFAULT_GRAPH_PEER_ID
    )


SyncRoute = Callable[[argparse.Namespace], int]


def route(cfg: BlackboxConfig, older_route: SyncRoute) -> SyncRoute:
    """The sync to run for *cfg*: :func:`sync` for the default graph (KI-282),
    otherwise *older_route* (the durable catch-up, unchanged). Every caller of
    ``blackbox sync`` goes through this one decision."""
    return sync if handles(cfg) else older_route


def sync(args: argparse.Namespace) -> int:
    """``blackbox sync`` for the default graph: observe the node's own recovery."""
    cfg = load_blackbox_config()
    return run(DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home), cfg, args)


@dataclass
class _Observation:
    """What one run of the observer has seen so far (state owned by :func:`run`)."""

    subscribed: bool = False
    gave_up: bool = False   # the node refused the subscription for good
    error: str = ""
    verified_rules: int = 0

    def record(self, status: str, phase: str, cfg: BlackboxConfig) -> None:
        """Publish progress for the dashboard and ``blackbox status``.

        ``graph_complete`` stays False: the node does not report per-graph
        recovery progress, and a usable rule set is not proof of a complete
        graph. The rule count is the measured fact."""
        sync_state.write(
            status,
            context_graph_id=cfg.context_graph_id,
            graph_peer_id=cfg.graph_peer_id,
            phase=phase,
            public_entries=self.verified_rules,
            count_kind="sampled-usable-rules" if cfg.detection_backend == "dkg" else "compiled-rules",
            community_entries=0,
            detection_ready=self.verified_rules > 0,
            graph_complete=False,
            complete=False,
            subscribed=self.subscribed,
            error=self.error,
        )


#: HTTP answers that mean "try again", not "no": a timeout and a rate limit.
_RETRYABLE_CLIENT_STATUSES = frozenset({408, 429})


def _refused_for_good(exc: DkgError) -> bool:
    """True when the node's answer will not change on retry: a 4xx other than a
    timeout or rate limit. Transport failures and 5xx are worth another poll."""
    code = exc.status_code
    return code is not None and 400 <= code < 500 and code not in _RETRYABLE_CLIENT_STATUSES


def _subscribe(client: DkgClient, cfg: BlackboxConfig, seen: _Observation) -> None:
    """Subscribe the node to the verified graph once; a refusal the node will
    not change its mind about ends the observation."""
    try:
        reply = client.subscribe_context_graph(cfg.context_graph_id)
    except DkgError as exc:
        seen.gave_up = _refused_for_good(exc)
        seen.error = f"DKG subscription unavailable: {exc}"
        return
    seen.subscribed = isinstance(reply, dict) and bool(reply.get("subscribed"))
    if not seen.subscribed:
        seen.gave_up = True
        seen.error = "the DKG node did not acknowledge the subscription"


def _compile_what_the_node_holds(client: DkgClient, cfg: BlackboxConfig, seen: _Observation) -> None:
    """Compile the verified rules the node already holds into the ruleset."""
    try:
        if cfg.detection_backend == "dkg":
            from ..graph_read.view import ready_sample
            seen.verified_rules = ready_sample(cfg)
            seen.error = ""
            return
        compiled = ruleset.refresh(cfg, client, wait_for_lock=False)
    except ruleset.RulesetRefreshLockUnavailable:
        seen.error = "another process is compiling the rules; waiting for it"
        return
    except (ruleset.RulesetRefreshUnavailable, ruleset.RulesetRefreshIncomplete, DkgError) as exc:
        # The cache stays as it was; the next poll tries again.
        logger.warning("blackbox: native sync could not compile the local graph yet: %s", exc)
        seen.error = "the local graph could not be read yet; retrying"
        return
    seen.verified_rules = compiled.source_count("public")
    seen.error = ""


def run(client: DkgClient, cfg: BlackboxConfig, args: argparse.Namespace) -> int:
    """Observe the node's own recovery until verified rules are usable.

    Returns 0 once usable verified rules exist (or, without ``--require-rules``,
    when the time runs out); 2 when ``--wait --require-rules`` ends with none.
    """
    wait = bool(getattr(args, "wait", False))
    required = bool(getattr(args, "require_rules", False))
    budget = max(1.0, float(getattr(args, "timeout", 3600) or 3600))
    if not wait:
        budget = min(budget, NO_WAIT_BUDGET_SECONDS)
    deadline = time.monotonic() + budget
    seen = _Observation()
    seen.record("running", "observing-native-recovery", cfg)
    try:
        while time.monotonic() < deadline:
            if not seen.subscribed:
                _subscribe(client, cfg, seen)
                if seen.subscribed:
                    print("Subscribed to the verified threat graph; the DKG node is recovering it.")
                if seen.gave_up:
                    break
            _compile_what_the_node_holds(client, cfg, seen)
            if seen.verified_rules > 0:
                seen.record("partial", "verified-rules-available", cfg)
                print(
                    f"{'Validated a sample of' if cfg.detection_backend == 'dkg' else 'Loaded'} {seen.verified_rules:,} verified detection rules. The node keeps "
                    "fetching the rest of the graph in the background; `blackbox status` shows "
                    "the count as it grows."
                )
                return 0
            seen.record("running", "observing-native-recovery", cfg)
            if not wait:
                break
            time.sleep(min(POLL_SECONDS, max(0.0, deadline - time.monotonic())))
    except KeyboardInterrupt:
        seen.error = "sync cancelled by user"
        seen.record("cancelled", "observing-native-recovery", cfg)
        print("Blackbox sync cancelled. The DKG node keeps recovering the graph.")
        return 130
    message = seen.error or "no verified rules are available yet; the DKG node is still recovering the graph"
    seen.error = message
    seen.record("failed" if (wait and required) else "partial", "waiting-for-verified-rules", cfg)
    print(message)
    return 2 if (wait and required) else 0
