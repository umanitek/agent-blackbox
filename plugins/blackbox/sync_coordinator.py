"""Exclusive state machine for Blackbox's hybrid DKG graph synchronization.

The normal DKG context-graph subscription is always the primary path.  The
curator-pinned recovery path is only legal after the normal job has reached a
known terminal state.  Keeping that rule in a small state machine makes it
hard for a future retry branch to accidentally start both paths at once.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict


REGULAR_ACTIVE_STATUSES = frozenset({"queued", "running"})
REGULAR_SUCCESS_STATUSES = frozenset({"done"})
REGULAR_FAILURE_STATUSES = frozenset(
    {"failed", "cancelled", "denied", "unreachable", "deferred"}
)
REGULAR_TERMINAL_STATUSES = REGULAR_SUCCESS_STATUSES | REGULAR_FAILURE_STATUSES

PREPARING = "preparing"
REGULAR_SUBSCRIBING = "regular-subscribing"
REGULAR_ACTIVE = "regular-active"
REGULAR_TERMINAL = "regular-terminal"
FALLBACK_PENDING = "fallback-pending"
FALLBACK_ACTIVE = "fallback-active"
RECONCILING = "reconciling"
COMPLETE = "complete"
FAILED = "failed"

_ALLOWED_TRANSITIONS = {
    PREPARING: {REGULAR_SUBSCRIBING, FAILED},
    REGULAR_SUBSCRIBING: {REGULAR_ACTIVE, REGULAR_TERMINAL, FAILED},
    REGULAR_ACTIVE: {REGULAR_ACTIVE, REGULAR_TERMINAL, FAILED},
    REGULAR_TERMINAL: {FALLBACK_PENDING, RECONCILING, FAILED},
    FALLBACK_PENDING: {FALLBACK_ACTIVE, FAILED},
    FALLBACK_ACTIVE: {RECONCILING, FAILED},
    RECONCILING: {COMPLETE, FAILED},
    COMPLETE: set(),
    FAILED: set(),
}

_PHASES = {
    PREPARING: "preparing-hybrid-sync",
    REGULAR_SUBSCRIBING: "regular-subscribing",
    REGULAR_ACTIVE: "network-catchup",
    REGULAR_TERMINAL: "regular-terminal",
    FALLBACK_PENDING: "fallback-pending",
    FALLBACK_ACTIVE: "recovering-verifiable-memory",
    RECONCILING: "reconciling-public-memory",
    COMPLETE: "complete",
    FAILED: "failed",
}


def catchup_status(payload: Any) -> str:
    """Extract a normalized DKG job status from a route or status response."""
    if not isinstance(payload, dict):
        return ""
    nested = payload.get("catchup")
    source = nested if isinstance(nested, dict) else payload
    return str(source.get("status") or "").strip().lower()


def catchup_job_id(payload: Any) -> str:
    """Extract a DKG catch-up job id from a route or status response."""
    if not isinstance(payload, dict):
        return ""
    nested = payload.get("catchup")
    source = nested if isinstance(nested, dict) else payload
    return str(source.get("jobId") or source.get("job_id") or "").strip()


@dataclass
class HybridSyncCoordinator:
    """Validate and publish one regular-first, fallback-second sync run."""

    writer: Callable[..., Dict[str, Any]]
    context_graph_id: str
    graph_peer_id: str
    state: str = PREPARING
    regular_status: str = ""
    regular_job_id: str = ""
    fallback_reason: str = ""
    _fallback_eligible: bool = field(default=False, init=False, repr=False)

    def publish_initial(self, **details: Any) -> Dict[str, Any]:
        return self._publish(PREPARING, **details)

    def start_regular(self, **details: Any) -> Dict[str, Any]:
        return self._transition(REGULAR_SUBSCRIBING, **details)

    def observe_regular(self, payload: Any, **details: Any) -> str:
        status = catchup_status(payload)
        job_id = catchup_job_id(payload)
        if job_id:
            self.regular_job_id = job_id
        if status:
            self.regular_status = status
        if status in REGULAR_ACTIVE_STATUSES:
            self._transition(REGULAR_ACTIVE, **details)
        elif status in REGULAR_TERMINAL_STATUSES:
            self._fallback_eligible = status in REGULAR_FAILURE_STATUSES
            self._transition(REGULAR_TERMINAL, **details)
        return status

    def mark_regular_empty(self, reason: str, **details: Any) -> None:
        """Make a clean but empty terminal regular result fallback-eligible."""
        if self.state != REGULAR_TERMINAL or self.regular_status not in REGULAR_SUCCESS_STATUSES:
            raise RuntimeError("regular catch-up must be terminal before empty-result fallback")
        self._fallback_eligible = True
        self.fallback_reason = reason
        self._publish(self.state, **details)

    def queue_fallback(self, reason: str, **details: Any) -> Dict[str, Any]:
        if self.state != REGULAR_TERMINAL or not self._fallback_eligible:
            raise RuntimeError("fallback is forbidden while regular catch-up may still be active")
        self.fallback_reason = reason
        return self._transition(FALLBACK_PENDING, **details)

    def start_fallback(self, **details: Any) -> Dict[str, Any]:
        if self.state != FALLBACK_PENDING:
            raise RuntimeError("fallback must pass through fallback-pending")
        return self._transition(FALLBACK_ACTIVE, **details)

    def start_reconciling(self, **details: Any) -> Dict[str, Any]:
        return self._transition(RECONCILING, **details)

    def complete(self, **details: Any) -> Dict[str, Any]:
        return self._transition(COMPLETE, **details)

    def fail(self, error: str, **details: Any) -> Dict[str, Any]:
        if self.state == FAILED:
            return self._publish(FAILED, error=error, **details)
        return self._transition(FAILED, error=error, **details)

    def _transition(self, target: str, **details: Any) -> Dict[str, Any]:
        allowed = _ALLOWED_TRANSITIONS.get(self.state, set())
        if target != self.state and target not in allowed:
            raise RuntimeError(f"invalid hybrid sync transition: {self.state} -> {target}")
        self.state = target
        return self._publish(target, **details)

    def _publish(self, state: str, **details: Any) -> Dict[str, Any]:
        sync_mode = "none"
        if state in {REGULAR_SUBSCRIBING, REGULAR_ACTIVE, REGULAR_TERMINAL}:
            sync_mode = "regular"
        elif state in {FALLBACK_PENDING, FALLBACK_ACTIVE}:
            sync_mode = "fallback"
        status = "running"
        if state == COMPLETE:
            status = "done"
        elif state == FAILED:
            status = "failed"
        payload = {
            "context_graph_id": self.context_graph_id,
            "graph_peer_id": self.graph_peer_id,
            "coordinator_state": state,
            "sync_mode": sync_mode,
            "phase": _PHASES[state],
            **details,
        }
        if self.regular_status:
            payload["regular_status"] = self.regular_status
        if self.regular_job_id:
            payload["regular_job_id"] = self.regular_job_id
        if self.fallback_reason:
            payload["fallback_reason"] = self.fallback_reason
        return self.writer(status, **payload)
