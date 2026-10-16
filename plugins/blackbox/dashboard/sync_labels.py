"""Sync-state presentation for ``GET /api/graph-status`` (the ``sync_progress`` labels).

Three pure helpers, so the route body stays a wiring list:

* ``_sync_label("VM", state)`` → ``"VM syncing"`` — the verified tier's label.
* ``_community_progress(cfg, rs, count)`` → ``{"count", "state", "label"}`` — the community
  tier's whole ``sync_progress`` entry. Its state is independent of the VM catch-up: the
  community tier is live on its own (a pulse can change it with no VM sync at all).
* ``_is_hidden_swm_catchup_error`` / ``_is_retryable_durable_catchup_error`` — which recorded
  catch-up errors the sync activity shows as a wait instead of a failure.
"""

from __future__ import annotations

from typing import Any, Dict
_SYNC_LABEL_SUFFIX = {
    "ready": "synced",
    "syncing": "syncing",
    "unreachable": "offline",
    "empty": "empty",
    "incomplete": "incomplete",
    "pending-approval": "curator approval pending",
    "pending-encryption-profile": "waiting for workspace encryption profile",
    "joining": "joining private graph",
    "not-configured": "not configured",
    "not-subscribed": "not subscribed — run blackbox sync --wait",
    "paused": "paused by curators",
    "sync-envelope-error": "peer sync handshake malformed",
}

_COMMUNITY_PROGRESS_LABEL = {
    "not-configured": "Community not configured (no graph)",
    "paused": "Community ingest paused by curators",
    "empty": "Community connected · no reports yet",
}


def _sync_label(tier: str, state: str) -> str:
    """Human label for a tier's sync state, e.g. ``"VM syncing"``."""
    return f"{tier} {_SYNC_LABEL_SUFFIX.get(state, state)}"


def _community_progress(cfg: Any, rs: Any, community: int) -> dict[str, Any]:
    """The ``sync_progress.community`` entry of /api/graph-status: ``{count, state, label}``.
    Its state is independent of the VM catch-up — the community tier is live on its own."""
    if not getattr(cfg, "context_graph_id", ""):
        state = "not-configured"
    elif getattr(rs, "community_paused", False):
        state = "paused"
    else:
        state = "ready" if community else "empty"
    label = _COMMUNITY_PROGRESS_LABEL.get(state, f"Community live · {int(community or 0)} corroborated threats")
    return {"count": int(community or 0), "state": state, "label": label}



def not_subscribed_activity() -> dict[str, Any]:
    """Sync-panel payload for a node with NO verified-graph subscription — says so,
    names the fix, and carries no clock (the pair showed '51 min elapsed' with nothing syncing)."""
    return {
        "status": "not-subscribed", "phase": "not-subscribed",
        "label": "Verified graph not subscribed",
        "detail": "This node is not subscribed to the verified threat graph — run `blackbox sync --wait` to join it. "
                  "Community reports still flow.",
        "started_at": None, "updated_at": None, "current": None, "expected": None,
        "percent": None, "indeterminate": True,
    }


def _is_hidden_swm_catchup_error(value: Any) -> bool:
    """Temporarily suppress the known DKG SWM catch-up UI failure."""
    text = str(value or "").lower()
    return "/api/shared-memory/catchup" in text and (
        "transport error" in text or "timed out" in text or "timeout" in text
    )


def _is_retryable_durable_catchup_error(value: Any) -> bool:
    """Recognize DKG's explicit transient durable-catchup response."""
    text = str(value or "").lower()
    compact = "".join(text.split())
    return (
        "/api/shared-memory/catchup" in text
        and "durable_catchup_all_peers_failed" in text
        and '"retryable":true' in compact
    )



def current_transfer_error(transfer: dict[str, Any], catchup: dict[str, Any]) -> str:
    """The failed transfer's recorded error, or "" once a catch-up job started AFTER it.

    A newer queued/running job supersedes the old failure: the sync activity shows the
    live job ("Fetching graph snapshot"), not a stale "waiting for publisher" or error.
    """
    newer_job = (str(catchup.get("status") or "").lower() in {"queued", "running"}
                 and _sync_time(catchup.get("startedAt")) > _sync_time(transfer.get("updated_at")))
    return "" if newer_job else str(transfer.get("error") or "")


def _sync_time(value: Any) -> float:
    """A sync-state time as seconds (0.0 when missing or unreadable)."""
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0
