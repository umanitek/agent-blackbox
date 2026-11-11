"""Cross-process status for the authoritative Blackbox graph transfer."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any, Optional, TypedDict, Unpack

import psutil

from ..kernel import constants
from ..kernel.bounded_files import atomic_write, read_json_object

_STALE_RUNNING_SECONDS = 3_600


def _pid_is_alive(pid: Any) -> bool:
    try:
        value = int(pid)
        if value <= 0:
            return False
        return psutil.pid_exists(value)
    except (TypeError, ValueError):
        return False


def _path() -> Path:
    return constants.blackbox_home() / "authoritative-sync.json"


class SyncDetails(TypedDict, total=False):
    """What a sync records beside its status — THE keys the dashboard's sync meter and
    ``blackbox status`` read, whichever route (catch-up, native, snapshot) writes them.

    Where: ``context_graph_id``, ``graph_peer_id``, ``phase``, ``job_id``. Counts:
    ``public_entries`` / ``expected_public_entries`` / ``community_entries`` and what they count
    (``count_kind``, :func:`count_kind`), ``assets``, ``committed``, ``inserted_durable_triples``.
    The node's durable progress (``sync.progress``): ``current_triples``, ``safe_current_triples``,
    ``expected_triples``, ``progress_percent``, ``snapshot_complete``. Snapshot route:
    ``subscribed``, ``complete``, ``graph_complete``, ``detection_ready``, ``readiness_state`` /
    ``readiness_error``, ``snapshot_digest``, ``chain_evidence_mode``. Failure: ``error``.
    The Optional ones are written as None when the node or the previous record had no value."""

    context_graph_id: Optional[str]
    graph_peer_id: Optional[str]
    phase: str
    job_id: Optional[str]
    public_entries: Optional[int]
    expected_public_entries: int
    community_entries: int
    count_kind: str
    assets: Optional[int]
    committed: Optional[int]
    inserted_durable_triples: int
    current_triples: int
    safe_current_triples: int
    expected_triples: int
    progress_percent: float
    snapshot_complete: bool
    subscribed: bool
    complete: bool
    graph_complete: bool
    detection_ready: bool
    readiness_state: str
    readiness_error: str
    snapshot_digest: Optional[str]
    chain_evidence_mode: Optional[str]
    error: str


def count_kind(direct_backend: bool) -> str:
    """What a sync's ``public_entries`` counts: rules sampled from the graph (the per-call graph
    backend) or rules compiled into the local file — one wording for every route."""
    return "sampled-usable-rules" if direct_backend else "compiled-rules"


def write(status: str, **details: Unpack[SyncDetails]) -> dict[str, Any]:
    """Atomically publish transfer state for the dashboard (*details*: :class:`SyncDetails`)."""
    path = _path()
    path.parent.mkdir(parents=True, exist_ok=True)
    now = time.time()
    previous = read()
    context_graph_id = str(details.get("context_graph_id") or "")
    if context_graph_id and str(previous.get("context_graph_id") or "") != context_graph_id:
        previous = {}
    state = {
        "status": str(status),
        "started_at": previous.get("started_at", now),
        "updated_at": now,
        "pid": os.getpid(),
        **details,
    }
    if status == "running" and previous.get("status") == "running":
        for key in ("public_entries", "expected_public_entries", "community_entries"):
            if key not in details and key in previous:
                state[key] = previous[key]
    if status == "running" and previous.get("status") != "running":
        state["started_at"] = now
    atomic_write(path, json.dumps(state, sort_keys=True))
    return state


def read() -> dict[str, Any]:
    """Read current transfer state, rejecting abandoned running markers."""
    state = read_json_object(_path())
    if state is None:
        return {}
    if state.get("status") == "running":
        updated = float(state.get("updated_at") or 0)
        if not _pid_is_alive(state.get("pid")):
            return {**state, "status": "failed", "error": "authoritative sync process exited"}
        if updated and time.time() - updated > _STALE_RUNNING_SECONDS:
            return {**state, "status": "failed", "error": "authoritative sync stopped updating"}
    return state


def read_for_graph(context_graph_id: str) -> dict[str, Any]:
    """Read transfer state only when it belongs to ``context_graph_id``."""
    state = read()
    if str(state.get("context_graph_id") or "") != str(context_graph_id or ""):
        return {}
    return state
