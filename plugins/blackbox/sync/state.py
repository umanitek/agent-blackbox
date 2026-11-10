"""Cross-process status for the authoritative Blackbox graph transfer."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any

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


def write(status: str, **details: Any) -> dict[str, Any]:
    """Atomically publish transfer state for the dashboard."""
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
