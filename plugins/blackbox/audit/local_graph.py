"""This machine's own private graph for the local audit record.

WHY (bench 2026-10-10, DKG 10.0.23): the private working-memory audit record was
written into Umanitek's verified graph, and the node refuses that write
(``400 CONTEXT_GRAPH_NOT_FOUND … Write operations must target an existing context
graph``) — the graph belongs to Umanitek's wallet, the node only subscribes to it.
The failure was swallowed, so the dashboard's Local tab stayed empty on every node.

The record now lives in a graph this node OWNS: ``<agent address>/blackbox-local``,
created once (an existing one answers 409, which is fine) and remembered in
``local_audit_graph.json``. Only working memory is ever written to it — private to
the node, never shared — so nothing in it leaves the machine.

Usage::

    graph = local_audit_graph(client)     # "0x…/blackbox-local", or "" when it cannot be had
"""

from __future__ import annotations

import json
import logging
import os
import threading
from typing import Any

from ..kernel import constants
from ..kernel.bounded_files import atomic_write, read_json_object

logger = logging.getLogger(__name__)

GRAPH_NAME = "blackbox-local"
_CACHE_FILE = "local_audit_graph.json"
_lock = threading.Lock()


def local_audit_graph(client: Any) -> str:
    """The id of this node's private audit graph, creating it on first use; "" when
    the node cannot say who it is or refuses the graph (the caller logs and skips)."""
    with _lock:
        cached = _read_cache()
        if cached:
            return cached
        try:
            address = str((client.agent_identity() or {}).get("agentAddress") or "").strip()
        except Exception as exc:   # an unreachable node: try again on the next record
            logger.warning("blackbox: local audit graph unavailable — node identity unknown: %s", exc)
            return ""
        if not address:
            return ""
        graph = f"{address}/{GRAPH_NAME}"
        if not _ensure_created(client, graph):
            return ""
        _write_cache(graph)
        return graph


def _ensure_created(client: Any, graph: str) -> bool:
    try:
        client.request("POST", "/api/context-graph/create",
                       {"id": graph, "name": "Blackbox local audit (private, this machine only)", "accessPolicy": 0},
                       timeout=30.0)
        return True
    except Exception as exc:
        if getattr(exc, "status_code", None) == 409:   # already there — the normal case after the first run
            return True
        logger.warning("blackbox: local audit graph %s could not be created: %s", graph, exc)
        return False


def _cache_path():
    return constants.blackbox_home() / _CACHE_FILE


def _read_cache() -> str:
    graph = str((read_json_object(_cache_path()) or {}).get("graph") or "")
    return graph if graph.endswith("/" + GRAPH_NAME) else ""


def _write_cache(graph: str) -> None:
    try:
        path = _cache_path()
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(path, json.dumps({"graph": graph}))
    except OSError as exc:   # the graph still works; it is just resolved again next time
        logger.debug("blackbox: local audit graph not cached: %s", exc)
