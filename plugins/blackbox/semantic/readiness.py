"""Explicit preparation and point-in-time residency, without a stale profile cache."""
import json
import threading
import time
from contextlib import contextmanager

from ..kernel.local_http import request
from ..ruleset import GraphReadUnavailable, LocalGraphClient, local_graph_url
from .reviewer import _local_model

# Reject overlapping preparation/inference instead of queuing behind a cold model.
# No configuration, readiness result, or profile state is retained globally.
_lane = threading.Lock()


@contextmanager
def model_lane():
    if not _lane.acquire(blocking=False):
        raise GraphReadUnavailable("SEMANTIC_REVIEW_BUSY")
    try:
        yield
    finally:
        _lane.release()


def _get(settings, path, deadline):
    status, raw = request(local_graph_url(settings.model_url), "GET", path, None, {},
                          deadline=deadline, max_bytes=1024 * 1024)
    if status != 200:
        raise GraphReadUnavailable("SEMANTIC_REVIEW_UNAVAILABLE")
    result = json.loads(raw)
    if not isinstance(result, dict) or not isinstance(result.get("models"), list):
        raise GraphReadUnavailable("SEMANTIC_REVIEW_UNAVAILABLE")
    return result["models"]


def _graph(cfg, deadline, warmup=False):
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise TimeoutError()
    reply = LocalGraphClient(cfg, budget_s=remaining).request("POST", "/api/entities/readiness", {
        "version": 1, "contextGraphId": cfg.context_graph_id, "indexId": cfg.semantic.index_id,
        "warmup": warmup, "timeoutMs": min(30_000 if warmup else 2000, max(1, int(remaining * 1000)))})
    if (reply.get("version") != 1 or reply.get("contextGraphId") != cfg.context_graph_id
            or reply.get("indexId") != cfg.semantic.index_id or reply.get("view") != "verifiable-memory"
            or reply.get("coverage") != "local-indexed-subset" or not reply.get("modelFingerprint")
            or type(reply.get("ready")) is not bool or not reply.get("observedAt")):
        raise GraphReadUnavailable("QUERY_MALFORMED_RESPONSE")
    if not reply["ready"]:
        raise GraphReadUnavailable("SEMANTIC_MODEL_NOT_READY")
    return reply


def check(cfg, deadline):
    """Fresh checks under the caller's budget; never load a model here."""
    graph = _graph(cfg, deadline)
    settings = cfg.semantic
    name = settings.model if ":" in settings.model else settings.model + ":latest"
    installed = next((m for m in _get(settings, "/api/tags", deadline) if m.get("name") == name), {})
    digest = installed.get("digest")
    if not digest or not any(m.get("name") == name and m.get("digest") == digest
                            and m.get("context_length") == 8192
                            for m in _get(settings, "/api/ps", deadline)):
        raise GraphReadUnavailable("SEMANTIC_MODEL_NOT_READY")
    return {"state": "ready", "model": name, "digest": digest,
            "embedding_fingerprint": graph["modelFingerprint"], "observed_at": graph["observedAt"]}


def prepare(cfg):
    """Bounded neutral warm-up; no user input, graph rebuild, or model download."""
    start = time.monotonic()
    try:
        if not cfg.semantic.ready:
            raise GraphReadUnavailable("SEMANTIC_CONFIG_REQUIRED")
        with model_lane():
            deadline = start + 60
            # Identical options/context to inference, so preparation does not warm
            # a different model instance. Keep actual evaluation cases out of it.
            _local_model(cfg.semantic, {"origin": "in-user-prompt", "input": "Hello.", "graph_evidence": []}, deadline)
            _graph(cfg, deadline, warmup=True)
            result = check(cfg, deadline)
    except Exception as exc:
        result = {"state": "unavailable", "code": getattr(exc, "code", "SEMANTIC_PREPARATION_FAILED")}
    return {**result, "preparation_seconds": time.monotonic() - start}
