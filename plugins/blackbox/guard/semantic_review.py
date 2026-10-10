"""Profile-bound, capacity-bounded semantic advisory work."""
import threading

from .. import audit, detection, semantic
from ..kernel import constants, threat_ids
from . import reporting

_lock = threading.Lock()
_active = set()


def warmup(cfg):
    schedule(cfg, [], {"prepare_models": True})


def schedule(cfg, sources, detail):
    settings = getattr(cfg, "semantic", None)
    if not settings or not settings.enabled:
        return
    key = str(constants.hermes_home().resolve())
    with _lock:
        if key in _active or len(_active) >= 2:
            audit.record(event="semantic_review", detail={"state": "unavailable", "code": "SEMANTIC_REVIEW_BUSY"})
            return
        _active.add(key)
    try:
        from agent.memory_provider import spawn_context_thread
        spawn_context_thread(_run, name="blackbox-semantic", args=(key, cfg, list(sources), dict(detail))).start()
    except Exception:
        with _lock:
            _active.discard(key)
        audit.record(event="semantic_review", detail={"state": "unavailable", "code": "SEMANTIC_WORKER_UNAVAILABLE"})


def _run(key, cfg, sources, detail):
    try:
        if detail.get("prepare_models"):
            audit.record(event="semantic_warmup", detail=semantic.prepare(cfg))
            return
        if len(sources) > 4:
            audit.record(event="semantic_review", detail={"state": "unavailable", "code": "SEMANTIC_SOURCE_LIMIT"})
            return
        for origin, text in sources:
            result = semantic.assess(cfg, text, origin)
            _record(cfg, result, origin, detail)
    finally:
        with _lock:
            _active.discard(key)


def _record(cfg, result, origin, detail):
    findings = []
    if result.verdict:
        v = result.verdict
        findings.append(detection.Finding(identifier=f'{v["category"]}:semantic:{threat_ids.stable_hash(v["entity_uri"], 12)}',
            category=v["category"], severity="high", title="Semantic advisory", evidence=v["input_quote"],
            matched=v["reason"], confirmed=False, source="llm"))
    evidence = [{k: v for k, v in item.items() if k != "text"} for item in result.evidence]
    # source=llm uses the existing never-share policy and is never a blocking input.
    reporting._report_and_audit(cfg, "semantic_review", reporting._flag_worthy(cfg, findings),
        {**detail, "semantic": {"state": result.state, "code": result.code, "origin": origin,
                               "retrieval": result.retrieval, "evidence": evidence, "verdict": result.verdict}})
