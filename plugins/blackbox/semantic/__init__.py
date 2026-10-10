"""Opt-in graph retrieval and local advisory review, independent of regex hits."""
import time
from dataclasses import dataclass, field

from ..kernel import redaction
from ..ruleset import semantic_candidates
from .reviewer import review
from .readiness import check, model_lane, prepare


@dataclass
class SemanticResult:
    state: str
    code: str = ""
    verdict: dict | None = None
    evidence: list = field(default_factory=list)
    retrieval: dict = field(default_factory=dict)


def assess(cfg, text, origin, *, retrieve=None, classify=None, ready=None):
    settings = getattr(cfg, "semantic", None)
    if not settings or not settings.enabled:
        return SemanticResult("disabled")
    if not settings.ready:
        return SemanticResult("unavailable", "SEMANTIC_CONFIG_REQUIRED")
    deadline = time.monotonic() + settings.budget_s
    # Redact the entire bounded input before inference or embedding; no credential reads.
    if not isinstance(text, str) or len(text) > 16_000:
        return SemanticResult("unavailable", "SEMANTIC_INPUT_LIMIT")
    text = redaction.redact_secret_values(text)
    if not text.strip():
        return SemanticResult("no-input")
    if len(text) > 6000:
        return SemanticResult("unavailable", "SEMANTIC_INPUT_LIMIT")
    try:
        # Explicit injected transports are a unit-test seam; production always
        # checks live residency. Instrumented evaluations can pass ready=check.
        if ready is not None or (retrieve is None and classify is None):
            (ready or check)(cfg, deadline)
        evidence, status = (retrieve or semantic_candidates)(cfg, text)
        if time.monotonic() >= deadline:
            raise TimeoutError()
        # Redact graph evidence as well; it is data, never instructions.
        evidence = [{**item, "text": redaction.redact_secret_values(item["text"])} for item in evidence]
        if not evidence:
            return SemanticResult("no-candidates", evidence=evidence, retrieval=status)
        with model_lane():
            verdict = review(cfg, text, origin, evidence, deadline=deadline, call=classify)
        if time.monotonic() >= deadline:
            raise TimeoutError()
        return SemanticResult("advisory" if verdict else "no-finding", verdict=verdict, evidence=evidence, retrieval=status)
    except TimeoutError:
        return SemanticResult("unavailable", "SEMANTIC_DEADLINE_EXCEEDED")
    except Exception as exc:
        code = getattr(exc, "code", "SEMANTIC_REVIEW_UNAVAILABLE")
        if isinstance(exc, ValueError) and str(exc) in {"SEMANTIC_REVIEW_INPUT_LIMIT", "SEMANTIC_REVIEW_INVALID", "SEMANTIC_REVIEW_UNGROUNDED"}:
            code = str(exc)
        return SemanticResult("unavailable", code)


from .command import add_semantic_parser

__all__ = ["add_semantic_parser", "assess", "SemanticResult", "prepare", "check"]
