"""Opt-in, local-only semantic review settings."""
from dataclasses import dataclass
import re


@dataclass(frozen=True)
class SemanticConfig:
    enabled: bool = False
    index_id: str = ""
    model: str = ""
    model_url: str = "http://127.0.0.1:11434"
    max_candidates: int = 5
    budget_s: float = 12.0

    @property
    def ready(self):
        return self.enabled and bool(re.fullmatch(r"[a-f0-9]{64}", self.index_id)) and bool(self.model)


def semantic_config(entry):
    raw = entry.get("semantic") or {}
    if not isinstance(raw, dict):
        return SemanticConfig()
    try:
        return SemanticConfig(enabled=raw.get("enabled") is True, index_id=str(raw.get("index_id", "")),
                              model=str(raw.get("model", "")), model_url=str(raw.get("model_url", "http://127.0.0.1:11434")),
                              max_candidates=min(10, max(1, int(raw.get("max_candidates", 5)))),
                              budget_s=min(30.0, max(1.0, float(raw.get("budget_s", 12)))))
    except (TypeError, ValueError):
        return SemanticConfig()
