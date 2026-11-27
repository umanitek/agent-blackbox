"""Prompt-injection check of TEXT an agent is about to send or read — for a runtime that is not
Hermes (a coding agent's own hooks: Claude Code, Codex, Cursor, Gemini CLI …).

Hermes scans a model request as it leaves (:func:`.hooks.on_pre_api_request`, observer-only: it
blocks at the tool call). A coding agent has no such hook; what it offers is a hook on the user's
prompt before it is sent and one on a tool's output before the model sees it. This answers for
those: the same injection patterns (the verified graph's injection tier, plus the built-in
heuristics as discovery candidates when ``discover`` is on), the same flag / block rules as a
tool call — only a VERIFIED pattern (``confirmed``) can block, and only in Block mode at or
above ``block_severity``; a heuristic match only flags. Nothing is recorded or reported here:
the asking runtime records under its own agent's name. The text never leaves this process.

Usage::

    verdict = guard.text_verdict([("in-tool-output", page_text)])
    verdict["decision"]   # "", "flag", "flag (local override)" or "block"
"""

from __future__ import annotations

from typing import Sequence

from .. import shields
from ..kernel import constants
from . import api_request, graph_rules, hooks, reporting
from .hooks import ToolCallVerdict
from .reporting import blackbox_block_message

#: The most text one check reads per source (a tool's whole output can be large).
MAX_TEXT_CHARS = 256 * 1024


def text_verdict(texts: Sequence[tuple[str, str]]) -> ToolCallVerdict:
    """What Blackbox makes of *texts* — ``(context, text)`` pairs, context one of
    ``constants.INJECTION_CONTEXTS`` (an unknown context is read as ``in-tool-output``).
    Raises on failure (the caller fails open)."""
    sources = [(context if context in constants.INJECTION_CONTEXTS else "in-tool-output", str(text or "")[:MAX_TEXT_CHARS])
               for context, text in texts if text]
    if not sources:
        return ToolCallVerdict(findings=[], blocked=[], decision="", message="", notes=[])
    cfg = hooks._config()   # through the module: one config source with the tool-call hook
    rules, _evidence = graph_rules.detection_rules(cfg, "", {})
    findings = api_request._injection_by_source(sources, rules, cfg.discover)
    active = shields.snapshot()
    # A prompt that names an item the person protected (File Shield): flagged, never kept.
    findings += shields.prompt_findings([text for context, text in sources if context == "in-user-prompt"], active)
    findings = reporting._flag_worthy(cfg, findings, active)
    blocking, overridden = hooks._split(cfg, findings)   # overrides read once
    decision = hooks._decision(cfg, findings, blocking, overridden) if findings else ""
    return ToolCallVerdict(findings=[finding.to_dict() for finding in findings],
                           blocked=[finding.identifier for finding in blocking], decision=decision,
                           message=blackbox_block_message(blocking, sources[0][0] if len({c for c, _ in sources}) == 1 else "text")
                           if blocking else "", notes=[])
