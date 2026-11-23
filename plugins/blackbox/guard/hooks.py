"""The five Hermes hook entry points — every tool call and model request passes here.

``on_pre_tool_call`` / ``on_pre_api_request`` run detection BEFORE execution
and may block (block mode, verified rules only); ``on_post_tool_call`` logs
local activity and starts background discovery; ``on_session_start`` /
``on_session_end`` manage per-session context. Fail-open at every boundary: a
Blackbox fault must never break the host agent.
"""

from __future__ import annotations

import functools
import json
import logging
from dataclasses import dataclass
from typing import Any, Callable, Optional, TypedDict
from .. import audit, detection, killlist, overrides, shields
from ..kernel import action_context, config as config_mod, constants
from ..kernel.config import BlackboxConfig
from . import api_request, background, graph_rules
from . import injection_sites
from . import reporting
from .reporting import blackbox_block_message
from . import dependency_files, host_process, session_context
from .activity import record_activity as _record_activity

logger = logging.getLogger(__name__)


def _config() -> BlackboxConfig:
    return config_mod.load_blackbox_config()


# ---------------------------------------------------------------------------
# Hook handlers
# ---------------------------------------------------------------------------


def _kill_list_findings(rs: Any, tool_name: str, args: Any) -> list[detection.Finding]:
    """R14: the kill-list finding for this call, if any (fail-open: a bad cached list kills nothing)."""
    try:
        found = killlist.finding_for(killlist.KillList.from_cache(getattr(rs, "kill_list", None)), tool_name, args)
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: kill-list check skipped: %s", exc)
        return []
    return [found] if found is not None else []


def _decision(cfg: BlackboxConfig, findings: list[detection.Finding], blocking: list[detection.Finding]) -> str:
    """What the hook DID, for the audit row: "block", "flag", or "flag (local override)"
    when a verified rule would have blocked but the operator unblocked it here (R7b)."""
    if blocking:
        return "block"
    return "flag (local override)" if _overridden(cfg, findings) else "flag"


def _decision_detail(cfg: BlackboxConfig, findings: list[detection.Finding],
                     blocking: list[detection.Finding]) -> dict[str, Any]:
    """The audit row's ``decision`` and, when something blocked, ``blocked`` —
    which findings did, so each report can say blocked or flagged (threat-profiles D3)."""
    out: dict[str, Any] = {"decision": _decision(cfg, findings, blocking)}
    if blocking:
        out["blocked"] = [f.identifier for f in blocking]
    return out


def _overridden(cfg: BlackboxConfig, findings: list[detection.Finding]) -> list[detection.Finding]:
    """Findings a local override keeps from blocking (empty unless block mode is on)."""
    try:
        unblocked = overrides.OverrideStore().unblocked()
    except Exception:  # pragma: no cover - fail open: no store, no override
        return []
    return overrides.demote_blocking(_would_block(cfg, findings), unblocked)[1] if unblocked else []


def _blocking(cfg: BlackboxConfig, findings: list[detection.Finding]) -> list[detection.Finding]:
    """The findings that block this call: :func:`_would_block` minus the
    operator's local overrides (R7b — a reduction every operator keeps)."""
    would = _would_block(cfg, findings)
    if not would:
        return []
    try:
        unblocked = overrides.OverrideStore().unblocked()
    except Exception:  # pragma: no cover - fail open to the published rule
        return would
    return overrides.demote_blocking(would, unblocked)[0]


def _would_block(cfg: BlackboxConfig, findings: list[detection.Finding]) -> list[detection.Finding]:
    """The findings that block this call (empty unless block mode is on).

    Confirmed findings and custom rules block; community/heuristic ones only
    alert. ``vulnerability`` kind never blocks (a legit-but-vulnerable package
    must keep working), nor ``flag-only`` (a local rule's community-sourced or
    routine finding, KI-385) — only ``malware`` is stopped. IOC findings alert but
    never auto-block in this rollout: network and crypto-address blocklists
    are higher-churn / higher-FP than pinned package versions, so they are
    validated in audit mode first.
    """
    # Refused in EVERY mode: Blackbox's own core (2026-11-20 — in Audit mode an agent could switch
    # the guard off and was merely flagged for it) and what the person protected with File Shield
    # (2026-11-21: their own explicit rule). Nothing else blocks unless Block mode is on.
    always = [f for f in findings if f.matched in detection.ALWAYS_BLOCKED_MATCHES]
    if not cfg.block_enabled:
        return always
    return always + [
        f for f in findings
        if (f.confirmed or f.source in ("custom", "secret"))
        and getattr(f, "kind", None) not in (constants.KIND_VULNERABILITY, "historical", detection.KIND_FLAG_ONLY)
        and f.category != "ioc"
        and cfg.meets_block_threshold(f.severity) and f not in always
    ]


def _raw_findings(cfg: BlackboxConfig, rs: Any, tool_name: str, args: Any,
                  active: shields.ShieldsSnapshot, notes: Optional[list[str]] = None) -> list[detection.Finding]:
    """All raw findings for one call, gathered here so new detectors join without growing the hook body.
    What could not be checked is added to *notes* (None: not kept)."""
    notes = [] if notes is None else notes
    isolated = detection.run_isolated   # each check on its own: one that raises costs only its findings
    raw = detection.detect_all(tool_name, args, rs, discover=cfg.discover)
    raw += isolated("detect_custom_fileaccess",
                    lambda: detection.detect_custom_fileaccess(tool_name, args, cfg.protected_paths))
    raw += shields.check(tool_name, args, active)
    # KI-473: an agent never switches its guard off.
    raw += isolated("detect_guard_tamper", lambda: detection.detect_guard_tamper(tool_name, args, cfg))
    # An agent asking for root is made visible (a flag, never a refusal: D7 leaves sudo alone).
    raw += isolated("detect_elevation", lambda: detection.detect_elevation(tool_name, args))
    # R14: curator-signed DISABLE / WARN, last-good list.
    raw += isolated("kill_list", lambda: _kill_list_findings(rs, tool_name, args))
    # KI-595: the manifests and lockfiles an install installs from, and packages a write adds to them.
    raw += isolated("dependency_files", lambda: dependency_files.before_call(cfg, rs, tool_name, args, notes))
    return raw


def _normalised_call(tool_name: Any, args: Any) -> tuple[str, Any]:
    """``(tool_name, args)`` the checks can read: the name as text, and *args* as the object it
    encodes when a host hands the arguments over as JSON text (Hermes passes a dict; another host,
    or a raw model reply, may pass the string) — the same fields are checked either way."""
    name = tool_name if isinstance(tool_name, str) else str(tool_name or "")
    if isinstance(args, str) and args.lstrip().startswith("{"):
        try:
            parsed = json.loads(args)
        except (ValueError, RecursionError):   # not JSON, or nested too deep to parse: checked as text
            return name, args
        return name, parsed if isinstance(parsed, dict) else args
    return name, args


def _with_normalised_call(hook: Callable[..., Any]) -> Callable[..., Any]:
    """Run *hook* on :func:`_normalised_call`'s ``(tool_name, args)`` — an odd shape there once made
    detection raise, and a raising hook lets the call through (fail-open)."""
    @functools.wraps(hook)
    def wrapper(tool_name: Any = "", args: Any = None, **kwargs: Any) -> Any:
        name, normalised = _normalised_call(tool_name, args)
        return hook(tool_name=name, args=normalised, **kwargs)
    return wrapper


@dataclass(frozen=True)
class _Judgement:
    """What the checks make of one tool call: the rules they ran on (and how they were read),
    the findings worth flagging, and the ones that block. Built once by :func:`_judge` for both
    the Hermes hook and :func:`tool_call_verdict`, so the two can never disagree."""

    cfg: BlackboxConfig
    rules: Any
    graph_evidence: Any
    findings: list[detection.Finding]
    blocking: list[detection.Finding]
    notes: list[str]   # what could not be checked ("dependencies not checked: …"), said on the session


def _judge(tool_name: str, args: Any, cwd: str = "") -> _Judgement:
    """The checks on one call run in the folder *cwd* (``kernel.action_context``: a script a
    command names by a relative path is the one there)."""
    cfg = _config()
    rs, graph_evidence = graph_rules.detection_rules(cfg, tool_name, args)
    active = shields.snapshot()   # every shield's mode, read once for this call
    notes: list[str] = []
    with action_context.working_in(cwd):
        findings = reporting._flag_worthy(cfg, _raw_findings(cfg, rs, tool_name, args, active, notes), active)
    return _Judgement(cfg, rs, graph_evidence, findings, _blocking(cfg, findings), notes)


class ToolCallVerdict(TypedDict):
    """:func:`tool_call_verdict`'s (and :func:`after_tool_call_verdict`'s) answer. ``findings``
    are ``Finding.to_dict()`` rows; ``blocked`` the identifiers that block; ``decision`` is "",
    "flag", "flag (local override)" or "block"; ``message`` what the agent is told when blocked
    ("" otherwise); ``notes`` what could not be checked, for the caller to record on its session."""

    findings: list[dict[str, Any]]
    blocked: list[str]
    decision: str
    message: str
    notes: list[str]


@_with_normalised_call
def tool_call_verdict(tool_name: str = "", args: Any = None, cwd: str = "", **_: Any) -> ToolCallVerdict:
    """What Blackbox makes of one tool call, for a runtime that is not Hermes (2026-11-20).

    The OpenClaw plugin asks this through the dashboard (``POST /api/guard/verdict``) before
    each tool call, so an OpenClaw agent is judged by the SAME checks as a Hermes agent — the
    verified threat graph, the protected paths, every shield, the kill list, local overrides —
    instead of by a second copy of them. Nothing is recorded or reported here: the asking
    runtime records the finding under its own agent's name. Raises on failure (the caller then
    falls back to its own built-in checks).

        verdict = guard.tool_call_verdict("exec", {"command": "npm install left-pad"})
        verdict["decision"], verdict["blocked"], verdict["message"]

    *cwd*: the folder the agent runs the call in (its hook names it), so a script a command names
    by a relative path is the right file (``kernel.action_context``).
    """
    judged = _judge(tool_name, args, cwd)
    decision = _decision(judged.cfg, judged.findings, judged.blocking) if judged.findings else ""
    return ToolCallVerdict(findings=[finding.to_dict() for finding in judged.findings],
                           blocked=[finding.identifier for finding in judged.blocking], decision=decision,
                           message=blackbox_block_message(judged.blocking) if judged.blocking else "", notes=judged.notes)


@_with_normalised_call
def after_tool_call_verdict(tool_name: str = "", args: Any = None, cwd: str = "", **_: Any) -> ToolCallVerdict:
    """What Blackbox makes of one tool call AFTER it ran, for a runtime that is not Hermes: the
    packages an install added to its lockfile (``dependency_files.after_check``, the same check
    the Hermes post hook runs — KI-602). Never blocks (it already ran): a listed package that
    landed is a flag, critical when verified, whose advice names the removal. Records nothing.

        verdict = guard.after_tool_call_verdict("terminal", {"command": "npm install express"}, cwd="/app")
    """
    check = dependency_files.after_check(_config(), tool_name, args, cwd)
    return ToolCallVerdict(findings=[finding.to_dict() for finding in check.findings], blocked=[],
                           decision="flag" if check.findings else "", message="", notes=check.notes)


@_with_normalised_call
def on_pre_tool_call(
    tool_name: str = "",
    args: Any = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    **_: Any,
) -> Optional[dict[str, str]]:
    """Detect threats; audit + report; block in block mode for ≥ block_severity.

    Only CONFIRMED graph findings can block; discovery candidates only alert.
    """
    try:
        judged = _judge(tool_name, args, host_process.facts()["cwd"])   # in this Hermes process's folder
        cfg, findings, blocking = judged.cfg, judged.findings, judged.blocking
        dependency_files.record_notes(judged.notes, tool_name, session_id)
        _record_activity(tool_name, args)   # visibility: log every file-access tool call (best-effort)
        detail = {"tool_name": tool_name, "session_id": session_id, "task_id": task_id,
                  "tool_call_id": tool_call_id, "args": audit.redact(args), "graph_read": judged.graph_evidence}
        if findings:   # conversation context only when a finding needs it
            ctx = session_context._tool_context(session_id, args)
            if ctx:
                detail["context"] = ctx
            # KI-189: the audit row says what the hook DID, not only what it saw —
            # R10's "a revoked threat blocked N actions here" counts these.
            detail.update(_decision_detail(cfg, findings, blocking))
        reporting._report_and_audit(cfg, "pre_tool_call", findings, detail)
        background.review_tool(cfg, tool_name, args, detail)
        # OSV auto-discovery runs off the blocking path so a network lookup
        # never delays or breaks the tool call.
        if cfg.discover and cfg.osv_lookup:
            background._spawn_osv_discovery(cfg, judged.rules, tool_name, args)
        if blocking:
            return {"action": "block", "message": blackbox_block_message(blocking)}
        return None
    except Exception as exc:  # pragma: no cover - fail open, said out loud (FIX-0160)
        reporting.hook_failed("pre_tool_call", exc, tool_name=tool_name, consequence="the action passed unchecked")
        return None


def _is_blackbox_assistant() -> bool:
    """True inside Blackbox's own assistant (its Hermes profile, ``constants.BLACKBOX_CHAT_PROFILE``)."""
    home = constants.hermes_home()
    return home.name == constants.BLACKBOX_CHAT_PROFILE and home.parent.name == "profiles"


def _recorded_findings() -> set[tuple[str, str]]:
    """``(identifier, evidence)`` of the findings already in Blackbox's log (the log's own cache)."""
    rows = audit.read_findings(limit=1000)
    return {(str(row.get("identifier") or ""), str(row.get("evidence") or "")) for row in rows}


def on_post_tool_call(
    tool_name: str = "",
    args: Any = None,
    result: Any = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    duration_ms: int = 0,
    **_: Any,
) -> None:
    """Audit the redacted tool result. Never blocks."""
    try:
        audit.record(
            event="post_tool_call",
            detail={
                "tool_name": tool_name,
                "session_id": session_id,
                "task_id": task_id,
                "tool_call_id": tool_call_id,
                "duration_ms": duration_ms,
                "result": audit.redact(result),
            },
        )
    except Exception as exc:  # pragma: no cover - fail open, said out loud (FIX-0160)
        reporting.hook_failed("post_tool_call", exc, tool_name=tool_name, consequence="the result was not audited")
    # KI-595: what an install added to its lockfile (a named install's transitive packages). Fail-open.
    dependency_files.after_call(_config, tool_name, args, session_id, tool_call_id)




def on_pre_api_request(**kwargs: Any) -> None:
    """Scan current user/tool input for prompt-injection patterns.

    Observer-only: blocking happens at the tool call, not here.
    """
    try:
        cfg = _config()
        # The query selects the bounded curated pattern tier; prompt text
        # stays in this process and is matched by the existing safe scanner.
        rs, graph_evidence = graph_rules.detection_rules(cfg, "", {})
        sources = api_request._untrusted_request_sources(kwargs.get("user_message"), kwargs.get("request_messages"))
        text = "\n".join(part for _, part in sources)   # the LLM reviewer's input
        findings = api_request._injection_by_source(sources, rs, cfg.discover) + detection.detect_model_request_secrets(sources)   # KI-381
        findings += injection_sites.injection_site_findings(findings, kwargs.get("request_messages"), rs)   # D8
        if _is_blackbox_assistant():   # it reads Blackbox's own findings back: an old one is not a new attack
            findings = api_request.drop_record_echoes(findings, sources, api_request.tool_output_texts(sources),
                                                      _recorded_findings())
        active = shields.snapshot()
        # A prompt that names an item the person protected (File Shield): flagged, never kept.
        findings += shields.prompt_findings([part for context, part in sources if context == "in-user-prompt"], active)
        findings = reporting._flag_worthy(cfg, findings, active)
        detail = {
            "graph_read": graph_evidence,
            "session_id": kwargs.get("session_id"),
            "task_id": kwargs.get("task_id"),
            "turn_id": kwargs.get("turn_id"),
            "model": kwargs.get("model"),
            "provider": kwargs.get("provider"),
        }
        # Always warm the per-session store (so later tool-call findings can show
        # the turn); attach as context only when this request produced a finding.
        turns = session_context._conversation_turns(kwargs.get("user_message"), kwargs.get("request_messages"))
        session_context._remember_convo(str(kwargs.get("session_id") or ""), turns)
        findings = api_request._dedupe_api_findings(findings, detail)
        if findings and turns:
            detail["context"] = {"turns": turns}
        reporting._report_and_audit(cfg, "pre_api_request", findings, detail)
        # Optional LLM second opinion, off-thread so it never delays the request.
        background.review_request(cfg, sources, text, detail)
    except Exception as exc:  # pragma: no cover - fail open, recorded
        reporting.hook_failed("pre_api_request", exc, consequence="the request passed unchecked")


def on_session_start(session_id: str = "", **kwargs: Any) -> None:
    try:
        # The Hermes agent picked for File Shield's sandbox: its terminal tool's shells and its
        # execute_code Python start inside it.
        cover = shields.enter_hermes_process()
        # Where it works, its process, how it started, its model and what of it is sandboxed:
        # the instance tree's facts (KI-572, KI-580).
        audit.record(event="session_start", detail={"session_id": session_id, "model": str(kwargs.get("model") or "")[:80],
                                                     "shells_sandboxed": cover.shells is True,
                                                     "code_sandboxed": cover.execute_code is True,
                                                     "sandbox_note": str(cover.note)[:200],
                                                     **host_process.facts(str(kwargs.get("platform") or ""))})
        cfg = _config()
        background._spawn_auto_attach(cfg)
        from . import semantic_review
        semantic_review.warmup(cfg)
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: on_session_start failed: %s", exc)


def on_session_end(session_id: str = "", completed: bool = True, interrupted: bool = False, **kwargs: Any) -> None:
    try:
        session_context._forget_convo(session_id)
        audit.record(
            event="session_end",
            detail={"session_id": session_id, "completed": completed, "interrupted": interrupted},
        )
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: on_session_end failed: %s", exc)
