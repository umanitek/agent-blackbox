"""Blackbox hook handlers.

Five hooks, all fail-open (broad ``try/except`` around every handler — a
Blackbox bug must never break the agent loop):

* ``pre_tool_call`` — detect, audit, report, and (block mode only) block.
* ``post_tool_call`` — audit the redacted result.
* ``pre_api_request`` — scan the prompt/messages for injection (observer only).
* ``on_session_start`` / ``on_session_end`` — lifecycle audit; session start also
  re-runs the attach sweep in the background (throttled) so agents installed
  after Blackbox get protected without a manual ``hermes blackbox attach``.

Blocking contract matches ``security-guidance``:
``return {"action": "block", "message": ...}`` in block mode, ``None`` otherwise.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Any, Dict, List, Optional

from . import audit, config as config_mod, constants, detection, quads, ruleset
from .config import BlackboxConfig
from .dkg_client import DkgClient, DkgError

logger = logging.getLogger(__name__)


def _config() -> BlackboxConfig:
    return config_mod.load_blackbox_config()


def blackbox_block_message(findings: List[detection.Finding]) -> str:
    """Human-readable block message summarizing the blocking findings."""
    lines = [
        "Blackbox blocked this tool call — it matched "
        f"{len(findings)} known threat{'s' if len(findings) != 1 else ''} in the threat graph:",
        "",
    ]
    for f in findings:
        lines.append(f"- [{f.severity.upper()}] {f.category}: {f.title} ({f.identifier})")
    lines.append("")
    lines.append(
        "Treat the source content as untrusted. If this is a false positive, "
        "switch Blackbox to audit mode and report the identifier to Umanitek."
    )
    return "\n".join(lines)


def _flag_worthy(cfg: BlackboxConfig, findings: List[detection.Finding]) -> List[detection.Finding]:
    """Apply the user's detection policy to raw findings.

    * Per-category policy (``detection.<category>.{enabled,min_severity}``):
      disabled categories never flag; the floor drops anything below it.
    * Heuristic gate: discovery candidates additionally need
      ``report_min_severity`` — they are nominations, not confirmed threats.

    Custom rules (``source == "custom"``) bypass the category policy.
    """
    out: List[detection.Finding] = []
    for f in findings:
        if f.source == "custom":
            out.append(f)
            continue
        if not cfg.category_allows(f.category, f.severity):
            continue
        if f.source == "heuristic" and not cfg.meets_report_threshold(f.severity):
            continue
        out.append(f)
    return out


def _report_and_audit(cfg: BlackboxConfig, event: str, findings: List[detection.Finding], detail: Dict[str, Any]) -> None:
    """Audit findings locally; never publish them to community SWM."""
    finding_dicts = [f.to_dict() for f in findings]
    audit.record(event=event, findings=finding_dicts or None, detail=detail)
    if not findings:
        return
    client: Optional[DkgClient] = None
    try:
        client = DkgClient(url=cfg.dkg_url, dkg_home=cfg.dkg_home)
    except Exception:
        client = None
    for finding in finding_dicts:
        # Custom rules, LLM opinions, and secret findings stay local — no private
        # KA, no sighting. Secret values must never risk reaching the shared graph.
        if finding.get("source") in ("custom", "llm", "secret"):
            continue
        identifier = str(finding.get("identifier") or "")
        # Per-threat cooldown: a re-fire within the window adds no signal.
        if audit.recently_reported(identifier):
            continue
        # Private WM audit KA (observed evidence stays local). Stamp the cooldown
        # here so it bounds the KA independently of whether a sighting is sent.
        if client is not None:
            audit.mark_reported(identifier)
            audit.write_private_audit_ka(client, cfg.context_graph_id, event, finding)
        # Outbound sharing is closed until the community graph ships. Findings
        # and their private audit evidence remain local.


def _share_sighting(client: DkgClient, cfg: BlackboxConfig, finding: Dict[str, Any]) -> None:
    try:
        reporter = _reporter_address(client)
        # Reports contain signatures, never raw prompts, paths, or source files.
        fields = finding.get("fields") if isinstance(finding.get("fields"), dict) else {}
        q = quads.build_report_quads(
            identifier=str(finding.get("identifier") or ""),
            category=str(finding.get("category") or ""),
            severity=str(finding.get("severity") or "info"),
            reporter_address=reporter,
            framework="hermes",
            **{k: v for k, v in fields.items() if v is not None},
        )
        name = f"report-{quads.stable_hash(str(finding.get('identifier')) + reporter, 16)}"
        client.share_knowledge_asset(cfg.context_graph_id, name, q)
    except DkgError as exc:
        logger.debug("blackbox: sighting share failed: %s", exc)
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: sighting share error: %s", exc)


_reporter_cache: Dict[str, str] = {}
_seen_api_findings: Dict[tuple, float] = {}
_API_FINDING_DEDUPE_TTL_SECS = 10 * 60


def _reporter_address(client: DkgClient) -> str:
    """Resolve this node's agent address (cached). Falls back to ``node``.

    ``agent_identity`` is definitive; ``status`` is a fallback for older daemons.
    """
    if "addr" in _reporter_cache:
        return _reporter_cache["addr"]
    addr = "node"
    for resolver in (client.agent_identity, client.status):
        try:
            info = resolver()
        except Exception:
            continue
        if not isinstance(info, dict):
            continue
        for key in ("agentAddress", "defaultAgentAddress", "address"):
            val = info.get(key)
            if isinstance(val, str) and val:
                addr = val
                break
        if addr != "node":
            break
    _reporter_cache["addr"] = addr
    return addr


def _dedupe_api_findings(findings: List[detection.Finding], detail: Dict[str, Any]) -> List[detection.Finding]:
    """Drop repeated pre-api findings from additional model calls in one turn."""
    turn_key = str(detail.get("turn_id") or detail.get("task_id") or detail.get("session_id") or "")
    if not turn_key:
        return findings
    now = time.time()
    for key, seen_at in list(_seen_api_findings.items()):
        if now - seen_at > _API_FINDING_DEDUPE_TTL_SECS:
            _seen_api_findings.pop(key, None)
    out: List[detection.Finding] = []
    for finding in findings:
        key = (turn_key, finding.identifier, finding.evidence or finding.matched or finding.title)
        if key in _seen_api_findings:
            continue
        _seen_api_findings[key] = now
        out.append(finding)
    return out


# ---------------------------------------------------------------------------
# Conversation context capture (local-only, redacted)
# ---------------------------------------------------------------------------
#
# Findings carry a small ``context`` snapshot so the dashboard modal can render
# the whole turn (injected prompt + response). Blackbox is a request-side
# observer, so the "response" is reconstructed from ``request_messages`` (which
# carries prior assistant/tool turns) and the tool call. Redacted + capped, and
# LOCAL-ONLY — it never enters ``Finding.fields`` or an SWM sighting.

_CONTEXT_TURNS = 12           # keep the last N conversation turns
_CONTEXT_TURN_CHARS = 3000    # per-turn cap, sized to show the whole message
_CONTEXT_INPUT_CHARS = 6000   # tool-input cap
_MAX_TRACKED_SESSIONS = 256

# Last conversation snapshot per session, captured at ``pre_api_request`` so a
# later tool-call finding (which has no conversation access) can still show the
# surrounding turns. Bounded, best-effort.
_last_convo: Dict[str, List[Dict[str, str]]] = {}
_convo_lock = threading.Lock()


def _message_role(msg: Dict[str, Any]) -> str:
    role = str(msg.get("role") or "").lower()
    return role if role in ("user", "assistant", "system", "tool") else "user"


def _message_text(content: Any) -> str:
    """Flatten a message's ``content`` (str, or a list of text parts) to text."""
    if isinstance(content, str):
        return content
    parts: List[str] = []
    if isinstance(content, list):
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
    return "\n".join(p for p in parts if p)


def _conversation_turns(user_message: Any, request_messages: Any) -> List[Dict[str, str]]:
    """Build a capped, redacted ``[{role, text}]`` from the request messages.

    Falls back to ``user_message`` when the messages list is unavailable.
    """
    turns: List[Dict[str, str]] = []
    msgs = request_messages if isinstance(request_messages, list) else []
    # Only the tail matters; cap the scan so a long history doesn't cost us on
    # the synchronous request path.
    for msg in msgs[-(_CONTEXT_TURNS * 3):]:
        if not isinstance(msg, dict):
            continue
        text = _message_text(msg.get("content"))
        if not text.strip():
            continue
        turns.append({
            "role": _message_role(msg),
            "text": audit.sanitize_text(text, _CONTEXT_TURN_CHARS),
        })
    if not turns:
        um = str(user_message or "").strip()
        if um:
            turns.append({"role": "user", "text": audit.sanitize_text(um, _CONTEXT_TURN_CHARS)})
    return turns[-_CONTEXT_TURNS:]


def _remember_convo(session_id: str, turns: List[Dict[str, str]]) -> None:
    if not session_id or not turns:
        return
    try:
        with _convo_lock:
            # Size bound: drop everything at the ceiling (best-effort cache).
            if session_id not in _last_convo and len(_last_convo) >= _MAX_TRACKED_SESSIONS:
                _last_convo.clear()
            _last_convo[session_id] = turns
    except Exception:  # pragma: no cover - fail open
        pass


def _recent_convo(session_id: str) -> List[Dict[str, str]]:
    if not session_id:
        return []
    try:
        with _convo_lock:
            return list(_last_convo.get(session_id) or [])
    except Exception:  # pragma: no cover - fail open
        return []


def _forget_convo(session_id: str) -> None:
    try:
        with _convo_lock:
            _last_convo.pop(session_id, None)
    except Exception:  # pragma: no cover - fail open
        pass


def _tool_context(session_id: str, args: Any) -> Optional[Dict[str, Any]]:
    """Context for a tool-call finding: the scanned tool input + recent turns."""
    ctx: Dict[str, Any] = {}
    turns = _recent_convo(session_id)
    if turns:
        ctx["turns"] = turns
    try:
        scanned = detection._injection_scan_text(args)
    except Exception:  # pragma: no cover - fail open
        scanned = ""
    if scanned.strip():
        ctx["input"] = audit.sanitize_text(scanned, _CONTEXT_INPUT_CHARS)
    return ctx or None


# ---------------------------------------------------------------------------
# Hook handlers
# ---------------------------------------------------------------------------


def on_pre_tool_call(
    tool_name: str = "",
    args: Any = None,
    task_id: str = "",
    session_id: str = "",
    tool_call_id: str = "",
    **_: Any,
) -> Optional[Dict[str, str]]:
    """Detect threats; audit + report; block in block mode for ≥ block_severity.

    Only CONFIRMED graph findings can block; discovery candidates only alert.
    """
    try:
        cfg = _config()
        rs = ruleset.get(cfg)
        # Visibility: log every file-access tool call (best-effort).
        _record_activity(tool_name, args)
        raw = detection.detect_all(tool_name, args, rs, discover=cfg.discover)
        raw += detection.detect_custom_fileaccess(tool_name, args, cfg.protected_paths)
        findings = _flag_worthy(cfg, raw)
        detail = {
            "tool_name": tool_name,
            "session_id": session_id,
            "task_id": task_id,
            "tool_call_id": tool_call_id,
            "args": audit.redact(args),
        }
        # Build the heavier conversation context only on a finding, so routine
        # tool calls stay lean in the audit log.
        if findings:
            ctx = _tool_context(session_id, args)
            if ctx:
                detail["context"] = ctx
        _report_and_audit(cfg, "pre_tool_call", findings, detail)
        # OSV auto-discovery runs off the blocking path so a network lookup
        # never delays or breaks the tool call.
        if cfg.discover and cfg.osv_lookup:
            _spawn_osv_discovery(cfg, rs, tool_name, args)
        if cfg.block_enabled:
            # Confirmed findings and custom rules block; community/heuristic ones
            # only alert. ``vulnerability`` kind never blocks (a legit-but-
            # vulnerable package must keep working) — only ``malware`` is stopped.
            blocking = [
                f for f in findings
                if (f.confirmed or f.source in ("custom", "secret"))
                and getattr(f, "kind", None) not in (constants.KIND_VULNERABILITY, "historical")
                # IOC findings alert but never auto-block in this rollout: network
                # and crypto-address blocklists are higher-churn/higher-FP than
                # pinned package versions, so validate them in audit mode first.
                and f.category != "ioc"
                and cfg.meets_block_threshold(f.severity)
            ]
            if blocking:
                return {"action": "block", "message": blackbox_block_message(blocking)}
        return None
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: pre_tool_call failed: %s", exc)
        return None


def _record_activity(tool_name: str, args: Any) -> None:
    """Log what the agent touched to the visibility trail (fail-open).

    Covers both the dedicated file tools and the shell channel (parsing reads,
    downloads, and dependency installs out of commands). Visibility, not
    detection: everything is logged regardless of whether it flags.
    """
    try:
        access = quads.file_access_arg(tool_name, args)
        if access:
            audit.record_file_access(access["tool"], access["path"], access["mode"])
            return
        if (tool_name or "").strip().lower() not in quads._SHELL_TOOLS:
            return
        command = quads._command_from_args(tool_name, args)
        if not command:
            return
        for path in quads.parse_shell_reads(command):
            audit.record_file_access("shell", path, "read")
        for url in quads.parse_downloads(command):
            audit.record_file_access("shell", url, "download")
        for dep in quads.parse_dependency_installs(command):
            audit.record_dependency(dep["ecosystem"], dep["name"], dep.get("version", ""), "shell")
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: activity visibility log failed: %s", exc)


def _spawn_osv_discovery(cfg: BlackboxConfig, rs: Any, tool_name: str, args: Any) -> None:
    """Run OSV dependency auto-discovery on a daemon thread (never blocks)."""
    import threading

    from . import osv

    def _run() -> None:
        try:
            findings = _flag_worthy(
                cfg, detection.discover_dependency_candidates(tool_name, args, rs, osv.lookup)
            )
            if findings:
                _report_and_audit(cfg, "osv_discovery", findings, {"tool_name": tool_name})
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("blackbox: OSV discovery failed: %s", exc)

    try:
        threading.Thread(target=_run, name="blackbox-osv", daemon=True).start()
    except Exception:  # pragma: no cover - fail open
        pass


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
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: post_tool_call failed: %s", exc)


def _untrusted_request_text(user_message: Any, request_messages: Any) -> str:
    """Return only the current turn's untrusted text for injection scanning.

    The API request also contains Hermes' system/developer instructions and
    earlier assistant turns. Those are trusted runtime context, not attacker
    input; scanning them caused harmless prompts to inherit matches from the
    system prompt. Scan the current user turn plus tool results produced during
    that turn, while keeping the full conversation separately for local audit
    context.
    """
    current = str(user_message or "").strip()
    messages = request_messages if isinstance(request_messages, list) else []

    # Limit the scan to the most recent user turn and anything returned by tools
    # after it. This also prevents an old injection from firing again on every
    # later request in the same conversation.
    start = 0
    for idx in range(len(messages) - 1, -1, -1):
        msg = messages[idx]
        if isinstance(msg, dict) and str(msg.get("role") or "").lower() == "user":
            start = idx
            break

    parts: List[str] = []
    seen: set[str] = set()

    def add(text: str) -> None:
        value = text.strip()
        if value and value not in seen:
            seen.add(value)
            parts.append(value)

    add(current)
    for msg in messages[start:]:
        if not isinstance(msg, dict):
            continue
        role = str(msg.get("role") or "").lower()
        # User content and tool output are the untrusted boundaries. System,
        # developer, and assistant content must never create a user finding.
        if role not in ("user", "tool"):
            continue
        add(_message_text(msg.get("content")))
    return "\n".join(parts)


def on_pre_api_request(**kwargs: Any) -> None:
    """Scan current user/tool input for prompt-injection patterns.

    Observer-only: blocking happens at the tool call, not here.
    """
    try:
        cfg = _config()
        rs = ruleset.get(cfg)
        text = _untrusted_request_text(
            kwargs.get("user_message"), kwargs.get("request_messages")
        )
        findings = detection.detect_injection(text, rs)
        if cfg.discover:
            findings = findings + detection.discover_injection(text, rs)
        findings = _flag_worthy(cfg, findings)
        detail = {
            "session_id": kwargs.get("session_id"),
            "task_id": kwargs.get("task_id"),
            "turn_id": kwargs.get("turn_id"),
            "model": kwargs.get("model"),
            "provider": kwargs.get("provider"),
        }
        # Always warm the per-session store (so later tool-call findings can show
        # the turn); attach as context only when this request produced a finding.
        turns = _conversation_turns(kwargs.get("user_message"), kwargs.get("request_messages"))
        _remember_convo(str(kwargs.get("session_id") or ""), turns)
        findings = _dedupe_api_findings(findings, detail)
        if findings and turns:
            detail["context"] = {"turns": turns}
        _report_and_audit(cfg, "pre_api_request", findings, detail)
        # Optional LLM second opinion, off-thread so it never delays the request.
        if cfg.llm_ready:
            _spawn_llm_review(cfg, text, detail)
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: pre_api_request failed: %s", exc)


def _spawn_llm_review(cfg: BlackboxConfig, text: str, detail: Dict[str, Any]) -> None:
    """Ask the configured LLM for an injection second opinion on a daemon thread.

    A positive verdict becomes a local ``source="llm"`` finding: audited and
    shown, never blocks, never shared to the graph.
    """
    import threading

    from . import llm

    def _run() -> None:
        try:
            verdict = llm.review_injection(text, cfg)
            if not verdict:
                return
            reason = verdict.get("reason") or "LLM flagged prompt injection"
            finding = detection.Finding(
                identifier=f"injection:llm:{quads.stable_hash(reason, 12)}",
                category="injection",
                severity=verdict.get("severity", "high"),
                title="Prompt injection (LLM review)",
                evidence=reason,
                matched=reason,
                confirmed=False,
                source="llm",
            )
            worthy = _flag_worthy(cfg, [finding])
            if worthy:
                review_detail = {**detail, "llm": True}
                # Give the LLM finding the same context; when the pattern scan
                # flagged nothing, pull the turn from the per-session store.
                if "context" not in review_detail:
                    turns = _recent_convo(str(detail.get("session_id") or ""))
                    if turns:
                        review_detail["context"] = {"turns": turns}
                _report_and_audit(cfg, "pre_api_request", worthy, review_detail)
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("blackbox: LLM review failed: %s", exc)

    try:
        threading.Thread(target=_run, name="blackbox-llm", daemon=True).start()
    except Exception:  # pragma: no cover - fail open
        pass


_AUTO_ATTACH_INTERVAL_SECS = 24 * 60 * 60


def _auto_attach_due() -> bool:
    """True once per interval, or immediately when a new agent target appears.

    Stamps the timestamp *before* the sweep so concurrent session starts don't
    each fan out their own attach thread.  Including the discovered target set
    prevents the 24-hour throttle from delaying protection for a Hermes profile
    or OpenClaw workspace installed after the last sweep.
    """
    import json
    import time

    try:
        path = constants.blackbox_home() / "auto_attach.json"
        now = time.time()
        try:
            from . import attach

            targets = sorted(
                [f"hermes:{item}" for item in attach.discover_hermes_homes()]
                + [f"openclaw:{item}" for item in attach.discover_openclaw_workspaces()]
            )
        except Exception:
            targets = []
        try:
            state = json.loads(path.read_text(encoding="utf-8"))
            last = float(state.get("last_run", 0.0))
            previous_targets = sorted(str(item) for item in (state.get("targets") or []))
        except Exception:
            last = 0.0
            previous_targets = []
        if now - last < _AUTO_ATTACH_INTERVAL_SECS and targets == previous_targets:
            return False
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps({"last_run": now, "targets": targets}), encoding="utf-8")
        return True
    except Exception as exc:
        logger.debug("blackbox: auto-attach throttle failed: %s", exc)
        return False


def _spawn_auto_attach(cfg: BlackboxConfig) -> None:
    """Re-run the attach sweep on a daemon thread (throttled, fail-open).

    Keeps protection current: a Hermes home or OpenClaw workspace created after
    install gets attached the next time any protected agent starts a session.
    """
    import threading

    if not cfg.auto_attach or not _auto_attach_due():
        return

    def _run() -> None:
        try:
            from . import attach

            report = attach.attach_all()
            changed = [
                row.get("target")
                for group in ("hermes", "openclaw")
                for row in report.get(group, [])
                if row.get("changed")
            ]
            if changed:
                audit.record(event="auto_attach", detail={"targets": changed})
        except Exception as exc:  # pragma: no cover - fail open
            logger.debug("blackbox: auto-attach failed: %s", exc)

    try:
        threading.Thread(target=_run, name="blackbox-auto-attach", daemon=True).start()
    except Exception:  # pragma: no cover - fail open
        pass


def on_session_start(session_id: str = "", **kwargs: Any) -> None:
    try:
        audit.record(event="session_start", detail={"session_id": session_id})
        _spawn_auto_attach(_config())
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: on_session_start failed: %s", exc)


def on_session_end(session_id: str = "", completed: bool = True, interrupted: bool = False, **kwargs: Any) -> None:
    try:
        _forget_convo(session_id)
        audit.record(
            event="session_end",
            detail={"session_id": session_id, "completed": completed, "interrupted": interrupted},
        )
    except Exception as exc:  # pragma: no cover - fail open
        logger.debug("blackbox: on_session_end failed: %s", exc)
