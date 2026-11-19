"""What the model-request hook reads: the turn's untrusted text, and the per-turn dedupe.

The API request Hermes hands ``on_pre_api_request`` also contains its own
system/developer instructions and earlier assistant turns — trusted runtime
context, not attacker input. :func:`_untrusted_request_sources` keeps only the
current user turn and the tool results produced during it, each tagged with the
closed context an injection report carries (``constants.INJECTION_CONTEXTS``);
:func:`_injection_by_source` scans each source so a finding names where it was;
:func:`_dedupe_api_findings` drops the repeats that several model calls in one
turn would otherwise raise. Split out of ``hooks.py`` on 2026-10-22 (it stood at
398 lines); the hooks call these by module.
"""

from __future__ import annotations

import re
import time
from typing import Any, Optional

from .. import detection
from . import session_context

_seen_api_findings: dict[tuple, float] = {}
_API_FINDING_DEDUPE_TTL_SECS = 10 * 60


def _dedupe_api_findings(findings: list[detection.Finding], detail: dict[str, Any]) -> list[detection.Finding]:
    """Drop repeated pre-api findings from additional model calls in one turn."""
    turn_key = str(detail.get("turn_id") or detail.get("task_id") or detail.get("session_id") or "")
    if not turn_key:
        return findings
    now = time.time()
    for key, seen_at in list(_seen_api_findings.items()):
        if now - seen_at > _API_FINDING_DEDUPE_TTL_SECS:
            _seen_api_findings.pop(key, None)
    out: list[detection.Finding] = []
    for finding in findings:
        key = (turn_key, finding.identifier, finding.evidence or finding.matched or finding.title)
        if key in _seen_api_findings:
            continue
        _seen_api_findings[key] = now
        out.append(finding)
    return out


#: Blackbox's OWN records read back over its local dashboard — the findings and the activity log.
#: Read back (the assistant answering "what was flagged?") an old finding's text is a record, not a
#: new attack, yet scanning it re-flagged that finding on every such question (2026-11-19). The
#: output is still scanned in full; drop_record_echoes() removes only exact echoes. Only these two
#: endpoints count: other dashboard data can carry text outsiders wrote (community threat names).
_OWN_RECORDS = re.compile(r"^https?://(?:127\.0\.0\.1|localhost):(\d+)/api/(?:findings|audit)(?:[?#]\S*)?$")
_ADDRESS = re.compile(r"https?://[^\s'\"\\)>]+")


def _own_record_reads(messages: list[Any], dashboard_port: int) -> set[str]:
    """Call ids of the tool calls whose every web address is Blackbox's own findings or activity
    on this machine's dashboard port. A call that names any other address — or no address — is
    not one: its output is scanned as before."""
    own: set[str] = set()
    if not dashboard_port:
        return own
    for call_id, arguments in _call_arguments(messages):
        addresses = _ADDRESS.findall(arguments)
        matches = [_OWN_RECORDS.match(address) for address in addresses]
        if addresses and all(m and int(m.group(1)) == dashboard_port for m in matches):
            own.add(call_id)
    return own


def own_record_texts(request_messages: Any, dashboard_port: int) -> list[str]:
    """The text of this turn's tool results that read Blackbox's own records (see _own_record_reads)."""
    messages = request_messages if isinstance(request_messages, list) else []
    own = _own_record_reads(messages, dashboard_port)
    texts = []
    for msg in messages:
        result = _tool_result(msg)
        if result is not None and result[0] in own:
            text = session_context._message_text(result[1]).strip()
            if text:
                texts.append(text)
    return texts


def drop_record_echoes(findings: list[Any], sources: list[tuple[str, str]], own_texts: list[str],
                       recorded: set[tuple[str, str]]) -> list[Any]:
    """*findings* without the echoes of old ones. A finding is an echo only when ALL hold: its
    evidence appears in Blackbox's own records read back (*own_texts*), nowhere else in this
    request, and the same rule already recorded that same text (*recorded*: identifier, evidence).
    Anything new in the same output — another rule, other text — is kept."""
    # The user's own words always count as "elsewhere" — even when they repeat the record word for
    # word (the sources hold each text once, so that text would otherwise look like the record).
    others = [text for context, text in sources if context == "in-user-prompt" or text not in own_texts]
    kept = []
    for finding in findings:
        evidence = str(getattr(finding, "evidence", "") or "")
        echo = (bool(evidence) and (str(getattr(finding, "identifier", "")), evidence) in recorded
                and any(evidence in text for text in own_texts) and not any(evidence in text for text in others))
        if not echo:
            kept.append(finding)
    return kept


def _call_arguments(messages: list[Any]) -> list[tuple[str, str]]:
    """``(call id, arguments text)`` for every tool call, in both wire shapes (see _tool_result)."""
    out: list[tuple[str, str]] = []
    for msg in messages:
        if isinstance(msg, dict) and msg.get("type") == "function_call" and msg.get("call_id"):
            out.append((str(msg["call_id"]), str(msg.get("arguments") or "")))
        calls = msg.get("tool_calls") if isinstance(msg, dict) else None
        for call in calls if isinstance(calls, list) else []:
            function = call.get("function") if isinstance(call, dict) else None
            if isinstance(function, dict) and call.get("id"):
                out.append((str(call["id"]), str(function.get("arguments") or "")))
    return out


def _untrusted_request_sources(user_message: Any, request_messages: Any) -> list[tuple[str, str]]:
    """Return the current turn's untrusted text as ``(context, text)`` pairs.

    The API request also contains Hermes' system/developer instructions and
    earlier assistant turns. Those are trusted runtime context, not attacker
    input; scanning them caused harmless prompts to inherit matches from the
    system prompt. Only the current user turn and the tool results produced
    during that turn are scanned. Each part is tagged with where it came from
    (``constants.INJECTION_CONTEXTS``) — the closed context an injection report
    carries (Refine R1, decision 24); never the source's address.
    """
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
    tool_names = _tool_names_by_call_id(messages)
    sources: list[tuple[str, str]] = []
    seen: set[str] = set()

    def add(context: str, text: str) -> None:
        value = text.strip()
        if value and value not in seen:
            seen.add(value)
            sources.append((context, value))

    add("in-user-prompt", str(user_message or ""))
    for msg in messages[start:]:
        role = str(msg.get("role") or "").lower() if isinstance(msg, dict) else ""
        # User content and tool output are the untrusted boundaries. System,
        # developer, and assistant content must never create a user finding.
        if role == "user":
            add("in-user-prompt", session_context._message_text(msg.get("content")))
            continue
        result = _tool_result(msg)
        if result is not None:
            call_id, content, name = result
            name = str(name or tool_names.get(call_id, "")).lower()
            context = "in-fetched-page" if name.startswith(detection.FETCH_TOOL_PREFIXES) else "in-tool-output"
            add(context, session_context._message_text(content))
    return sources


def _tool_result(msg: Any) -> Optional[tuple[str, Any, str]]:
    """``(call id, content, tool name or "")`` when *msg* is a tool's result, else None.

    Two wire shapes reach ``pre_api_request``: Chat Completions sends
    ``{"role": "tool", "tool_call_id", "content"}``; the Responses API (OpenAI direct,
    Codex — Hermes passes ``api_kwargs["input"]``) sends
    ``{"type": "function_call_output", "call_id", "output"}``. Reading only the first
    left every Responses-API agent's tool output unscanned for injection (KI-365)."""
    if not isinstance(msg, dict):
        return None
    if str(msg.get("role") or "").lower() == "tool":
        return str(msg.get("tool_call_id") or ""), msg.get("content"), str(msg.get("name") or "")
    if msg.get("type") == "function_call_output":
        return str(msg.get("call_id") or ""), msg.get("output"), ""
    return None


def _tool_names_by_call_id(messages: list[Any]) -> dict[str, str]:
    """``tool_call_id`` -> tool name, from the assistant turns' ``tool_calls`` (Chat
    Completions) and from ``function_call`` items (Responses API)."""
    names: dict[str, str] = {}
    for msg in messages:
        if isinstance(msg, dict) and msg.get("type") == "function_call" and msg.get("call_id"):
            names[str(msg["call_id"])] = str(msg.get("name") or "")
        calls = msg.get("tool_calls") if isinstance(msg, dict) else None
        for call in calls if isinstance(calls, list) else []:
            function = call.get("function") if isinstance(call, dict) else None
            if isinstance(function, dict) and call.get("id"):
                names[str(call["id"])] = str(function.get("name") or "")
    return names


def _injection_by_source(sources: list[tuple[str, str]], rs: Any, discover: bool) -> list[Any]:
    """Injection findings (graph matches, plus heuristic candidates when
    *discover*) scanned per source so each carries its context; a pattern seen
    in several sources is reported once, with the first source's context."""
    found: dict[str, Any] = {}
    for context, text in sources:
        findings = detection.detect_injection(text, rs, context)
        if discover:
            findings += detection.discover_injection(text, rs, context)
        for finding in findings:
            found.setdefault(finding.identifier, finding)
    return list(found.values())
