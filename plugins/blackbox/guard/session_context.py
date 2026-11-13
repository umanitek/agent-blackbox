"""Bounded per-session conversation memory used as finding context.

Keeps the last few turns per session (capped turns, chars and sessions, one
lock) so a finding can be recorded with the surrounding conversation — the
local evidence an operator needs to judge it. Nothing here is ever shared.
"""

from __future__ import annotations

import threading
from typing import Any, Optional
from .. import audit, detection

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
_last_convo: dict[str, list[dict[str, str]]] = {}
_convo_lock = threading.Lock()


def _message_role(msg: dict[str, Any]) -> str:
    role = str(msg.get("role") or "").lower()
    return role if role in ("user", "assistant", "system", "tool") else "user"


def _message_text(content: Any) -> str:
    """Flatten a message's ``content`` (str, or a list of text parts) to text."""
    if isinstance(content, str):
        return content
    parts: list[str] = []
    if isinstance(content, list):
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
    return "\n".join(p for p in parts if p)


def _conversation_turns(user_message: Any, request_messages: Any) -> list[dict[str, str]]:
    """Build a capped, redacted ``[{role, text}]`` from the request messages.

    Falls back to ``user_message`` when the messages list is unavailable.
    """
    turns: list[dict[str, str]] = []
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


def _remember_convo(session_id: str, turns: list[dict[str, str]]) -> None:
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


def _recent_convo(session_id: str) -> list[dict[str, str]]:
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


def _tool_context(session_id: str, args: Any) -> Optional[dict[str, Any]]:
    """Context for a tool-call finding: the scanned tool input + recent turns."""
    ctx: dict[str, Any] = {}
    turns = _recent_convo(session_id)
    if turns:
        ctx["turns"] = turns
    try:
        scanned = detection.injection_scan_text(args)
    except Exception:  # pragma: no cover - fail open
        scanned = ""
    if scanned.strip():
        ctx["input"] = audit.sanitize_text(scanned, _CONTEXT_INPUT_CHARS)
    return ctx or None
