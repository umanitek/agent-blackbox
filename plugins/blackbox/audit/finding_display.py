"""Which finding rows are ONE threat on screen, and which row stands for it.

Several detectors can record the same threat in the same agent turn (one record each); the
dashboard's findings list, its alerts and Desktop's Threats page show it once, choosing the
record with the strongest source, then the highest severity. That rule was written in
JavaScript twice (dashboard/static/index.html, desktop/plugin.js) and the copies drifted
(raw vs known category, case of the user role). It is defined here, served with every
findings row (``display_key`` / ``display_rank``), and both pages group on what they are
served; their own functions remain only for rows from an older running dashboard.

The key mirrors index.html's ``findingDisplayKey`` exactly — agent scope, occurrence
(turn / task id, else session + last user words + the second), category, matched text —
and test_blackbox_finding_display.py runs both on the same rows to keep them equal.

    row["display_key"], row["display_rank"] = display_key(row), display_rank(row)
"""

from __future__ import annotations

import math
from datetime import datetime
from typing import Any, Mapping

#: The page's categories (index.html CATS); anything else shows as "other".
_CATEGORIES = frozenset({"dependency", "injection", "escalation", "fileaccess", "skill", "secret", "ioc", "other"})
#: The page's severities (index.html SEV) and their rank (SEV_RANK).
_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
#: Which record stands for a threat: the strongest source first (index.html sourceRank).
_SOURCE_RANK = {"public": 6, "custom": 5, "community": 4, "secret": 3, "llm": 2, "heuristic": 1}
_AGENT_SEP, _PART_SEP = "\u001e", "\u001f"


def _normalized(value: Any) -> str:
    return " ".join(str(value or "").split()).lower()


def _last_user_text(row: Mapping[str, Any]) -> str:
    context = row.get("context")
    turns = context.get("turns") if isinstance(context, Mapping) else None
    for turn in reversed(turns if isinstance(turns, list) else []):
        if isinstance(turn, Mapping) and turn.get("role") == "user" and turn.get("text"):
            return str(turn["text"])
    return ""


def _time_ms(row: Mapping[str, Any]) -> float:
    """index.html findingTime: epoch seconds or milliseconds, or an ISO text; 0 when unreadable."""
    value = row.get("time") or row.get("ts") or row.get("timestamp")
    if isinstance(value, bool) or value is None:
        return 0.0
    if isinstance(value, (int, float)):
        return float(value) * (1000 if value < 1e12 else 1)
    try:
        return datetime.fromisoformat(str(value).strip()).timestamp() * 1000
    except ValueError:
        return 0.0


def _source(row: Mapping[str, Any]) -> str:
    source = str(row.get("source") or "").lower()
    if source in _SOURCE_RANK:
        return source
    confirmed = row.get("confirmed")
    return "public" if confirmed is True or confirmed == "true" else "heuristic"   # JS ===: 1 is not true


def display_key(row: Mapping[str, Any]) -> str:
    """The key two rows share exactly when the page shows them as one threat."""
    agent = _AGENT_SEP.join(str(row.get(name) or "") for name in ("framework", "workspace")) + _AGENT_SEP + str(
        row.get("agent_id") or row.get("agentId") or row.get("profile") or "")
    occurrence = str(row.get("turn_id") or row.get("turnId") or row.get("task_id") or row.get("taskId") or "")
    if not occurrence:
        occurrence = _AGENT_SEP.join([str(row.get("session_id") or row.get("sessionId") or ""),
                                      _normalized(_last_user_text(row)), str(math.floor(_time_ms(row) / 1000))])
    category = str(row.get("category") or row.get("type") or "other").lower()
    matched = row.get("evidence") or row.get("matched") or row.get("title") or row.get("identifier") or ""
    return _PART_SEP.join([agent, occurrence, category if category in _CATEGORIES else "other", _normalized(matched)])


def display_rank(row: Mapping[str, Any]) -> int:
    """Which of the rows sharing a key stands for the threat: the highest rank."""
    severity = str(row.get("severity") or "info").lower()
    return _SOURCE_RANK.get(_source(row), 0) * 10 + _SEVERITY_RANK.get(severity if severity in _SEVERITY_RANK else "info", 0)
