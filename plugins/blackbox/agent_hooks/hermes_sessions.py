"""The Hermes agent — Blackbox's own host — in the instance tree, beside the coding agents.

Hermes sessions are already guarded by the plugin's own hooks (``guard``: ``on_session_start``,
``pre_tool_call``, ``post_tool_call``, ``on_session_end``), which write each event to Blackbox's
audit log (``$BLACKBOX_HOME/audit.jsonl``: the session id, the tool and its redacted arguments,
the decision, the Hermes home as ``workspace``). This module reads that log as it grows and records
each event in the SAME instance model the coding agents' hooks feed (``instances.record``): product
"Hermes agent", its profile = the Hermes home, its sessions, their tool calls and refusals — no
Hermes-owned file is touched, no new hook is added, and ``guard`` gains no dependency on
``agent_hooks`` (it would be a cycle).

Sub-agents: Hermes runs a delegated task (``delegate_task``) as a child agent with a session of
its own. A session that first appears in the same Hermes home within :data:`DELEGATE_SECONDS` of
a ``delegate_task`` call is that call's sub-agent: its tool calls and its end are recorded under
the delegating session.

Read incrementally (:func:`catch_up`, from the observer's look every few seconds and from the live
view): a byte cursor kept in ``agent-hooks/hermes-cursor.json`` survives restarts, so no event is
recorded twice; the first run starts at the end of the log (earlier sessions stay in the audit
trail). Bounded: at most :data:`MAX_READ_BYTES` a look.

Pattern: **Adapter** (the audit trail's rows → the instance model's events).

Usage::

    from . import hermes_sessions
    hermes_sessions.catch_up()      # how many events were recorded
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections import OrderedDict, deque
from pathlib import Path
from typing import Any, Mapping

from ..kernel import constants
from ..kernel.agent_hosts import HERMES_ID
from ..kernel.bounded_files import read_json_object, write_json_object
from .instances import record, store
from .protect.events import session_key

logger = logging.getLogger(__name__)

#: The audit trail's Hermes events → the instance model's events.
EVENTS = {"session_start": "session_start", "pre_tool_call": "pre_tool", "post_tool_call": "post_tool", "session_end": "stop"}
#: Hermes' tool that runs a task as a child agent.
DELEGATE_TOOL = "delegate_task"
#: How soon after a ``delegate_task`` call a new session in the same Hermes home is its child.
DELEGATE_SECONDS = 120.0
MAX_READ_BYTES = 1024 * 1024
MAX_CHILDREN = 1024
MAX_PENDING = 32

_lock = threading.Lock()
_children: OrderedDict[str, str] = OrderedDict()            # child session id → parent session id
_pending: dict[str, deque[tuple[str, float]]] = {}           # Hermes home → (delegating session id, when)


def log_path() -> Path:
    return constants.blackbox_home() / "audit.jsonl"


def _cursor_path() -> Path:
    return constants.blackbox_home() / "agent-hooks" / "hermes-cursor.json"


def reset() -> None:
    """Tests: forget the children and pending delegations (the cursor file stays where it is)."""
    with _lock:
        _children.clear()
        _pending.clear()


def _parent_of(raw: str, home: str, kind: str, now: float, known: bool) -> str:
    """The delegating session *raw* belongs to ("" for a session of its own)."""
    if raw in _children:
        return _children[raw]
    queue = _pending.get(home)
    if known or not queue:
        return ""
    while queue and now - queue[0][1] > DELEGATE_SECONDS:
        queue.popleft()
    if not queue or queue[0][0] == raw:
        return ""
    parent, _at = queue.popleft()
    _children[raw] = parent
    while len(_children) > MAX_CHILDREN:
        _children.popitem(last=False)
    return parent


def apply(row: Mapping[str, Any]) -> bool:
    """Record one audit row of the Hermes agent; False when it is not one (another agent's,
    an event the instance model does not follow, no session)."""
    kind = EVENTS.get(str(row.get("event") or ""))
    detail = row.get("detail") if isinstance(row.get("detail"), dict) else {}
    raw = str(detail.get("session_id") or "")[:200]
    if kind is None or not raw or row.get("framework"):
        return False
    home = str(row.get("workspace") or "")[:500]
    tool = str(detail.get("tool_name") or "")[:120]
    now = float(row.get("ts") or time.time())
    with _lock:
        if kind == "pre_tool" and tool == DELEGATE_TOOL:
            queue = _pending.setdefault(home, deque(maxlen=MAX_PENDING))
            queue.append((raw, now))
        parent = _parent_of(raw, home, kind, now, store.get(session_key(HERMES_ID, raw, "")) is not None)
    fields: dict[str, Any] = {"agent": HERMES_ID, "event": kind, "session": raw, "cwd": home, "profile": home, "tool_name": tool,
                              "args": detail.get("args"), "tool_call_id": str(detail.get("tool_call_id") or "")[:200]}
    key = session_key(HERMES_ID, raw, "")
    if parent:
        fields.update(sub=raw, sub_type="delegated task", event={"session_start": "subagent_start", "stop": "subagent_stop"}.get(kind, kind))
        key = session_key(HERMES_ID, parent, "")
    decision = str(detail.get("decision") or "")
    record(fields, key, decision=decision if decision == "block" else "", findings=int(row.get("findingCount") or 0))
    return True


def _rows(text: str) -> list[dict[str, Any]]:
    rows = []
    for line in text.splitlines():
        try:
            row = json.loads(line)
        except ValueError:
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def catch_up() -> int:
    """Record the Hermes events written to the audit trail since the last look; how many."""
    path = log_path()
    try:
        stat = path.stat()
    except OSError:   # no Hermes event yet: when the log appears, it is read from its start
        if not _cursor_path().exists():
            write_json_object(_cursor_path(), {"inode": 0, "offset": 0}, what="the Hermes sessions cursor")
        return 0
    with _lock:
        cursor = read_json_object(_cursor_path()) or {}
        same_file = cursor.get("inode") == stat.st_ino and isinstance(cursor.get("offset"), int) and cursor["offset"] <= stat.st_size
        start = int(cursor["offset"]) if same_file else (stat.st_size if not cursor else 0)
        if start >= stat.st_size:
            if not same_file:
                write_json_object(_cursor_path(), {"inode": stat.st_ino, "offset": stat.st_size}, what="the Hermes sessions cursor")
            return 0
        with open(path, "rb") as handle:
            handle.seek(start)
            chunk = handle.read(MAX_READ_BYTES)
        complete = chunk[:chunk.rfind(b"\n") + 1]   # a line still being written waits for the next look
        write_json_object(_cursor_path(), {"inode": stat.st_ino, "offset": start + len(complete)}, what="the Hermes sessions cursor")
    applied = 0
    for row in _rows(complete.decode("utf-8", "replace")):
        try:
            applied += apply(row)
        except Exception:   # health: allow BLE001 -- one odd row costs only itself
            logger.debug("blackbox: a Hermes audit row could not be recorded", exc_info=True)
    return applied



__all__ = ["DELEGATE_SECONDS", "DELEGATE_TOOL", "EVENTS", "apply", "catch_up", "log_path", "reset"]
