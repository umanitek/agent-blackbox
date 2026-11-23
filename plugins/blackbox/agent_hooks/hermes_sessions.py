"""The Hermes agent — Blackbox's own host — in the instance tree, beside the coding agents.

Hermes sessions are already guarded by the plugin's own hooks (``guard``: ``on_session_start``,
``pre_tool_call``, ``post_tool_call``, ``on_session_end``), which write each event to Blackbox's
audit log (``$BLACKBOX_HOME/audit.jsonl``: the session id, the tool and its redacted arguments,
the decision, the Hermes home as ``workspace``). This module reads that log as it grows and records
each event in the SAME instance model the coding agents' hooks feed (``instances.record``): product
"Hermes agent", its profile = the Hermes home, its sessions, their tool calls and refusals — no
Hermes-owned file is touched, no new hook is added, and ``guard`` gains no dependency on
``agent_hooks`` (it would be a cycle).

What each row gives (KI-572, the real trail of the Hermes agent on the test VM, 2026-11-22):
``session_start`` names the project folder, the process, how it was started and the model
(``guard.host_process``: ``cwd``, ``pid``, ``launch``, ``model``); ``pre_api_request`` — one per
model call — names the model and the ``turn_id``: the first call of each turn is that session's
PROMPT (counted once per turn, never its text). The Hermes home is the PROFILE, never the project.

Sub-agents: Hermes runs a delegated task (``delegate_task``) as child agents with sessions of
their own, in the delegating session's process. Every session that first appears in the same
Hermes home within :data:`DELEGATE_SECONDS` of a ``delegate_task`` call — and that is in the same
process, or names none (a child's first event may be a tool call) — is that call's sub-agent:
one call may start several (H3: the second child was shown as a session of its own). A session
started in ANOTHER process is never a child.

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
from .protect import sandbox_errors
from .protect.events import reason_of, session_key

logger = logging.getLogger(__name__)

#: The audit trail's Hermes events → the instance model's events.
EVENTS = {"session_start": "session_start", "pre_tool_call": "pre_tool", "post_tool_call": "post_tool", "session_end": "stop",
          "pre_api_request": "prompt"}
#: Hermes' tool that runs a task as a child agent.
DELEGATE_TOOL = "delegate_task"
#: Hermes' code tool: its Python runs inside the sandbox when the session's code is sandboxed.
CODE_TOOL = "execute_code"
#: How soon after a ``delegate_task`` call a new session in the same Hermes home is its child.
DELEGATE_SECONDS = 120.0
MAX_READ_BYTES = 1024 * 1024
MAX_CHILDREN = 1024
MAX_PENDING = 32
MAX_SESSIONS = 1024

_lock = threading.Lock()
_children: OrderedDict[str, str] = OrderedDict()            # child session id → parent session id
_pending: dict[str, deque[tuple[str, float]]] = {}           # Hermes home → (delegating session id, when)
_facts: OrderedDict[str, dict[str, Any]] = OrderedDict()     # session id → {cwd, pid, launch, model}
_turns: OrderedDict[str, str] = OrderedDict()                # session id → the turn already counted as a prompt


def log_path() -> Path:
    return constants.blackbox_home() / "audit.jsonl"


def _cursor_path() -> Path:
    return constants.blackbox_home() / "agent-hooks" / "hermes-cursor.json"


#: Set once a look found no log yet: when it appears it is read from its start, even where no cursor
#: file could be written (Blackbox's home did not exist then).
_seen_empty = threading.Event()


def reset() -> None:
    """Tests: forget the children and pending delegations (the cursor file stays where it is)."""
    with _lock:
        _children.clear()
        _pending.clear()
        _facts.clear()
        _turns.clear()


def _bounded_put(table: OrderedDict, key: str, value: Any) -> None:
    table.pop(key, None)
    table[key] = value
    while len(table) > MAX_SESSIONS:
        table.popitem(last=False)


def _parent_of(raw: str, home: str, now: float, known: bool) -> str:
    """The delegating session *raw* belongs to ("" for a session of its own): the newest
    ``delegate_task`` in its Hermes home within :data:`DELEGATE_SECONDS`, from the same process
    (or *raw* names no process yet). The delegation is NOT used up: one call starts many children."""
    if raw in _children:
        return _children[raw]
    queue = _pending.get(home)
    if known or not queue:
        return ""
    while queue and now - queue[0][1] > DELEGATE_SECONDS:
        queue.popleft()
    mine = _facts.get(raw, {}).get("pid")
    for parent, _at in reversed(queue):
        theirs = _facts.get(parent, {}).get("pid")
        if parent != raw and (not mine or not theirs or mine == theirs):
            _bounded_put(_children, raw, parent)
            return parent
    return ""


def _session_facts(raw: str, kind: str, detail: Mapping[str, Any]) -> dict[str, Any]:
    """What this row adds to the session's facts (remembered for its later rows)."""
    known = dict(_facts.get(raw, {}))
    if kind == "session_start":
        pid = detail.get("pid")
        known.update(cwd=str(detail.get("cwd") or "")[:500], launch=str(detail.get("launch") or ""),
                     pid=pid if isinstance(pid, int) and not isinstance(pid, bool) and pid > 1 else 0,
                     shells_sandboxed=detail.get("shells_sandboxed") is True,
                     code_sandboxed=detail.get("code_sandboxed") is True,
                     # Shells AND execute_code inside: the whole agent's code runs kernel-enforced.
                     sandboxed=detail.get("shells_sandboxed") is True and detail.get("code_sandboxed") is True)
    if detail.get("model"):
        known["model"] = str(detail["model"])[:80]
    _bounded_put(_facts, raw, known)
    return known


def _new_turn(raw: str, detail: Mapping[str, Any]) -> bool:
    """True for the first model call of a turn this session has not counted yet."""
    turn = str(detail.get("turn_id") or detail.get("task_id") or "")
    if not turn or _turns.get(raw) == turn:
        return False
    _bounded_put(_turns, raw, turn)
    return True


def apply(row: Mapping[str, Any]) -> bool:
    """Record one audit row of the Hermes agent; False when it is not one (another agent's,
    an event the instance model does not follow, no session, a model call of a turn already counted)."""
    kind = EVENTS.get(str(row.get("event") or ""))
    detail = row.get("detail") if isinstance(row.get("detail"), dict) else {}
    raw = str(detail.get("session_id") or "")[:200]
    if kind is None or not raw or row.get("framework"):
        return False
    home = str(row.get("workspace") or "")[:500]
    tool = str(detail.get("tool_name") or "")[:120]
    now = float(row.get("ts") or time.time())
    with _lock:
        facts = _session_facts(raw, str(row.get("event")), detail)
        if kind == "prompt" and not _new_turn(raw, detail):
            return False
        if kind == "pre_tool" and tool == DELEGATE_TOOL:
            queue = _pending.setdefault(home, deque(maxlen=MAX_PENDING))
            queue.append((raw, now))
        parent = _parent_of(raw, home, now, store.get(session_key(HERMES_ID, raw, "")) is not None)
    fields: dict[str, Any] = {"agent": HERMES_ID, "event": kind, "session": raw, "cwd": facts.get("cwd", ""), "profile": home,
                              "tool_name": tool, "args": detail.get("args"), "tool_call_id": str(detail.get("tool_call_id") or "")[:200],
                              "model": facts.get("model", ""), "launch": facts.get("launch", ""), "agent_pid": facts.get("pid") or None,
                              "shells_sandboxed": facts.get("shells_sandboxed") is True, "sandboxed": facts.get("sandboxed") is True}
    key = session_key(HERMES_ID, raw, "")
    if parent:
        fields.update(sub=raw, sub_type="delegated task", event={"session_start": "subagent_start", "stop": "subagent_stop"}.get(kind, kind))
        key = session_key(HERMES_ID, parent, "")
    decision = str(detail.get("decision") or "")
    findings = [finding for finding in row.get("findings") or [] if isinstance(finding, dict)]
    # The row's reason: the titles of what refused or flagged it, as for every coding agent (KI-580).
    reason = reason_of({}, findings) if findings else ""
    # KI-600 (execute_code half): the kernel logged NO deny line for execute_code's refused read
    # (round 5, s5-hmx1), so the helper's deny-log watch had nothing to count; the refusal the
    # code tool's own output names (PermissionError: [Errno 1] … '<path>') is counted here instead.
    code_call = kind == "post_tool" and tool == CODE_TOOL and facts.get("code_sandboxed") is True
    refused = sandbox_errors.refusals(str(detail.get("result") or "")) if kind == "post_tool" and (fields["shells_sandboxed"] or code_call) else []
    if sandbox_errors.counted(refused) or (code_call and sandbox_errors.files(refused)):   # KI-590 / KI-600
        decision, reason = "block", sandbox_errors.note(refused)
    if refused:
        sandbox_errors.emit(refused, HERMES_ID, key, str(detail.get("cwd") or ""))
    record(fields, key, decision=decision if decision == "block" else "", findings=int(row.get("findingCount") or 0), reason=reason)
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
    """Record the Hermes events written to the audit trail since the last look; how many. With no
    log and no Blackbox home it writes nothing (KI-611: a process still looking during an uninstall
    re-created ``agent-hooks/hermes-cursor.json`` after Blackbox's home was deleted)."""
    path = log_path()
    try:
        stat = path.stat()
    except OSError:   # no Hermes event yet: when the log appears, it is read from its start
        _seen_empty.set()
        if constants.blackbox_home().is_dir() and not _cursor_path().exists():
            write_json_object(_cursor_path(), {"inode": 0, "offset": 0}, what="the Hermes sessions cursor")
        return 0
    with _lock:
        cursor = read_json_object(_cursor_path()) or ({"inode": 0, "offset": 0} if _seen_empty.is_set() else {})
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
