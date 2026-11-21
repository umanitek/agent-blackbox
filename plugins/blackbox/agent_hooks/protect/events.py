"""One hook event from a coding agent: recorded, and — before a tool runs — judged.

:func:`record_event` is what ``POST /api/agent-hooks/event`` calls with the runner's summary
(:func:`.runner.summary`). It

* judges a ``pre_tool`` call with the ONE guard (``guard.tool_call_verdict``, the same checks a
  Hermes agent's hook runs — threats AND self-protection) and answers ``{"decision": "block",
  "message"}`` or ``allow``; a Codex ``apply_patch`` is judged file by file;
* checks TEXT for prompt injection with the same guard (``guard.text_verdict``: only a verified
  pattern blocks, in Block mode): the prompt before it is sent, a tool's output before the model
  reads it, a file before a pre-read hook lets the agent read it. The text is checked in this
  process and never recorded — the records keep its length, and a finding only its matched phrase
  as local evidence (≤200 chars, redacted — as for a Hermes agent);
* writes the event to the agent's own audit log (``audit.record_for``) under the Hermes event names
  Agent activity already rebuilds sessions from — so each agent's sessions and tool calls show;
* keeps a small per-agent record (:data:`STATE_FILE`): last event, events seen, sessions (hashed
  ids only), errors — what tells HOOKED from CONNECTED.

A session id is never stored as given: it is ``<agent>:<sha256 prefix>``.

**Undo:** decides one call at a time with the guard; with protection off no hook calls it.
Session records stay in Blackbox's own data folder.
"""

from __future__ import annotations

import hashlib
import threading
import time
from typing import Any, Mapping

from ... import audit, guard
from ...kernel import constants
from ...kernel.bounded_files import read_json_object, write_json_object
from ..hosts import BY_ID, EVENTS
from .runner import patch_files

#: The most text one event carries for the injection check (the runner bounds it the same).
MAX_CHECK_TEXT = 256 * 1024
#: Tools whose output is a fetched web page (an injection there names its site).
_FETCH_TOOLS = ("webfetch", "web_fetch", "fetch", "web_extract", "browse", "read_url", "url")
_EMPTY = {"findings": [], "blocked": [], "decision": "", "message": ""}

#: Sessions kept per agent (the oldest go first).
MAX_SESSIONS = 40
MAX_TEXT = 500
#: The audit event each hook event is written as (Agent activity's own vocabulary).
AUDIT_EVENT = {"session_start": "session_start", "prompt": "user_prompt", "pre_tool": "pre_tool_call",
               "post_tool": "post_tool_call", "turn_end": "agent_turn_end", "stop": "session_end"}

_lock = threading.Lock()


def state_path():
    return constants.blackbox_home() / "agent-hooks" / "state.json"


def read_state() -> dict[str, Any]:
    data = read_json_object(state_path()) or {}
    return data if isinstance(data.get("agents"), dict) else {"agents": {}}


def write_state(state: Mapping[str, Any]) -> None:
    write_json_object(state_path(), state, what="the agent hooks state")


def session_key(agent: str, raw: str, cwd: str) -> str:
    """``<agent>:<16 hex>`` for the agent's session id (or, when it sends none, its folder + day)."""
    seed = raw or f"{cwd}|{time.strftime('%Y-%m-%d')}"
    return f"{agent}:{hashlib.sha256(f'{agent}|{seed}'.encode()).hexdigest()[:16]}"


def _text(value: Any, limit: int = MAX_TEXT) -> str:
    return value[:limit] if isinstance(value, str) else ""


def validate(body: Any) -> dict[str, Any]:
    """The event as checked fields; raises ValueError (a 400) for anything else."""
    if not isinstance(body, dict):
        raise ValueError("the event must be a JSON object")
    agent, event = body.get("agent"), body.get("event")
    if agent not in BY_ID:
        raise ValueError("unknown agent")
    if event not in EVENTS:
        raise ValueError("unknown event")
    tool_name = body.get("tool_name", "")
    if not isinstance(tool_name, str) or len(tool_name) > 120:
        raise ValueError("tool_name must be a short string")
    chars = body.get("prompt_chars", 0)
    text = body.get("text", "")
    if not isinstance(text, str):
        raise ValueError("text must be a string")
    return {"agent": agent, "event": event, "session": _text(body.get("session"), 200), "cwd": _text(body.get("cwd")),
            "tool_name": tool_name, "args": body.get("args"), "tool_call_id": _text(body.get("tool_call_id"), 200),
            "prompt_chars": chars if isinstance(chars, int) and chars >= 0 else 0, "text": text[:MAX_CHECK_TEXT]}


def _merge(verdicts: list[Mapping[str, Any]]) -> dict[str, Any]:
    """One answer from several verdicts: blocked when any blocks, flagged when any flags."""
    findings = [finding for verdict in verdicts for finding in verdict.get("findings") or []]
    blocked = [identifier for verdict in verdicts for identifier in verdict.get("blocked") or []]
    decisions = [str(verdict.get("decision") or "") for verdict in verdicts]
    decision = "block" if "block" in decisions else next((d for d in decisions if d), "")
    message = next((str(v.get("message")) for v in verdicts if v.get("decision") == "block" and v.get("message")), "")
    return {"findings": findings, "blocked": blocked, "decision": decision, "message": message}


def _tool_verdicts(tool_name: str, args: Any) -> list[Mapping[str, Any]]:
    """The tool call itself — and, for Codex's ``apply_patch``, each file it touches as a write
    (a deletion as a whole-file write, an update or addition with the patch as its edit)."""
    verdicts = [guard.tool_call_verdict(tool_name=tool_name, args=args)]
    if tool_name == "apply_patch" and isinstance(args, dict):
        patch = str(args.get("patch") or "")
        for path in patch_files(patch):
            deleted = f"*** Delete File: {path}" in patch
            verdicts.append(guard.tool_call_verdict(tool_name="write_file",
                                                    args={"path": path, "content": ""} if deleted else {"path": path, "patch": patch}))
    return verdicts


def _verdict(event: Mapping[str, Any]) -> dict[str, Any]:
    kind, text = event["event"], event["text"]
    if kind == "pre_tool" and event["tool_name"]:
        verdicts = _tool_verdicts(event["tool_name"], event["args"])
        if text:   # a file a pre-read hook is about to let the agent read
            verdicts.append(guard.text_verdict([("in-tool-output", text)]))
        return _merge(verdicts)
    if kind == "prompt" and text:
        return _merge([guard.text_verdict([("in-user-prompt", text)])])
    if kind == "post_tool" and text:
        fetched = event["tool_name"].lower().startswith(_FETCH_TOOLS)
        return _merge([guard.text_verdict([("in-fetched-page" if fetched else "in-tool-output", text)])])
    return dict(_EMPTY)


def _remember(event: Mapping[str, Any], session: str, verdict: Mapping[str, Any]) -> None:
    now = time.time()
    with _lock:
        state = read_state()
        agent = state["agents"].setdefault(event["agent"], {})
        agent["last_event"] = now
        agent["events"] = int(agent.get("events", 0)) + 1
        sessions = agent.setdefault("sessions", {})
        row = sessions.setdefault(session, {"first": now, "events": 0, "tools": 0, "blocked": 0, "folder": ""})
        row["last"] = now
        row["events"] += 1
        row["tools"] += event["event"] == "pre_tool"
        row["blocked"] += verdict.get("decision") == "block"
        row["folder"] = (event["cwd"].rstrip("/").rsplit("/", 1)[-1] or row["folder"])[:120]
        row["ended"] = event["event"] == "stop" or (row.get("ended", False) and event["event"] == "turn_end")
        for old in sorted(sessions, key=lambda key: sessions[key].get("last", 0))[:-MAX_SESSIONS]:
            sessions.pop(old)
        write_state(state)


def note_error(agent: str) -> None:
    """Counts a failed event for *agent* (shown as DEGRADED when errors outnumber good events lately)."""
    with _lock:
        state = read_state()
        row = state["agents"].setdefault(agent, {})
        row["errors"] = int(row.get("errors", 0)) + 1
        row["last_error"] = time.time()
        write_state(state)


def record_event(body: Any) -> dict[str, Any]:
    """Record one hook event and answer it. Raises ValueError for a malformed event."""
    event = validate(body)
    state = read_state()["agents"].get(event["agent"], {})
    if state.get("disabled"):
        return {"decision": "allow", "message": "", "recorded": False}   # a stale hook after "Stop protecting"
    session = session_key(event["agent"], event["session"], event["cwd"])
    verdict = _verdict(event)
    detail: dict[str, Any] = {"session_id": session}
    if event["event"] in ("pre_tool", "post_tool"):
        detail.update(tool_name=event["tool_name"], tool_call_id=event["tool_call_id"] or f"{session}:{time.time()}")
    if event["event"] == "pre_tool":
        detail.update(args=event["args"], decision=verdict.get("decision") or "allow")
    if event["event"] == "prompt":
        detail["prompt_chars"] = event["prompt_chars"]
    if event["text"]:
        detail["checked_chars"] = len(event["text"])   # the text itself is never recorded
    if verdict.get("decision") and event["event"] != "pre_tool":
        detail["decision"] = verdict["decision"]
    findings = [{**finding, "tool_name": event["tool_name"]} for finding in verdict.get("findings") or []]
    audit.record_for(event["agent"], event=AUDIT_EVENT[event["event"]], workspace=event["cwd"],
                     findings=findings or None, detail=detail)
    _remember(event, session, verdict)
    blocked = verdict.get("decision") == "block"
    return {"decision": "block" if blocked else "allow", "message": verdict.get("message", "") if blocked else "",
            "findings": len(findings), "recorded": True}
