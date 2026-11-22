"""Every instance of every coding agent: live, and kept as history.

A hook event says which session it belongs to — and, inside a session, which sub-agent
(``agent_id`` for Claude Code, Codex and Copilot CLI; ``subagent_id`` for Cursor). :func:`record`
turns each event into the instance it belongs to (created on first sight, ended when the agent
says so), counts what Blackbox checked and refused, and adds the action to the instance's
timeline. :mod:`.views` answers what the dashboard and a companion app show.

Privacy: keys are hashed ids; an action keeps a tool's name and a short redacted summary (a
command's start, a file's path) — never a prompt, a tool's output or a file's text.

Usage::

    from .instances import record, views
    record(event, session_key, decision="block")      # from agent_hooks.record_event
    views.live()                                       # the tree, for GET /api/agents/live
"""

from __future__ import annotations

import hashlib
import time
from typing import Any, Mapping

from ...kernel.agent_hosts import BY_ID, DECISION_TOO_LATE
from ...kernel.redaction import redact_secret_values
from . import links, store
from .model import LAUNCHES, Action, Instance

__all__ = ["links", "record", "store", "sub_key"]

MAX_WHAT = 200
MAX_TASK = 200
_ENTRY_LAUNCH = {"cli": "interactive", "sdk-ts": "sdk", "sdk-py": "sdk", "sdk-cli": "headless", "claude-vscode": "ide",
                 "claude-desktop": "ide", "mcp": "sdk"}


def sub_key(session: str, raw: str) -> str:
    """A sub-agent's key under its session's (the agent's own id is hashed, never kept)."""
    return f"{session}/{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:12]}"


def _what(event: Mapping[str, Any]) -> str:
    args = event.get("args")
    text = ""
    if isinstance(args, dict):
        # A spawn tool (Task, task, spawn_agent) is shown by its task's title — never its prompt.
        text = str(args.get("command") or args.get("path") or args.get("file_path") or args.get("url")
                   or args.get("description") or "")
    return redact_secret_values(text.replace("\n", " "))[:MAX_WHAT]


#: Ends Blackbox INFERRED (the agent never said so): a later event from a different, live agent
#: process means the same session id runs again (``opencode --session``, a resumed run).
INFERRED_ENDS = ("process-exit", "quiet")
#: The event that starts each kind of instance — the only one that reopens an ended instance.
_STARTS = {"session": "session_start", "sub-agent": "subagent_start"}


def _resumes(found: Instance, event: Mapping[str, Any]) -> bool:
    """True when *event* starts *found* (ended) again. Ended means ended (KI-551): a late or
    repeated event of an ended instance never reopens it; only the agent's own start event does
    (a resume says so), or — when Blackbox only inferred the end — an event from another live
    process of the agent."""
    if event["event"] == _STARTS[found.kind]:
        return True
    pid = event.get("agent_pid")
    return found.end_reason in INFERRED_ENDS and isinstance(pid, int) and pid > 0 and pid != found.pid


def _open(key: str, event: Mapping[str, Any], *, kind: str, parent: str = "") -> Instance:
    """The instance *key*, created now when this is its first event, or reopened when *event*
    starts it again (:func:`_resumes`). An ended instance it does not start stays ended."""
    found = store.get(key)
    now = time.time()
    if found is None:
        found = Instance(key=key, agent=event["agent"], kind=kind, started=now, last=now, parent=parent,
                         launch="sub-agent" if kind == "sub-agent" else "unknown")
    elif found.ended is not None and _resumes(found, event):
        found.ended, found.end_reason, found.pid = None, "", 0   # its process is learned again from this run
    return found


def _describe(instance: Instance, event: Mapping[str, Any]) -> None:
    cwd = str(event.get("cwd") or "")
    if cwd:
        instance.cwd, instance.folder = cwd[:500], (cwd.rstrip("/").rsplit("/", 1)[-1])[:120]
    instance.model = str(event.get("model") or instance.model)[:80]
    instance.profile = str(event.get("profile") or instance.profile)[:500]
    instance.sandboxed = instance.sandboxed or event.get("sandboxed") is True
    if instance.kind == "session":
        if event.get("background"):
            instance.launch = "background"
        elif instance.launch == "unknown":
            # The agent's own word first (Claude Code's entry point), then its command line.
            from_process = str(event.get("launch") or "")
            instance.launch = _ENTRY_LAUNCH.get(str(event.get("entry") or "")) or (from_process if from_process in LAUNCHES else "unknown")
        if not instance.pid and isinstance(event.get("agent_pid"), int):
            instance.pid = event["agent_pid"]
    else:
        instance.type = str(event.get("sub_type") or instance.type)[:80]
        if not instance.task and event.get("task"):
            instance.task = redact_secret_values(str(event["task"]).replace("\n", " "))[:MAX_TASK]


#: What each kind of event says about waiting ("" = the agent is working again).
_WAITING_AFTER = {"turn_end": "idle", "prompt": "", "pre_tool": "", "post_tool": "", "session_start": "", "subagent_start": ""}


def _waiting(instance: Instance, kind: str, why: str) -> None:
    """Set or clear what *instance* waits for, from what its agent just said."""
    if kind == "attention":
        lowered = why.lower()
        instance.waiting = "permission" if "permission" in lowered else "idle" if "idle" in lowered else "attention"
    elif kind in _WAITING_AFTER:
        instance.waiting = _WAITING_AFTER[kind]


#: The prompt ids already counted per instance (newest kept), so one prompt is counted once.
_PROMPT_IDS: dict[str, list[str]] = {}
MAX_PROMPT_IDS = 32


def _new_prompt(instance: Instance, event: Mapping[str, Any]) -> bool:
    """True for a prompt of the PERSON not counted yet. WHY (KI-567, real Claude Code 2.1.330 with
    five background sub-agents, 2026-11-22): each sub-agent's result reached the session as a new
    turn that fired UserPromptSubmit — one prompt was counted six times."""
    if event.get("agent_turn") is True:
        return False
    prompt_id = str(event.get("prompt_id") or "")
    if not prompt_id:
        return True
    seen = _PROMPT_IDS.setdefault(instance.key, [])
    if prompt_id in seen:
        return False
    seen.append(prompt_id)
    del seen[:-MAX_PROMPT_IDS]
    return True


def _count(instance: Instance, kind: str, decision: str, findings: int, event: Mapping[str, Any], own: bool = True) -> None:
    """Count one event. An ended instance's ``last`` stays where it ended (start ≤ last ≤ end).
    *own*: the event is this instance's own, not one of its sub-agents' — a sub-agent's prompt
    (the task its session gave it) is the sub-agent's, never another prompt of the session's person."""
    if instance.ended is None:
        instance.last = time.time()
    instance.events += 1
    instance.checked += kind == "pre_tool"
    instance.prompts += kind == "prompt" and own and _new_prompt(instance, event)
    instance.refused += decision == "block"
    instance.too_late += decision == DECISION_TOO_LATE
    instance.flagged += decision not in ("block", DECISION_TOO_LATE) and findings > 0


def _end(instance: Instance, reason: str) -> None:
    instance.ended, instance.end_reason = time.time(), (reason or "ended")[:40]


def _open_sub(session: Instance, event: Mapping[str, Any]) -> Instance:
    """The sub-agent an event belongs to. Cursor's ``subagentStop`` names only the TYPE, so it
    closes the oldest open sub-agent of that type in the session."""
    raw = str(event.get("sub") or "")
    if not raw and event["event"] == "subagent_stop":
        open_subs = sorted((item for item in store.all_instances() if item.parent == session.key and item.ended is None
                            and item.type == str(event.get("sub_type") or item.type)), key=lambda item: item.started)
        if open_subs:
            return open_subs[0]
    return _open(sub_key(session.key, raw or f"{event.get('sub_type')}|{time.time()}"), event, kind="sub-agent", parent=session.key)


MAX_REASON = 400
_TIMELINE = ("pre_tool", "prompt", "subagent_start", "subagent_stop", "session_start", "stop", "turn_end", "attention")


def _target(session: Instance, event: Mapping[str, Any]) -> Instance:
    """The instance *event* is about: its sub-agent when it names one, else the session. Under an
    ENDED session no new sub-agent is created — a late event names a known one or the session."""
    if not (event.get("sub") or event["event"] in ("subagent_start", "subagent_stop")):
        return session
    if session.ended is not None:
        known = store.get(sub_key(session.key, str(event.get("sub") or "")))
        return known if known is not None and event.get("sub") else session
    return _open_sub(session, event)


def _timeline(target: Instance, event: Mapping[str, Any], decision: str, findings: int, reason: str, prompt_text: str,
              late: bool) -> None:
    kind = event["event"]
    verdict = decision if decision in ("block", DECISION_TOO_LATE) else "flag" if findings else "allow" if kind == "pre_tool" else ""
    action = Action(time.time(), kind, str(event.get("tool_name") or "")[:120], _what(event) if kind == "pre_tool" else "", verdict,
                    redact_secret_values(reason)[:MAX_REASON] if verdict in ("block", DECISION_TOO_LATE, "flag") else "",
                    prompt_text if kind == "prompt" else "", late)
    store.append_action(target.key, action, target.events)
    if not late:   # the live tree shows the newest entry — never a prompt's text
        target.last_action = Action(action.ts, action.kind, action.tool, action.what, action.verdict, action.reason)


def _end_spawned(session: Instance, event: Mapping[str, Any]) -> None:
    """A spawn call returned in *session*: the sub-agent it started is finished — for an agent
    whose hooks say no sub-agent stop of their own (OpenCode's ``task``). WHY (KI-574, real OpenCode
    1.19.6, 2026-11-22): its sub-agents stayed live until the 30-minute quiet limit."""
    host = BY_ID.get(session.agent)
    if host is None or "subagent_stop" in host.events.values() or str(event.get("tool_name") or "").lower() not in links.SPAWN_TOOLS:
        return
    found = store.get(links.claimed_by(str(event.get("tool_call_id") or "")) or "")
    if found is not None and found.ended is None:
        _end(found, "finished")
        store.put(found)


def _close_session(session: Instance, why: str) -> None:
    _end(session, why or "ended")
    for item in store.all_instances():
        if item.parent == session.key and item.ended is None:
            _end(item, "session-ended")
            store.put(item)


def record(event: Mapping[str, Any], session_key: str, *, decision: str = "", findings: int = 0, reason: str = "",
           prompt_text: str = "") -> Instance:
    """Record one validated hook *event* against its instance; returns that instance.

    *reason*: what the agent was told when the action was refused, or what flagged it. *prompt_text*: a prompt's
    text, already redacted — passed ONLY when the person turned prompt-text recording on.

    A session event updates the session; an event that names a sub-agent updates the sub-agent
    AND counts in its session (the session's totals include its sub-agents'). ``stop`` ends the
    session and every sub-agent still open in it. An event for an instance that has ENDED (and
    that it does not start again, see :func:`_resumes`) is LATE: counted and added to that
    instance's timeline marked ``late``, and the instance stays ended (KI-551)."""
    kind = event["event"]
    session = _open(session_key, event, kind="session")
    target = _target(session, event)
    late = target.ended is not None
    for item in (session,) if target is session else (session, target):
        if not late:
            _describe(item, event)
        _count(item, kind, decision, findings, event, own=item is target)
    if not late:
        _waiting(target, kind, str(event.get("why") or ""))
        if kind == "subagent_stop" and target is not session:
            _end(target, str(event.get("why") or "finished"))
        if kind == "stop":
            _close_session(session, str(event.get("why") or ""))
        if kind == "post_tool" and target is session:
            _end_spawned(session, event)
    if kind in _TIMELINE or late:
        _timeline(target, event, decision, findings, reason, prompt_text, late)
    if target is not session:
        store.put(target)
    store.put(session, flush=kind in ("stop", "session_start"))
    return target
