"""Every instance of every coding agent: live, and kept as history.

A hook event says which session it belongs to — and, inside a session, which sub-agent
(``agent_id`` for Claude Code, Codex and Copilot CLI; ``subagent_id`` for Cursor). :func:`record`
turns each event into the instance it belongs to (created on first sight, ended when the agent
says so), counts what Blackbox checked and refused, and adds the action to the instance's
timeline. :mod:`.views` answers what the dashboard and Blackbox Desktop show.

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

from ...kernel.redaction import redact_secret_values
from . import store
from .model import Action, Instance

__all__ = ["record", "store", "sub_key"]

MAX_WHAT = 200
_ENTRY_LAUNCH = {"cli": "interactive", "sdk-ts": "sdk", "sdk-py": "sdk", "sdk-cli": "headless", "claude-vscode": "ide",
                 "claude-desktop": "ide", "mcp": "sdk"}


def sub_key(session: str, raw: str) -> str:
    """A sub-agent's key under its session's (the agent's own id is hashed, never kept)."""
    return f"{session}/{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:12]}"


def _what(event: Mapping[str, Any]) -> str:
    args = event.get("args")
    text = ""
    if isinstance(args, dict):
        text = str(args.get("command") or args.get("path") or args.get("file_path") or args.get("url") or "")
    return redact_secret_values(text.replace("\n", " "))[:MAX_WHAT]


def _open(key: str, event: Mapping[str, Any], *, kind: str, parent: str = "") -> Instance:
    """The instance *key*, created now when this is its first event."""
    found = store.get(key)
    now = time.time()
    if found is None:
        found = Instance(key=key, agent=event["agent"], kind=kind, started=now, last=now, parent=parent,
                         launch="sub-agent" if kind == "sub-agent" else "unknown")
    elif found.ended is not None and event["event"] not in ("stop", "subagent_stop"):
        found.ended, found.end_reason = None, ""   # a resumed session, or a sub-agent that goes on
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
            instance.launch = _ENTRY_LAUNCH.get(str(event.get("entry") or ""), "unknown")
        if not instance.pid and isinstance(event.get("agent_pid"), int):
            instance.pid = event["agent_pid"]
    else:
        instance.type = str(event.get("sub_type") or instance.type)[:80]


#: What each kind of event says about waiting ("" = the agent is working again).
_WAITING_AFTER = {"turn_end": "idle", "prompt": "", "pre_tool": "", "post_tool": "", "session_start": "", "subagent_start": ""}


def _waiting(instance: Instance, kind: str, why: str) -> None:
    """Set or clear what *instance* waits for, from what its agent just said."""
    if kind == "attention":
        lowered = why.lower()
        instance.waiting = "permission" if "permission" in lowered else "idle" if "idle" in lowered else "attention"
    elif kind in _WAITING_AFTER:
        instance.waiting = _WAITING_AFTER[kind]


def _count(instance: Instance, kind: str, decision: str, findings: int) -> None:
    instance.last = time.time()
    instance.events += 1
    instance.checked += kind == "pre_tool"
    instance.prompts += kind == "prompt"
    instance.refused += decision == "block"
    instance.flagged += decision != "block" and findings > 0


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


def record(event: Mapping[str, Any], session_key: str, *, decision: str = "", findings: int = 0, reason: str = "",
           prompt_text: str = "") -> Instance:
    """Record one validated hook *event* against its instance; returns that instance.

    *reason*: what the agent was told when the action was refused. *prompt_text*: a prompt's
    text, already redacted — passed ONLY when the person turned prompt-text recording on.

    A session event updates the session; an event that names a sub-agent updates the sub-agent
    AND counts in its session (the session's totals include its sub-agents'). ``stop`` ends the
    session and every sub-agent still open in it."""
    kind = event["event"]
    session = _open(session_key, event, kind="session")
    _describe(session, event)
    target = session
    if event.get("sub") or kind in ("subagent_start", "subagent_stop"):
        target = _open_sub(session, event)
        _describe(target, event)
        _count(target, kind, decision, findings)
        if kind == "subagent_stop":
            _end(target, str(event.get("why") or "finished"))
    _count(session, kind, decision, findings)
    _waiting(target, kind, str(event.get("why") or ""))
    if kind == "stop":
        _end(session, str(event.get("why") or "ended"))
        for item in store.all_instances():
            if item.parent == session.key and item.ended is None:
                _end(item, "session-ended")
                store.put(item)
    if kind in _TIMELINE:
        verdict = "block" if decision == "block" else "flag" if findings else "allow" if kind == "pre_tool" else ""
        action = Action(time.time(), kind, str(event.get("tool_name") or "")[:120], _what(event) if kind == "pre_tool" else "", verdict,
                        redact_secret_values(reason)[:MAX_REASON] if verdict == "block" else "",
                        prompt_text if kind == "prompt" else "")
        store.append_action(target.key, action, target.events)
        # The live tree shows the newest entry — never a prompt's text.
        target.last_action = Action(action.ts, action.kind, action.tool, action.what, action.verdict, action.reason)
    if target is not session:
        store.put(target)
    store.put(session, flush=kind in ("stop", "session_start"))
    return target
