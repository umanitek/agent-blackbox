"""One hook event from a coding agent: recorded, and — before a tool runs — judged.

:func:`answer_event` is what ``POST /api/agent-hooks/event`` calls with the runner's summary
(:func:`.runner.summary`): :func:`judge` answers, and :func:`bookkeep` records on the recorder
thread after the agent has its answer (KI-552); :func:`record_event` does both before returning
(tests, direct callers). Together they

* judges a ``pre_tool`` call with the ONE guard (``guard.tool_call_verdict``, the same checks a
  Hermes agent's hook runs — threats AND self-protection) and answers ``{"decision": "block",
  "message"}`` or ``allow``; a Codex ``apply_patch`` is judged file by file;
* checks TEXT for prompt injection with the same guard (``guard.text_verdict``: only a verified
  pattern blocks, in Block mode): the prompt before it is sent, a tool's output before the model
  reads it, a file before a pre-read hook lets the agent read it. The text is checked in this
  process and not recorded — the records keep its length, and a finding only its matched phrase
  as local evidence (≤200 chars, redacted — as for a Hermes agent). One exception, the person's
  own choice: with ``agent_activity.record_prompt_text`` on (off by default), a PROMPT's redacted
  text is handed to the instance timeline (``agent_hooks.prompt_text``) — never to the audit log,
  a finding or a report;
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
from collections import OrderedDict
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Mapping, Optional

from ... import audit, guard
from ...kernel import constants
from ...kernel.bounded_files import read_json_object, write_json_object
from ...kernel.agent_hosts import BY_ID, DECISION_TOO_LATE, EVENTS
from . import recorder
from .runner import patch_files

if TYPE_CHECKING:
    from ..tracking import Captured

#: The most text one event carries for the injection check (the runner bounds it the same).
MAX_CHECK_TEXT = 256 * 1024
#: Tools whose output is a fetched web page (an injection there names its site).
_FETCH_TOOLS = ("webfetch", "web_fetch", "fetch", "web_extract", "browse", "read_url", "url")
_EMPTY = {"findings": [], "blocked": [], "decision": "", "message": ""}

#: An answer this close to the hook's limit may arrive after it (the bytes still travel): it is
#: recorded as too late rather than claimed as a stop — Blackbox under-claims, never over-claims.
LATE_MARGIN_SECONDS = 0.25

#: Sessions kept per agent (the oldest go first).
MAX_SESSIONS = 40
MAX_TEXT = 500
#: The audit event each hook event is written as (Agent activity's own vocabulary).
AUDIT_EVENT = {"session_start": "session_start", "prompt": "user_prompt", "pre_tool": "pre_tool_call",
               "post_tool": "post_tool_call", "turn_end": "agent_turn_end", "stop": "session_end",
               "subagent_start": "subagent_start", "subagent_stop": "subagent_stop", "config_change": "config_change",
               "attention": "agent_attention"}

_lock = threading.Lock()

#: How many sessions' answered calls are remembered (the least recently active go first), and
#: how many calls per session.
MAX_ANSWERED_SESSIONS = 256
MAX_ANSWERED_PER_SESSION = 256
#: ``session`` → ``(the agent's tool-call id, event)`` → the answer. WHY: an agent can report ONE
#: call through two hook forms (Cline's hook script and its SDK plugin; OpenCode's two plugin
#: files) or send the same event twice; the repeat gets the first answer and is not recorded or
#: counted again (KI-551). Keyed per session on the agent's OWN call id, with no time limit — the
#: same id is the same call however late it comes — and bounded per session and in sessions, so
#: a busy session cannot push another session's calls out.
_answered: OrderedDict[str, OrderedDict[tuple[str, str], dict[str, Any]]] = OrderedDict()


def _answered_before(session: str, call: tuple[str, str]) -> dict[str, Any] | None:
    with _lock:
        calls = _answered.get(session)
        return dict(calls[call]) if calls is not None and call in calls else None


def _note_answer(session: str, call: tuple[str, str], answer: Mapping[str, Any]) -> None:
    with _lock:
        calls = _answered.setdefault(session, OrderedDict())
        _answered.move_to_end(session)
        calls[call] = dict(answer)
        while len(calls) > MAX_ANSWERED_PER_SESSION:
            calls.popitem(last=False)
        while len(_answered) > MAX_ANSWERED_SESSIONS:
            _answered.popitem(last=False)


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
            "prompt_chars": chars if isinstance(chars, int) and chars >= 0 else 0, "text": text[:MAX_CHECK_TEXT],
            "sandboxed": body.get("sandboxed") is True, "answer_by": _answer_by(body.get("answer_by")), **_identity(body)}


def _answer_by(value: Any) -> float:
    """When the hook stops waiting (the runner's ``answer_by``, epoch seconds); 0 when not said."""
    return float(value) if isinstance(value, (int, float)) and not isinstance(value, bool) and value > 0 else 0.0


def _identity(body: Mapping[str, Any]) -> dict[str, Any]:
    """Which instance the event belongs to (the runner's ``identity``), as bounded fields."""
    pid = body.get("pid")
    return {"sub": _text(body.get("sub"), 200), "sub_type": _text(body.get("sub_type"), 80), "task": _text(body.get("task"), 200),
            "parents_named": body.get("parents_named") is True,
            "parent": _text(body.get("parent"), 200), "model": _text(body.get("model"), 80), "why": _text(body.get("why"), 40),
            "background": body.get("background") is True, "profile": _text(body.get("profile")),
            "entry": _text(body.get("entry"), 40), "pid": pid if isinstance(pid, int) and not isinstance(pid, bool) and pid > 0 else 0}


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
    if tool_name == "read_file" and isinstance(args, dict) and isinstance(args.get("paths"), list):
        # One call that reads several files (Cline's read_files): each file is judged.
        verdicts += [guard.tool_call_verdict(tool_name="read_file", args={"path": str(path)}) for path in args["paths"][1:50]]
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


def _remember(event: Mapping[str, Any], session: str, decision: str) -> None:
    now = time.time()
    with _lock:
        state = read_state()
        agent = state["agents"].setdefault(event["agent"], {})
        agent["last_event"] = now
        agent["events"] = int(agent.get("events", 0)) + 1
        sessions = agent.setdefault("sessions", {})
        row = sessions.setdefault(session, {"first": now, "events": 0, "tools": 0, "blocked": 0, "too_late": 0, "folder": ""})
        row["last"] = now
        row["events"] += 1
        row["tools"] += event["event"] == "pre_tool"
        row["blocked"] += decision == "block"
        row["too_late"] = int(row.get("too_late", 0)) + (decision == DECISION_TOO_LATE)
        row["folder"] = (event["cwd"].rstrip("/").rsplit("/", 1)[-1] or row["folder"])[:120]
        row["ended"] = event["event"] == "stop" or (row.get("ended", False) and event["event"] in ("turn_end", "subagent_stop"))
        # Inside File Shield's OS sandbox (the runner proved it with the canary): once seen, the session is.
        row["sandboxed"] = bool(row.get("sandboxed")) or event.get("sandboxed") is True
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


@dataclass(frozen=True)
class Judged:
    """One event after its verdict: what :func:`bookkeep` records (the audit row, the per-agent
    state, the instance timeline). *process*: the agent process learned while the hook waited."""

    event: dict[str, Any]
    session: str
    verdict: dict[str, Any]
    findings: list[dict[str, Any]]
    blocked: bool
    process: Optional[Captured]
    decision: str = ""   # what is RECORDED: the verdict's, or DECISION_TOO_LATE for a stop the agent never got


def judge(body: Any) -> tuple[dict[str, Any], Optional[Judged]]:
    """The answer to one hook event — and what is left to record (None: nothing). Only what the
    answer needs runs here: the checks, the guard's verdict, and reading the hook's ancestry
    while the hook still exists (``tracking.capture``, microseconds). Raises ValueError for a
    malformed event."""
    event = validate(body)
    state = read_state()["agents"].get(event["agent"], {})
    if state.get("disabled"):
        return {"decision": "allow", "message": "", "recorded": False}, None   # a stale hook after "Stop protecting"
    session = session_key(event["agent"], event["session"], event["cwd"])
    call_key = (event["tool_call_id"], event["event"])
    if event["tool_call_id"] and event["event"] in ("pre_tool", "post_tool"):
        again = _answered_before(session, call_key)
        if again is not None:
            return {**again, "recorded": False}, None   # the same call, reported through a second hook form
    verdict = _verdict(event)
    findings = [{**finding, "tool_name": event["tool_name"]} for finding in verdict.get("findings") or []]
    blocked = verdict.get("decision") == "block"
    answer = {"decision": "block" if blocked else "allow", "message": verdict.get("message", "") if blocked else "",
              "findings": len(findings), "recorded": True}
    if event["tool_call_id"] and event["event"] in ("pre_tool", "post_tool"):
        _note_answer(session, call_key, answer)
    from .. import tracking   # late: tracking imports this package's editors
    process = tracking.capture(event, session)
    decision = str(verdict.get("decision") or "")
    if blocked and event["answer_by"] and time.time() > event["answer_by"] - LATE_MARGIN_SECONDS:
        decision = DECISION_TOO_LATE   # the hook had stopped waiting: the action ran
    return answer, Judged(event, session, verdict, findings, blocked, process, decision)


def bookkeep(judged: Judged) -> None:
    """Record a judged event: the agent's audit log, its per-agent state and its instance."""
    event, session, verdict, decision = judged.event, judged.session, judged.verdict, judged.decision
    detail: dict[str, Any] = {"session_id": session}
    if event["event"] in ("pre_tool", "post_tool"):
        detail.update(tool_name=event["tool_name"], tool_call_id=event["tool_call_id"] or f"{session}:{time.time()}")
    if event["event"] == "pre_tool":
        detail.update(args=event["args"], decision=decision or "allow")
    if event["event"] == "prompt":
        detail["prompt_chars"] = event["prompt_chars"]
    if event["text"]:
        detail["checked_chars"] = len(event["text"])   # the text itself is never recorded
    if decision and event["event"] != "pre_tool":
        detail["decision"] = decision
    if event["sub"] or event["event"] in ("subagent_start", "subagent_stop"):
        detail["sub_agent"] = hashlib.sha256(event["sub"].encode("utf-8")).hexdigest()[:12] if event["sub"] else ""
        detail["sub_agent_type"] = event["sub_type"]
    audit.record_for(event["agent"], event=AUDIT_EVENT[event["event"]], workspace=event["cwd"],
                     findings=judged.findings or None, detail=detail)
    _remember(event, session, decision)
    from .. import tracking   # late: tracking imports this package's editors
    tracking.track(event, session, decision=decision, findings=len(judged.findings),
                   reason=reason_of(verdict, judged.findings),
                   text=event["text"] if event["event"] == "prompt" else "",   # kept only if the person turned that on
                   process=judged.process)
    if event["event"] == "post_tool" and event["sandboxed"]:   # a refusal the kernel made during that call (KI-568)
        tracking.attribute_kernel_refusals()


#: The most finding titles a flagged row names as its reason.
MAX_REASON_TITLES = 3


def reason_of(verdict: Mapping[str, Any], findings: list[dict[str, Any]]) -> str:
    """Why an event was refused OR flagged, in words: what the agent was told when it was refused,
    else the titles of the findings that flagged it. WHY: a flagged row once carried no reason at
    all — the person saw "flagged" and nothing else (KI-573, real Cline and OpenCode runs
    2026-11-22). Empty only when nothing was found."""
    message = str(verdict.get("message") or "")
    if message:
        return message
    titles = list(dict.fromkeys(str(finding.get("title") or finding.get("identifier") or "") for finding in findings))
    titles = [title for title in titles if title]
    more = len(titles) - MAX_REASON_TITLES
    return "; ".join(titles[:MAX_REASON_TITLES]) + (f" (and {more} more)" if more > 0 else "")


def record_event(body: Any) -> dict[str, Any]:
    """Record one hook event and answer it, both before returning. Raises ValueError for a
    malformed event."""
    answer, judged = judge(body)
    if judged is not None:
        bookkeep(judged)
    return answer


def answer_event(body: Any) -> dict[str, Any]:
    """Answer one hook event now and record it right after, on the recorder thread
    (:mod:`.recorder`) — what ``POST /api/agent-hooks/event`` calls, so an agent waits only for
    the verdict (KI-552). Raises ValueError for a malformed event."""
    answer, judged = judge(body)
    if judged is not None:
        recorder.submit(lambda: bookkeep(judged))
    return answer
