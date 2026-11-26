"""The hook runner's answer IN TIME: the dashboard first, then the installed plugin's own
judgement made here, inside one deadline — and the recording of a locally judged event after the answer.

Copied beside ``runner.py`` into Blackbox's data folder (``agent_hooks.RUNNER_FILES``; standard
library only until it loads the plugin). Private security finding
``2026-11-24-linux-an-agent-stops-blackbox-s-dashboar`` (Linux round L1, High): an agent killed
the dashboard and the hooks then let everything through. :func:`judge_here` loads the plugin
folder ``agent_hooks`` named in :data:`JUDGE_HERE_FILE` and answers with its ``events.judge`` —
the same guard, ruleset file, verified-graph lookup and local checks, offline.

Linux round L7 (BB-LINUX-PENDING-7582d0, Medium): on the busy VM the dashboard did not answer,
that judgement then took 15 s — and Gemini CLI, told to wait 10 s, stopped waiting and RAN the
call: a graph-listed package installed. Now (:func:`answer_in_time`):

* the dashboard has :data:`TIMEOUT_SECONDS` for both of its requests;
* the local judgement runs on its own thread and is waited for until :data:`BUDGET_SECONDS`
  after the hook started — a tool call it did not finish judging by then is REFUSED
  (:data:`NOT_CHECKED_IN_TIME`), never passed unjudged; a prompt or a tool's output passes with a
  note (those checks flag what Blackbox reads, as Hermes runs them: never blocking);
* only the VERDICT is worked out before the answer; what it leaves to record (the audit row, the
  session) runs AFTER it, in a detached child process (:func:`record_detached`), off the critical path;
* genuine breakage (no plugin, an import error) still fails open.

Usage (inside the runner)::

    verdict = answer_in_time(url, event, body, started)   # .answer, .record, .late
    answer, record = judge_here(summary_body)              # the local judgement alone
"""

from __future__ import annotations

import json
import os
import signal
import sys
import threading
import time
import urllib.request
from pathlib import Path

#: Beside the runner: where the plugin that installed it lives, and its homes —
#: ``{"plugin": <folder>, "hermes_home": …, "blackbox_home": …}`` (written by ``agent_hooks``).
JUDGE_HERE_FILE = "judge-here.json"
#: The name the plugin is loaded under for :func:`judge_here` (never a name Hermes uses).
_HERE_PACKAGE = "blackbox_judge_here"


def judge_here(body: dict) -> tuple:
    """The dashboard's answer to *body*, worked out in this process: the installed plugin's own
    judgement, loaded from the folder :data:`JUDGE_HERE_FILE` names (its package ``__init__`` is
    not run — only the judgement and what it imports) — and what is left to record, a callable
    (None: nothing). ``({}, None)`` when it cannot be loaded."""
    if __package__:   # imported as the plugin's module (tests, the plugin itself)
        from . import events
        return _judged(events, body)
    import importlib
    import types
    with open(Path(__file__).with_name(JUDGE_HERE_FILE), encoding="utf-8-sig") as handle:
        where = json.loads(handle.read(65536))
    plugin = Path(str(where.get("plugin") or ""))
    if not (plugin / "agent_hooks" / "protect" / "events.py").is_file():
        return {}, None
    for variable, key in (("HERMES_HOME", "hermes_home"), ("BLACKBOX_HOME", "blackbox_home")):
        if where.get(key):
            os.environ[variable] = str(where[key])   # this process only: the homes the dashboard runs with
    package = types.ModuleType(_HERE_PACKAGE)
    package.__path__ = [str(plugin)]
    package.__package__ = _HERE_PACKAGE
    sys.modules.setdefault(_HERE_PACKAGE, package)
    return _judged(importlib.import_module(_HERE_PACKAGE + ".agent_hooks.protect.events"), body)


def _judged(events, body: dict) -> tuple:
    answer, judged = events.judge(body)
    return answer, (None if judged is None else lambda: events.bookkeep(judged))



#: Events whose answer can stop the action.
BLOCKING_EVENTS = frozenset({"pre_tool", "prompt", "post_tool"})
#: How long the dashboard may take to answer (its two requests together) before the runner judges
#: the call itself. WHY 4 s: the dashboard holds the rules warm and answered in 0.1-3.3 s at load 12
#: on the L7 VM, while a fresh process's own judgement needs 8 s and more there (~700 modules to
#: import) — so a SLOW dashboard is worth waiting for, and an ABSENT one (connection refused, at
#: once) leaves the whole budget to the local judgement.
TIMEOUT_SECONDS = 4.0
#: The whole hook's time, from its start to its answer. WHY (Linux round L7, BB-LINUX-PENDING-7582d0):
#: every agent is told to wait 10 s for Blackbox (``kernel.agent_hosts.HOOK_WAIT_SECONDS``), and an
#: agent that stops waiting RUNS the call — on the busy VM the dashboard did not answer, the local
#: judgement then took 15 s, Gemini CLI gave up at 10 s and installed a graph-listed package. The
#: runner now answers by this deadline whatever happens; the rest of the 10 s is the interpreter's
#: start and exit on a busy machine (a whole run took up to 2.5 s more than its budget at load 12 on the L7 VM).
BUDGET_SECONDS = 6.5
#: What the agent is told when a call could not be judged inside :data:`BUDGET_SECONDS`: refused,
#: never passed unjudged (the same rule Hermes keeps for its own timed-out ``pre_tool_call``).
NOT_CHECKED_IN_TIME = ("Blackbox could not check this action in time (this computer is very busy), so it was refused. "
                       "Try it again in a moment.")
#: The most a detached recorder (:func:`_record_detached`) may run before it ends itself.
RECORD_SECONDS = 120


def _left(deadline: float) -> float:
    """Seconds until *deadline*; raises TimeoutError once it passed (no request is started late)."""
    left = deadline - time.time()
    if left <= 0.05:
        raise TimeoutError("the dashboard's time is up")
    return left


def ask(url: str, body: dict, deadline: float = 0.0) -> dict:
    """POST *body* to the dashboard with its session token, both requests inside *deadline*
    (epoch seconds; :data:`TIMEOUT_SECONDS` from now when 0); {} when it cannot answer."""
    deadline = deadline or time.time() + TIMEOUT_SECONDS
    with urllib.request.urlopen(f"{url}/api/session", timeout=_left(deadline)) as response:
        token = json.loads(response.read(65536)).get("token", "")
    # When this hook stops waiting for the dashboard: an answer after it reaches nobody, and the
    # dashboard records it as decided too late, never as stopped (KI-PENDING-f5765e).
    body = {**body, "answer_by": round(deadline, 3)}
    request = urllib.request.Request(f"{url}/api/agent-hooks/event", data=json.dumps(body).encode("utf-8"), method="POST",
                                     headers={"content-type": "application/json", "X-Blackbox-Token": token})
    with urllib.request.urlopen(request, timeout=_left(deadline)) as response:
        answer = json.loads(response.read(65536))
    return answer if isinstance(answer, dict) else {}


class Verdict:
    """The local judgement's outcome: *answer* (as the dashboard's), *record* (what is left to
    record, run after the agent has its answer), *late* (the judgement did not finish in time —
    the process then ends without waiting for it)."""

    def __init__(self, answer: dict, record=None, late: bool = False) -> None:
        self.answer, self.record, self.late = answer, record, late


def _judge_in_time(event: str, body: dict, deadline: float) -> Verdict:
    """:func:`judge_here` on its own thread, waited for until *deadline*. Not finished by then: a
    tool call is REFUSED (:data:`NOT_CHECKED_IN_TIME`), a prompt or a tool's output passes with a
    note (those checks only flag what Blackbox reads; Hermes runs them without ever blocking).
    Raised: genuine breakage — fail open."""
    outcome: list = []

    def run() -> None:
        try:
            outcome.append(judge_here(body))
        except BaseException as broken:   # health: allow BLE001 -- handed back below: fail open
            outcome.append(broken)

    worker = threading.Thread(target=run, name="blackbox-judge-here", daemon=True)
    worker.start()
    worker.join(max(0.0, deadline - time.time()))
    if not outcome:
        sys.stderr.write("Blackbox: the check did not finish in time on this busy computer.\n")
        if event == "pre_tool":
            return Verdict({"decision": "block", "message": NOT_CHECKED_IN_TIME}, late=True)
        return Verdict({}, late=True)
    if isinstance(outcome[0], BaseException):
        return Verdict({})   # fail open: genuine breakage never stops the agent
    answer, record = outcome[0]
    return Verdict(answer, record)


def answer_in_time(url: str, event: str, body: dict, started: float = 0.0) -> Verdict:
    """The dashboard's answer, or — when it does not answer in time and the event can stop the
    action — the same judgement made here (:func:`judge_here`) inside the hook's budget; an empty
    answer when neither can be had (fail open)."""
    started = started or time.time()
    try:
        return Verdict(ask(url, body, min(started + TIMEOUT_SECONDS, started + BUDGET_SECONDS)))
    except Exception as down:   # health: allow BLE001 -- the dashboard is down or slow: judge locally instead
        if event not in BLOCKING_EVENTS:
            return Verdict({})
        sys.stderr.write(f"Blackbox: the dashboard did not answer ({type(down).__name__}); judging here.\n")
    return _judge_in_time(event, body, started + BUDGET_SECONDS)


def record_detached(record) -> None:
    """Run *record* after the agent has its answer: in a child process that lets go of the
    agent's pipes at once (the agent waits for this process and its output to end), so recording
    never delays or loses a verdict. Where there is no fork (Windows) it runs here, after the
    answer was written."""
    if not hasattr(os, "fork"):
        record()
        return
    sys.stdout.flush()
    sys.stderr.flush()
    try:
        child = os.fork()
    except OSError:
        record()
        return
    if child:
        return
    try:   # the child: no pipe of the agent's, its own session, a bounded life
        os.setsid()
        quiet = os.open(os.devnull, os.O_RDWR)
        for stream in (0, 1, 2):
            os.dup2(quiet, stream)
        if hasattr(signal, "alarm"):
            signal.alarm(RECORD_SECONDS)
        record()
    finally:
        os._exit(0)


__all__ = ["BLOCKING_EVENTS", "BUDGET_SECONDS", "JUDGE_HERE_FILE", "NOT_CHECKED_IN_TIME", "RECORD_SECONDS", "TIMEOUT_SECONDS", "Verdict",
           "answer_in_time", "ask", "judge_here", "record_detached"]
