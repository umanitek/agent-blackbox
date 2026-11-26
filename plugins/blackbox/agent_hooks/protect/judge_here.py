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
    where = _where()
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


def _where() -> dict:
    """What :data:`JUDGE_HERE_FILE` says (``{}`` when it can not be read)."""
    try:
        with open(Path(__file__).with_name(JUDGE_HERE_FILE), encoding="utf-8-sig") as handle:
            where = json.loads(handle.read(65536))
    except (OSError, ValueError):
        return {}
    return where if isinstance(where, dict) else {}


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


#: The kernel's record of this process (its start time, field 22) and the time since boot, where the
#: system keeps them as files (Linux); elsewhere the budget counts from the runner's own start.
_SELF_STAT, _UPTIME = "/proc/self/stat", "/proc/uptime"


def process_age() -> float:
    """Seconds since this process started (0.0 where that can not be read). WHY (bb-l7-u24, load
    10): the interpreter's own start took up to 5 s there, and the agent's 10 s wait began before
    it — a budget counted from ``main()`` answered at 11.8 s, after the agent had stopped waiting."""
    try:
        with open(_SELF_STAT, "rb") as handle:
            fields = handle.read(4096).rsplit(b")", 1)[1].split()
        with open(_UPTIME, "rb") as handle:
            up = float(handle.read(256).split()[0])
        return max(0.0, up - int(fields[19]) / os.sysconf("SC_CLK_TCK"))
    except (OSError, ValueError, IndexError):
        return 0.0


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
    the process then ends without waiting for it), *unrecorded* (the dashboard did not answer, so
    nothing recorded the event yet: :func:`keep` does)."""

    def __init__(self, answer: dict, record=None, late: bool = False, unrecorded: bool = False) -> None:
        self.answer, self.record, self.late, self.unrecorded = answer, record, late, unrecorded


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

    worker = threading.Thread(target=run, name="blackbox-judge-here", daemon=True)   # health: allow HX012 -- stdlib-only runner, one process per hook: no profile scope to carry
    worker.start()
    worker.join(max(0.0, deadline - time.time()))
    if not outcome:
        sys.stderr.write("Blackbox: the check did not finish in time on this busy computer.\n")
        if event == "pre_tool":
            return Verdict({"decision": "block", "message": NOT_CHECKED_IN_TIME}, late=True, unrecorded=True)
        return Verdict({}, late=True, unrecorded=True)
    if isinstance(outcome[0], BaseException):
        return Verdict({}, unrecorded=True)   # fail open: genuine breakage never stops the agent
    answer, record = outcome[0]
    return Verdict(answer, record, unrecorded=True)


def answer_in_time(url: str, event: str, body: dict, started: float = 0.0) -> Verdict:
    """The dashboard's answer, or — when it does not answer in time and the event can stop the
    action — the same judgement made here (:func:`judge_here`) inside the hook's budget; an empty
    answer when neither can be had (fail open)."""
    started = started or time.time()
    try:
        return Verdict(ask(url, body, min(started + TIMEOUT_SECONDS, started + BUDGET_SECONDS)))
    except Exception as down:   # health: allow BLE001 -- the dashboard is down or slow: judge locally instead
        if event not in BLOCKING_EVENTS:
            return Verdict({}, unrecorded=True)
        sys.stderr.write(f"Blackbox: the dashboard did not answer ({type(down).__name__}); judging here.\n")
    return _judge_in_time(event, body, started + BUDGET_SECONDS)


#: :data:`JUDGE_HERE_FILE`'s key naming the spool folder (``agent_hooks.protect.spool``).
SPOOL_KEY = "spool"
#: The most events that wait in the spool; past it a refusal still leaves its journal mark.
MAX_SPOOLED = 2000
#: The largest spooled event (a write tool's whole file can be in it): past it its text is dropped.
MAX_SPOOLED_BYTES = 512 * 1024
#: The system journal's socket (Linux, systemd) and the tag of Blackbox's marks in it.
JOURNAL_SOCKET, JOURNAL_TAG = "/run/systemd/journal/socket", "blackbox-hook"
#: A journal mark's spool name when the event could not be written to the spool (full, no disk).
UNSPOOLED = "unspooled"
#: Events whose text is the person's own words: never written to the spool.
_PERSONS_WORDS = frozenset({"prompt", "session_start"})


def keep(verdict: Verdict, body: dict, detach: bool = False) -> None:
    """After the answer: record what the dashboard did not (it did not answer in time).

    WHY (Linux round L8, BB-LINUX-PENDING-e6e905, Medium): with the dashboard stopped, a SANDBOXED
    agent's refusal left no row, finding or session. Inside the sandbox Blackbox's data folder is
    read-only (``EROFS``), and below Linux 6.12 the sandbox is a PID namespace whose processes the
    kernel kills when the agent ends — so the detached recorder could neither write nor outlive
    it. Now: the detached recorder (:func:`record_detached`) only where this process may write
    Blackbox's data folder; everywhere else the event goes, before this process ends, into the
    spool the dashboard replays (``agent_hooks.protect.spool.replay``) — a 0600 file in a folder
    the sandbox leaves writable — and a refusal also into the system journal (Linux), which the
    agent can neither change nor delete: a spooled refusal removed before the dashboard read it is
    then itself reported. A call refused unjudged (:data:`NOT_CHECKED_IN_TIME`) is kept the same way."""
    if not verdict.unrecorded or not body or verdict.answer.get("recorded") is False:
        return
    home, spool = _homes()
    if verdict.record is not None and not verdict.late and (not spool or _may_write(home)):
        (record_detached if detach else _now)(verdict.record)
        return
    decided = str(verdict.answer.get("decision") or "allow")
    name = _spooled(spool, body, decided, verdict.late) if spool else ""
    if decided == "block":
        _journal_mark(name, body, verdict)


def _may_write(folder: str) -> bool:
    """True when this process may write *folder* (or, before it exists, the folder it would be made
    in). ``access`` answers False on a read-only mount (``EROFS``) — the sandbox's — whatever the modes say."""
    path = os.path.abspath(folder or "/")
    while not os.path.exists(path) and os.path.dirname(path) != path:
        path = os.path.dirname(path)
    return os.access(path, os.W_OK)


def _now(record) -> None:
    record()


def _homes() -> tuple:
    """``(Blackbox's data folder, the spool folder)`` this runner records into ("" when unknown)."""
    if __package__:
        from . import spool
        from ...kernel import constants
        return str(constants.blackbox_home()), str(spool.folder())
    where = _where()
    return str(where.get("blackbox_home") or ""), str(where.get(SPOOL_KEY) or "")


def _spooled(folder: str, body: dict, decided: str, late: bool) -> str:
    """Write one event into the spool *folder* (whole or not at all); its name, "" when not written."""
    import secrets
    body = {**body, "text": ""} if body.get("event") in _PERSONS_WORDS else body
    entry = {"body": body, "decided": decided, "late": late, "at": time.time()}
    raw = json.dumps(entry, default=str)
    if len(raw) > MAX_SPOOLED_BYTES:
        entry["body"] = {**body, "text": "", "args": {"dropped": "too long to keep"}}
        raw = json.dumps(entry, default=str)
    try:
        os.makedirs(folder, mode=0o700, exist_ok=True)
        if len(os.listdir(folder)) >= MAX_SPOOLED:
            return ""
        name = f"{time.time_ns()}-{os.getpid()}-{secrets.token_hex(4)}"
        part = os.path.join(folder, name + ".part")
        handle = os.open(part, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
        with os.fdopen(handle, "w", encoding="utf-8") as out:
            out.write(raw)
        os.replace(part, os.path.join(folder, name + ".json"))   # the replay never reads half an event
        return name
    except OSError:
        return ""


def _journal_mark(name: str, body: dict, verdict: Verdict) -> None:
    """A refusal's line in the system journal (Linux; nothing where there is none): agent, event,
    tool and the spool name — never the call's arguments or text."""
    if not os.path.exists(JOURNAL_SOCKET):
        return
    fields = {"MESSAGE": f"Blackbox refused a {body.get('agent')} action ({'not checked in time' if verdict.late else 'judged here'})",
              "SYSLOG_IDENTIFIER": JOURNAL_TAG, "PRIORITY": "5", "BLACKBOX_SPOOL_ID": name or UNSPOOLED,
              "BLACKBOX_AGENT": body.get("agent"), "BLACKBOX_EVENT": body.get("event"), "BLACKBOX_TOOL": body.get("tool_name"),
              "BLACKBOX_SESSION": body.get("session"), "BLACKBOX_LATE": "1" if verdict.late else "0"}
    lines = "".join(f"{key}={str(value or '').replace(chr(10), ' ')[:300]}\n" for key, value in fields.items())
    try:
        import socket
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as journal:
            journal.settimeout(0.5)
            journal.sendto(lines.encode("utf-8", "replace"), JOURNAL_SOCKET)
    except OSError:
        pass   # no journal here: the spool file is the record


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
        child = os.fork()   # windows-footgun: ok -- guarded above: no fork means record here
    except OSError:
        record()
        return
    if child:
        return
    try:   # the child: no pipe of the agent's, its own session, a bounded life
        os.setsid()   # windows-footgun: ok -- only in the forked child (POSIX)
        quiet = os.open(os.devnull, os.O_RDWR)
        for stream in (0, 1, 2):
            os.dup2(quiet, stream)
        if hasattr(signal, "alarm"):
            signal.alarm(RECORD_SECONDS)
        record()
    finally:
        os._exit(0)


__all__ = ["BLOCKING_EVENTS", "BUDGET_SECONDS", "JOURNAL_SOCKET", "JOURNAL_TAG", "JUDGE_HERE_FILE", "MAX_SPOOLED", "NOT_CHECKED_IN_TIME",
           "RECORD_SECONDS", "SPOOL_KEY", "TIMEOUT_SECONDS", "UNSPOOLED", "Verdict", "answer_in_time", "ask", "judge_here", "keep", "process_age",
           "record_detached"]
