"""An AI agent's programs running as root — the FACT, seen in the process list (read-only).

``detection.detect_elevation`` flags an agent ASKING for root; this module sees that it GOT it:
a process an agent session started (at any depth), or the agent itself, whose real AND effective
user is root. A setuid system tool (``ps``; ``sudo`` while it still asks for the password) has
only the effective user 0 and is not counted, nor are the programs that merely ask
(:data:`ASKERS`) — what they start is.

Each new root run is recorded once: an entry in the instance's timeline (kind ``root``), the
instance's ``root`` / ``root_runs`` / ``root_last``, and a local finding ``agent:running-as-root``
(critical; source ``custom`` — never shared) that the findings list and the notifications show.
When the last one ends the instance's ``root`` goes back to False.

Limits, said plainly: the list is read about every 1.5 s, so a root command shorter than that
can be missed (its REQUEST is still flagged); a root program that detaches from the agent's
process tree is no longer attributed to it. Nothing here signals or stops a process.

Usage::

    from . import root_watch
    new = root_watch.scan(table, users, sessions)     # [RootRun] first seen in this reading
    root_watch.note(instance)                          # one plain sentence for the live view, or ""
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from pathlib import PurePath
from typing import Iterable, Mapping

from .. import audit
from . import observe
from .instances import store, views
from .instances.model import Action, Instance

__all__ = ["ASKERS", "ROOT_ID", "RootRun", "note", "reset", "scan"]

ROOT_ID = "agent:running-as-root"
TITLE = "A program started by an AI agent is running as root"
#: Programs that ask for root; they are setuid themselves and are not the root run — what they start is.
ASKERS = frozenset({"sudo", "su", "doas", "pkexec", "login", "sudoedit", "security_authtrampoline"})
MAX_KNOWN = 2000
_lock = threading.Lock()
#: ``(pid, process start)`` → the run, for every root run that is still there.
_known: dict[tuple[int, float], RootRun] = {}


@dataclass(frozen=True)
class RootRun:
    """One root process in an agent's tree. *program*: its file name only (never its arguments).
    *itself*: the agent's own process is the one running as root."""

    instance: str
    agent: str
    pid: int
    program: str
    started: float
    itself: bool = False


def reset() -> None:
    """Forget every known run (tests)."""
    with _lock:
        _known.clear()


def _program(command: str) -> str:
    words = command.split()
    return PurePath(words[0]).name[:80] if words else ""


def _is_root(users: Mapping[int, tuple[int, int]], pid: int) -> bool:
    return users.get(pid) == (0, 0)


def _record(run: RootRun, session: Instance) -> None:
    """Put a new root run on its instance, in its timeline and in the findings."""
    now = time.time()
    session.root, session.root_runs, session.root_last = True, session.root_runs + 1, now
    session.flagged += 1
    what = f"{run.program} (the agent itself)" if run.itself else run.program
    action = Action(now, "root", "", what, "flag")
    store.append_action(session.key, action, session.events)
    session.last_action = action
    store.put(session, flush=True)
    finding = {"identifier": ROOT_ID, "category": "escalation", "severity": "critical", "title": TITLE, "tool_name": "",
               "evidence": f"{what}, process {run.pid}", "confirmed": False, "source": "custom",
               "fields": {"program": run.program, "session": session.key, "itself": run.itself}}
    try:
        audit.record_for(run.agent, event="agent_root", workspace=session.cwd, findings=[finding],
                         detail={"session_id": session.key, "program": run.program, "pid": run.pid, "decision": "flag"})
    except Exception:   # health: allow BLE001 -- the timeline and the live view already hold it
        pass


def scan(table: Mapping[int, observe.Proc], users: Mapping[int, tuple[int, int]], sessions: Iterable[Instance]) -> list[RootRun]:
    """Compare the process list with what is known: record each NEW root process in a live
    session's tree, and clear ``root`` on a session whose root processes all ended. Returns the
    new runs. *users*: ``observe.read_users()`` ({} = unreadable: nothing is concluded)."""
    if not users:
        return []
    new: list[RootRun] = []
    seen: set[tuple[int, float]] = set()
    with _lock:
        for session in sessions:
            if session.kind != "session" or session.ended is not None or not session.pid or session.pid not in table:
                continue
            running_now = False
            for proc in [table[session.pid], *observe.descendants(table, session.pid)]:
                program = _program(proc.command)
                if not _is_root(users, proc.pid) or program in ASKERS:
                    continue
                running_now = True
                key = (proc.pid, proc.started)
                seen.add(key)
                if key not in _known and len(_known) < MAX_KNOWN:
                    run = RootRun(session.key, session.agent, proc.pid, program, proc.started, proc.pid == session.pid)
                    _known[key] = run
                    _record(run, session)
                    new.append(run)
            if session.root and not running_now:
                session.root = False
                store.put(session)
        for key in [key for key in _known if key not in seen]:
            _known.pop(key)
    return new


def note(instance: Instance, now: float | None = None) -> str:
    """What the live view says about root for *instance* ("" when there is nothing to say)."""
    return views.root_note(instance, now)
