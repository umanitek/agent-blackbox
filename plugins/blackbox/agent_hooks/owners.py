"""Which agent instance owns something: a recorded finding, or a running process (KI-588).

A companion app's Activity view lists File Shield's refusals and the processes on the network,
and needs to say WHICH instance of which agent each one belongs to — the core's answer, not a
process-tree walk of its own.

* :func:`finding_owners` — a resolver for ``audit.read_findings`` rows: a hook's row names its
  session key (``session_id``) and, inside the session, its hashed sub-agent id; an OS-sandbox
  refusal (recorded as ``agent-sandbox``: the kernel's log names a program, not a session) is
  given to the instance ``instances.kernel_refusals`` attributed it to, or to none (never guessed).
* :func:`of_pid` — the live instance whose agent process is *pid* or one of its ancestors (the
  same ancestry the tracker reads while a hook waits, ``observe.ancestry``: microseconds, no
  ``ps``). Bounded (at most ``observe.MAX_ANCESTORS`` parents) and cached for
  :data:`PID_CACHE_SECONDS`. A sub-agent is named only when it has its own process (a sub-agent
  that runs inside its session's process cannot be told apart by pid — honest "", never guessed).

Usage::

    owner_of = finding_owners()          # reads the attributions once
    owner_of(row)                        # Owner(agent, instance, sub_agent, folder, pid) or None
    of_pid(4242)                         # the same record for a process, or None
"""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Mapping, Optional

from ..audit import SANDBOX_RECORDER
from . import observe, tracking
from .instances import kernel_refusals, store
from .instances.model import Instance

#: How long one pid's answer is reused (a view asks for many pids every second).
PID_CACHE_SECONDS = 2.0
MAX_PIDS_CACHED = 1024
#: An agent process found under a pid must have started before its instance's first event; one
#: that started this much later is a new process that reused the pid.
PID_REUSE_SLACK_SECONDS = 60.0

_lock = threading.Lock()
_pid_cache: dict[int, tuple[float, Optional[Owner]]] = {}


@dataclass(frozen=True)
class Owner:
    """The agent instance something belongs to: *agent* (an agent id, ``claude-code``),
    *instance* (its session's key, ``claude-code:<16 hex>``), *sub_agent* (the sub-agent's key
    under it, "" when not known), *folder* (the project folder's name) and *pid* (the agent
    process, 0 when not known)."""

    agent: str
    instance: str
    sub_agent: str = ""
    folder: str = ""
    pid: int = 0


def _owner(item: Instance, sub_agent: str = "") -> Owner:
    if item.kind == "sub-agent" and item.parent:
        parent = store.get(item.parent)
        return Owner(item.agent, item.parent, item.key, (parent.folder if parent else item.folder), item.pid)
    return Owner(item.agent, item.key, sub_agent, item.folder, item.pid)


def finding_owners() -> Callable[[Mapping[str, Any]], Optional[Owner]]:
    """A resolver for findings rows (see the module doc). Attributes new sandbox refusals once,
    then answers from memory — call it once per listing, not once per row."""
    tracking.attribute_kernel_refusals()
    given = kernel_refusals.owners()

    def owner_of(row: Mapping[str, Any]) -> Optional[Owner]:
        if row.get("framework") == SANDBOX_RECORDER:
            key = given.get(kernel_refusals.refusal_id(row), "")
            found = store.get(key) if key else None
            return _owner(found) if found is not None else None
        session = str(row.get("session_id") or "")
        agent = str(row.get("framework") or "")
        if not session.startswith(f"{agent}:"):
            return None   # a Hermes row, or one written before hooks named their session
        sub = str(row.get("sub_agent") or "")
        sub_key = f"{session}/{sub}" if sub else ""
        found = store.get(session)
        if found is None:
            return Owner(agent, session, sub_key)
        return Owner(agent, session, sub_key, found.folder, found.pid)

    return owner_of


def _live_by_pid() -> dict[int, Instance]:
    """The live instances that have a process, by pid (a session wins over a sub-agent)."""
    found: dict[int, Instance] = {}
    for item in store.all_instances():
        if item.pid and item.ended is None and (item.pid not in found or item.kind == "session"):
            found[item.pid] = item
    return found


def _chain(pid: int) -> Mapping[int, observe.Proc]:
    chain = observe.ancestry(pid)
    return chain if chain is not None else tracking.process_table()


def _find(pid: int) -> Optional[Owner]:
    live = _live_by_pid()
    if not live:
        return None
    chain = _chain(pid)
    current = chain.get(pid)
    for _ in range(observe.MAX_ANCESTORS + 1):
        if current is None:
            return None
        item = live.get(current.pid)
        if item is not None and (not current.started or current.started <= item.started + PID_REUSE_SLACK_SECONDS):
            return _owner(item)
        current = chain.get(current.ppid)
    return None


def of_pid(pid: int) -> Optional[Owner]:
    """The live agent instance *pid* belongs to (itself or an ancestor is its agent process), or
    None. Cached per pid for :data:`PID_CACHE_SECONDS`, bounded to :data:`MAX_PIDS_CACHED`."""
    now = time.monotonic()
    with _lock:
        cached = _pid_cache.get(pid)
        if cached is not None and now - cached[0] < PID_CACHE_SECONDS:
            return cached[1]
    found = _find(pid)
    with _lock:
        if len(_pid_cache) >= MAX_PIDS_CACHED:
            for old in [key for key, (at, _) in _pid_cache.items() if now - at >= PID_CACHE_SECONDS] or list(_pid_cache)[:1]:
                _pid_cache.pop(old, None)
        _pid_cache[pid] = (now, found)
    return found


@dataclass(frozen=True)
class SandboxedRun:
    """A live agent instance running inside Blackbox's sandbox: its *agent*, *instance* key, agent
    process *pid* (0 when not known) and the *profile* its launcher chose (``<file>#<digest>``, as
    the agent's own hook reported it — untrusted: a reader checks the file is Blackbox's)."""

    agent: str
    instance: str
    pid: int
    profile: str


def sandboxed_runs() -> list[SandboxedRun]:
    """Every live session that reported the sandbox profile it started in."""
    return [SandboxedRun(item.agent, item.key, item.pid, item.sandbox_profile) for item in store.all_instances()
            if item.kind == "session" and item.ended is None and item.sandbox_profile]


def forget() -> None:
    """Drops the cached pid answers (tests)."""
    with _lock:
        _pid_cache.clear()


__all__ = ["Owner", "SandboxedRun", "finding_owners", "forget", "of_pid", "sandboxed_runs"]
