"""Which session a sub-agent belongs to when its agent reports it as a session of its own.

Some agents run a sub-agent as a CHILD SESSION with its own session id: OpenCode's ``task`` tool
creates a child session (``Session.parentID``), and a Codex ``spawn_agent`` thread can report under
its own id when no ``SubagentStart`` fires (seen in ``codex exec``, KI-557). Without a link each
shows as a separate session with no parent (KI-555). :func:`resolve` links a child session to its
parent, so its events are recorded as that parent's sub-agent — two ways, best first:

1. **Named** — the event names its parent session (``parent`` in the runner's identity: OpenCode's
   plugin sends the child session's ``parentID``). Exact.
2. **By process** — a NEW session whose first event is a tool call, in the SAME agent process as
   a live session with a spawn call not yet claimed (``task``, ``Task``, ``Agent``,
   ``spawn_agent``), is that call's sub-agent; parallel spawns are claimed oldest first. Used
   only when nothing names a parent and the agent's hooks do not say they always would
   (``parents_named``); the coverage matrix says which agents rely on it.

A spawn call's ``description`` (the short title the model gives a task — never its prompt) and
its sub-agent type are kept as :class:`Spawn` and given to the sub-agent that claims it, so the
sub-agent says what it was asked to do.

Bounded: at most :data:`MAX_PENDING` unclaimed spawns per session, kept :data:`SPAWN_SECONDS`;
at most :data:`MAX_LINKS` links (the oldest go first). In memory only — the records it shapes are
the instances themselves.

Usage::

    from .instances import links
    links.note_spawn(session_key, event)                    # every pre_tool
    parent, child = links.resolve(event, session_key, ...)  # before recording an event
"""

from __future__ import annotations

import threading
import time
from collections import OrderedDict, deque
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Mapping, Optional

from ...kernel.redaction import redact_secret_values
from .model import Instance

__all__ = ["SPAWN_TOOLS", "Link", "Spawn", "claim", "note_spawn", "reset", "resolve"]

#: The tools that start a sub-agent, lower-cased: Claude Code's ``Task`` / ``Agent``, OpenCode's
#: ``task``, Codex's ``spawn_agent``.
SPAWN_TOOLS = frozenset({"task", "agent", "spawn_agent"})
#: The events a child session can open with to be linked by process. WHY: one agent process
#: can host several sessions a person started (``codex app-server``, ``opencode serve``); those
#: open with their start event or a prompt, a spawned sub-agent with its first tool call.
FIRST_SUB_EVENTS = ("pre_tool", "post_tool")
MAX_PENDING = 32
SPAWN_SECONDS = 15 * 60.0
MAX_LINKS = 4096
MAX_TASK = 200


@dataclass(frozen=True)
class Spawn:
    """One spawn call not yet claimed by a sub-agent: when, its task's title, its type."""

    at: float
    task: str
    type: str


@dataclass(frozen=True)
class Link:
    """A child session recorded as a sub-agent: its parent session's key and the child's own
    session id (hashed by ``instances.sub_key`` like any sub-agent id)."""

    parent: str
    child: str


_lock = threading.Lock()
_pending: dict[str, deque[Spawn]] = {}
_links: OrderedDict[str, Link] = OrderedDict()


def reset() -> None:
    """Forget every link and pending spawn (tests; a new ``BLACKBOX_HOME``)."""
    with _lock:
        _pending.clear()
        _links.clear()


def _spawn_of(event: Mapping[str, Any]) -> Optional[Spawn]:
    if event.get("event") != "pre_tool" or str(event.get("tool_name") or "").lower() not in SPAWN_TOOLS:
        return None
    args = event.get("args") if isinstance(event.get("args"), dict) else {}
    task = redact_secret_values(str(args.get("description") or "").replace("\n", " "))[:MAX_TASK]
    kind = str(args.get("subagent_type") or args.get("agent_type") or "")[:80]
    return Spawn(time.time(), task, kind)


def note_spawn(session_key: str, event: Mapping[str, Any]) -> None:
    """Remember a spawn call *event* makes in *session_key* (anything else is ignored)."""
    found = _spawn_of(event)
    if found is None:
        return
    with _lock:
        queue = _pending.setdefault(session_key, deque(maxlen=MAX_PENDING))
        queue.append(found)
        for old in list(_pending)[:-MAX_LINKS]:
            _pending.pop(old)


def claim(session_key: str) -> Optional[Spawn]:
    """The oldest unexpired spawn of *session_key*, taken (None when there is none)."""
    with _lock:
        queue = _pending.get(session_key)
        while queue:
            spawn = queue.popleft()
            if time.time() - spawn.at < SPAWN_SECONDS:
                return spawn
        return None


def _has_pending(session_key: str) -> bool:
    with _lock:
        return any(time.time() - spawn.at < SPAWN_SECONDS for spawn in _pending.get(session_key, ()))


def _link(child_key: str, link: Link) -> Link:
    with _lock:
        _links[child_key] = link
        while len(_links) > MAX_LINKS:
            _links.popitem(last=False)
    return link


def resolve(event: Mapping[str, Any], session_key: str, *, key_of: Callable[[str], str], known: Optional[Instance],
            sessions: Iterable[Instance]) -> Optional[Link]:
    """The link that makes *session_key* (the event's own session) a sub-agent, or None.

    *key_of*: a raw session id → its session key (``events.session_key`` for this agent and
    folder). *known*: the instance *session_key* already has (a session recorded before it was
    linked stays a session). *sessions*: the instances now, for the by-process rule."""
    with _lock:
        found = _links.get(session_key)
    if found is not None:
        return found
    raw, parent_raw = str(event.get("session") or ""), str(event.get("parent") or "")
    if raw and parent_raw and parent_raw != raw:
        return _link(session_key, Link(key_of(parent_raw), raw))
    pid = event.get("agent_pid")
    if known is not None or not raw or not isinstance(pid, int) or pid <= 0 or event.get("parents_named"):
        return None
    if event.get("event") not in FIRST_SUB_EVENTS:
        return None   # a session a PERSON starts opens with its start event or a prompt
    parents = sorted((item for item in sessions if item.kind == "session" and item.ended is None and item.pid == pid
                      and item.agent == event.get("agent") and item.key != session_key and _has_pending(item.key)),
                     key=lambda item: item.started)
    return _link(session_key, Link(parents[0].key, raw)) if parents else None
