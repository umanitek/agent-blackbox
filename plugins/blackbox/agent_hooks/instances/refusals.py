"""ONE count of what an instance was refused — each refusal once, whichever way it was seen (KI-637).

A refusal reaches an instance three ways:

* :data:`HOOK` — Blackbox's hook refused the call before it ran (a ``pre_tool`` answered ``block``);
* :data:`OUTPUT` — the OS sandbox refused something while the call ran, read from the call's output
  (``protect.sandbox_errors``: ``PermissionError … '<path>'``, ``Bootstrap failed: 5``, a setuid
  program), one per thing refused;
* :data:`KERNEL` — File Shield read the refusal from the kernel's log (``kernel_refusals``).

The last two are often the SAME refusal seen twice: the code tool printed ``PermissionError`` for
the file the kernel logged. Security round 6 (bb-sec-r6) counted it twice for the Hermes agent
(refused 2 for one read), not at all when only one of them came (Codex's sandboxed ``p.py``: no
kernel row, refused 0; Claude Code's refused ``os.rename(~/.hermes)``: no kernel row, refused 2 of
3), and once per hook form when an agent reported one call twice (Cline). So every path counts
through :func:`count`, which is idempotent on its key — ``(instance, call id + what)`` for a call,
``(instance, kernel record id)`` for a log line — and pairs a log line with the output refusal of
the same place made while that call ran (:data:`SLACK_SECONDS` either side). The same thing
reported twice for one call — the same id, or no id and no new call started in between — is one.

Memory only, bounded: the instance store is the dashboard process's Repository, and every caller
(the hook recorder, the Hermes reader, the kernel-log attribution) runs in that process.

Usage::

    call_started(instance, "toolu_1", ts)                         # each pre_tool
    count(instance, OUTPUT, "/Users/me/.hermes/.env", ts=now, call_id="toolu_1")   # COUNTED
    count(instance, KERNEL, "/Users/me/.hermes/.env", ts=now - 0.5, record="sandbox:23")  # SAME: one refusal
"""

from __future__ import annotations

import itertools
import os
import threading
from collections import OrderedDict, deque
from dataclasses import dataclass, field

from .model import Instance

HOOK, OUTPUT, KERNEL = "hook", "output", "kernel"
#: What :func:`count` did: counted it now; it was the other view of one counted already (a kernel
#: log line and the output of the same run); it was reported again (the same call, a second time).
COUNTED, SAME, REPEAT = "counted", "same", "repeat"
#: How far outside a call's run a kernel log line of the same place is still that call's refusal
#: (the log's own time is whole seconds, and the hook's record of the call lands a moment late).
SLACK_SECONDS = 3.0
#: How long a call that started unseen (no ``pre_tool``) is taken to have run before its output.
UNSEEN_START_SECONDS = 60.0
MAX_INSTANCES = 512
MAX_SEEN = 64
MAX_CALLS = 64

_lock = threading.Lock()
_unique = itertools.count()


@dataclass
class _Seen:
    key: str
    source: str
    what: str
    start: float
    end: float
    call_seq: int
    paired: bool = False


@dataclass
class _Memory:
    started: float                                            # the instance it is of (a new one with the same key starts afresh)
    seen: deque = field(default_factory=lambda: deque(maxlen=MAX_SEEN))
    calls: OrderedDict = field(default_factory=OrderedDict)   # call id -> when it started
    call_seq: int = 0                                         # pre_tools seen so far


_memory: OrderedDict[str, _Memory] = OrderedDict()


def _of(instance: Instance) -> _Memory:
    found = _memory.get(instance.key)
    if found is None or found.started != instance.started:
        found = _memory[instance.key] = _Memory(instance.started)
    _memory.move_to_end(instance.key)
    while len(_memory) > MAX_INSTANCES:
        _memory.popitem(last=False)
    return found


def reset() -> None:
    """Tests: forget every refusal and call seen."""
    with _lock:
        _memory.clear()


def call_started(instance: Instance, call_id: str, ts: float) -> None:
    """A ``pre_tool`` of *instance*: a new call has begun (its output belongs to it)."""
    with _lock:
        memory = _of(instance)
        memory.call_seq += 1
        if call_id:
            memory.calls[call_id] = ts
            while len(memory.calls) > MAX_CALLS:
                memory.calls.popitem(last=False)


def _same_place(one: str, other: str) -> bool:
    """True when two refused things are one place (a file, or the folder holding it); only paths match."""
    if not (one.startswith("/") and other.startswith("/")):
        return False
    one, other = os.path.realpath(one), os.path.realpath(other)
    return one == other or one.startswith(other.rstrip("/") + "/") or other.startswith(one.rstrip("/") + "/")


def _pair(memory: _Memory, new: _Seen) -> bool:
    """Pair *new* with the unpaired refusal of the same place seen the OTHER way during the same run."""
    wanted = OUTPUT if new.source == KERNEL else KERNEL
    for old in memory.seen:
        if old.source != wanted or old.paired or not _same_place(old.what, new.what):
            continue
        output, kernel = (old, new) if wanted == OUTPUT else (new, old)
        if output.start - SLACK_SECONDS <= kernel.start <= output.end + SLACK_SECONDS:
            old.paired = True
            return True
    return False


def _repeat(memory: _Memory, new: _Seen) -> bool:
    """True when *new* was counted already: the same key, or the same output refusal reported again
    before any new call started (one call through two hook forms, KI-551)."""
    return any(old.key == new.key or (new.source == OUTPUT and old.source == OUTPUT and old.what == new.what
                                      and old.call_seq == new.call_seq) for old in memory.seen)


def count(instance: Instance, source: str, what: str, *, ts: float, call_id: str = "", record: str = "") -> str:
    """Count one refusal of *what* (a path, or ``<kind>:<name>``) on *instance* unless it was counted
    already: :data:`COUNTED` (``instance.refused`` went up by one), :data:`SAME` or :data:`REPEAT`.

    *source*: :data:`HOOK`, :data:`OUTPUT` or :data:`KERNEL`. *ts*: when it happened (an output
    refusal: when the call's output came). *call_id*: the agent's id for the call ("" when it sends
    none). *record*: a kernel log line's record id."""
    with _lock:
        memory = _of(instance)
        if source == KERNEL:
            key = f"kernel:{record}"
        elif call_id:
            key = f"{source}:{call_id}:{what}"
        else:   # no id: the event is its own (only an output repeat before a new call is the same)
            key = f"{source}:#{next(_unique)}:{what}"
        start = memory.calls.get(call_id, ts - UNSEEN_START_SECONDS) if source == OUTPUT else ts
        new = _Seen(key, source, what, min(start, ts), ts, memory.call_seq)
        if _repeat(memory, new):
            return REPEAT
        new.paired = source != HOOK and _pair(memory, new)
        memory.seen.append(new)
        if new.paired:
            return SAME
        instance.refused += 1
        return COUNTED


__all__ = ["COUNTED", "HOOK", "KERNEL", "OUTPUT", "REPEAT", "SAME", "SLACK_SECONDS", "call_started", "count", "reset"]
