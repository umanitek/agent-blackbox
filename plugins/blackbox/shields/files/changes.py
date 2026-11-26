"""File Shield's real-time file changes, as the system protection helper reports them.

The helper (``blackbox-netd``, root) watches every protected item and every watched folder with the
operating system's own file events (FSEvents on macOS — ``helper/src/platform/macos/observe/
file_watch.rs``) and posts each change within about a second, SIGNED (``shields.helper_link``) to
``POST /api/shields/file-shield/api/file-report``. This module checks each event, keeps the ones
inside an item or folder of the CURRENT setting (a report naming anything else is dropped), and
remembers the newest :data:`MAX_KEPT` (one small file, written atomically). Waiters — an
add-on's scan, which used to look every 2 s — are woken at once (:func:`wait_for`).

FSEvents says what changed, not which program changed it: ``program`` is "" and a person reads
"a program changed …". Nothing of a file is read: only its path and the kind of change.

``denied`` is the OS sandbox refusing a program (Layer 2, :mod:`.sandbox`): the helper reads the
kernel's sandbox messages for the protected paths, and here the log names the ``program``. A denial
inside a protected item is also recorded as a File Shield hit (``files:file-hit`` /
``files:folder-hit``, agent ``agent-sandbox``) — the same refusal list the hooks fill.

Usage::

    changes.record([{"path": "/Users/me/Downloads/x.dmg", "kind": "created", "ts": 1795}], mode)
    seq, new = changes.since(last_seq)
    changes.wait_for(last_seq, timeout=30)      # True when something new arrived
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Iterable, Optional, Sequence

from ...kernel import constants
from ...kernel.bounded_files import atomic_write, read_small_text
from ..contract import ShieldMode
from ..json_records import JsonValue, _record_json
from ..shield_api import ShieldApiError
from . import mode as mode_module

KINDS = ("created", "modified", "removed", "renamed", "changed", "denied")
DENIED = "denied"
MAX_PROGRAM_CHARS = 64
MAX_KEPT = 500
MAX_PER_REPORT = 200
MAX_PATH_CHARS = 1024
_MAX_FILE_BYTES = 512 * 1024

PROTECTED, WATCHED = "protected", "watched"


@dataclass(frozen=True)
class FileChange:
    """One change: *path* (absolute), *kind* (one of :data:`KINDS`), the *item* it falls under —
    a protected item as the person wrote it, or a watched folder — and its *scope*
    (``protected`` / ``watched``). *seq* orders changes; *program* is "" (FSEvents cannot say)."""

    seq: int
    ts: float
    path: str
    kind: str
    item: str
    scope: str
    program: str = ""

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)


_cond = threading.Condition()
_state: dict[str, Any] = {"loaded": False, "seq": 0, "changes": []}


def _path() -> Any:
    return constants.blackbox_home() / "file-shield" / "changes.json"


def _load() -> None:
    if _state["loaded"]:
        return
    _state["loaded"] = True
    text = read_small_text(str(_path()), _MAX_FILE_BYTES, nofollow=True)
    try:
        saved = json.loads(text) if text else {}
        rows = [FileChange(**row) for row in saved.get("changes", [])][-MAX_KEPT:]
    except (ValueError, TypeError):   # a damaged file: start over, never refuse to run
        rows = []
    _state["changes"] = rows
    _state["seq"] = max((row.seq for row in rows), default=0)


def _save() -> None:
    body = {"changes": [row.as_json() for row in _state["changes"]]}
    atomic_write(_path(), json.dumps(body, separators=(",", ":")), mode=0o600)


def _under(path: str, place: str) -> bool:
    return path == place or path.startswith(place.rstrip("/") + "/")


def _scope(path: str, mode: ShieldMode) -> Optional[tuple[str, str]]:
    """``(item, scope)`` the changed *path* falls under in *mode*, or None (not ours: dropped)."""
    real = os.path.normpath(path)
    for item in mode_module.protected(mode):
        if _under(real, os.path.realpath(os.path.expanduser(item))):
            return item, PROTECTED
    for folder, written in zip(mode_module.resolved(mode), mode_module.folders(mode)):
        if _under(real, str(folder)):
            return written, WATCHED
    return None


def _checked(event: Any, now: float) -> tuple[str, str, float, str]:
    if not isinstance(event, dict):
        raise ShieldApiError(400, "each file event is an object")
    path, kind = event.get("path"), event.get("kind")
    if not isinstance(path, str) or not path.startswith("/") or len(path) > MAX_PATH_CHARS or "\x00" in path:
        raise ShieldApiError(400, "each file event names an absolute path")
    if kind not in KINDS:
        raise ShieldApiError(400, f"each file event has a kind: {', '.join(KINDS)}")
    ts = event.get("ts", int(now))
    if type(ts) is not int or not 0 <= ts <= 4_102_444_800:
        raise ShieldApiError(400, "ts must be a whole number of seconds")
    program = event.get("program", "")
    if not isinstance(program, str) or len(program) > MAX_PROGRAM_CHARS or "\x00" in program:
        raise ShieldApiError(400, f"program must be a name of at most {MAX_PROGRAM_CHARS} characters")
    return path, kind, float(min(ts, now)), program if kind == DENIED else ""


#: The largest pid a refusal may name.
_MAX_PID = 2 ** 31 - 1


def _pid_of(event: Any) -> int:
    """The refused process's pid the helper read from the kernel's log (0: not named)."""
    pid = event.get("pid") if isinstance(event, dict) else None
    return pid if type(pid) is int and 0 < pid <= _MAX_PID else 0


def record(events: Sequence[Any], mode: ShieldMode, now: Optional[float] = None,
           self_protected: Sequence[str] = (), owner_of_pid: Optional[Callable[[int], Any]] = None,
           sandboxed_agents: Optional[Callable[[], Iterable[str]]] = None) -> list[FileChange]:
    """Keeps the events inside the current items and folders; answers the ones kept. Refuses a
    report with a malformed event (nothing kept) or more than :data:`MAX_PER_REPORT` events.
    *self_protected*: the files the sandbox keeps closed for Blackbox (``sandbox.self_protected_files``)
    — a refusal naming one is recorded as a self-protection hit (KI-581), not kept as a change.
    *owner_of_pid*: the agent tracker's ``pid -> InstanceRef | None``; a refusal whose pid it knows
    NOW (the refused process, or its agent, may still run) is recorded on that instance (KI-598).
    *sandboxed_agents*: the agents running inside the sandbox now (``ShieldContext.sandboxed_runs``):
    a self-protection refusal whose process is already gone names the agent when only ONE agent runs
    there (KI-697) — the agent, never an instance (that stays unattributed, KI-598)."""
    now = time.time() if now is None else now
    if len(events) > MAX_PER_REPORT:
        raise ShieldApiError(400, f"a file report carries at most {MAX_PER_REPORT} events")
    checked = [_checked(event, now) for event in events]
    owners = {index: _owner(owner_of_pid, _pid_of(event)) for index, event in enumerate(events)
              if checked[index][1] == DENIED and _pid_of(event)}
    with _cond:
        _load()
        kept: list[FileChange] = []
        self_denials = [(os.path.normpath(path), program, owners.get(index)) for index, (path, kind, _ts, program) in enumerate(checked)
                        if kind == DENIED and _inside_any(os.path.normpath(path), self_protected)]
        hit_owners: dict[int, Any] = {}
        for index, (path, kind, ts, program) in enumerate(checked):
            scope = _scope(path, mode)
            if scope is None or (kind == DENIED and scope[1] != PROTECTED):
                continue
            _state["seq"] += 1
            kept.append(FileChange(seq=_state["seq"], ts=ts, path=path, kind=kind, item=scope[0], scope=scope[1],
                                   program=program))
            hit_owners[_state["seq"]] = owners.get(index)
        if kept:
            _state["changes"] = (_state["changes"] + kept)[-MAX_KEPT:]
            _save()
            _cond.notify_all()
    _record_hits([change for change in kept if change.kind == DENIED], hit_owners)
    _record_self_hits(self_denials, _only_agent(sandboxed_agents) if any(owner is None for *_rest, owner in self_denials) else "")
    return kept


def _only_agent(sandboxed_agents: Optional[Callable[[], Iterable[str]]]) -> str:
    """The one agent running inside the sandbox now, "" when none or several (or not known)."""
    if sandboxed_agents is None:
        return ""
    try:
        agents = {str(agent) for agent in sandboxed_agents() if agent}
    except Exception:   # health: allow BLE001 -- a refusal is still recorded; it then names no agent
        return ""
    return agents.pop() if len(agents) == 1 else ""


def _owner(owner_of_pid: Optional[Callable[[int], Any]], pid: int) -> Any:
    """The instance *pid* belongs to by its ancestry now, None when not known (never guessed)."""
    if owner_of_pid is None or not pid:
        return None
    try:
        return owner_of_pid(pid)
    except Exception:   # health: allow BLE001 -- a refusal is still recorded; it then names no instance
        return None


def _owned(owner: Any) -> dict[str, str]:
    """The record's ``session_id`` / ``agent`` for a known owner (``kernel_refusals`` gives it there)."""
    return {"session_id": owner.instance, "agent": owner.agent} if owner is not None else {}


def _inside_any(path: str, places: Sequence[str]) -> bool:
    """True when *path* is one of *places* or inside one of them (an add-on folder)."""
    return any(_under(path, place) for place in places)


def _record_self_hits(denials: list[tuple[str, str, Any]], only_agent: str = "") -> None:
    """Each sandbox refusal of a write to a file kept closed for Blackbox, as a self-protection hit
    (named for its owner's agent, else *only_agent*: the one agent inside the sandbox then)."""
    if not denials:
        return
    from ... import audit
    from .protect import SANDBOX_AGENT, sandbox_self_hit
    for path, program, owner in denials:
        named = _owned(owner) or ({"agent": only_agent} if only_agent else {})
        audit.record_for(SANDBOX_AGENT, event="sandbox_deny", findings=[sandbox_self_hit(path, program).to_dict()],
                         detail={"decision": "block", "tool_name": program, "tool_call_id": f"sandbox-self:{time.time():.6f}:{path}",
                                 **named})


#: The refusal kinds an agent's hook reads from a tool's output (``agent_hooks``' sandbox words): a
#: file the kernel would not open or write, a shell startup file, a place something starts from.
SEEN_FILE, SEEN_STARTUP_FILE, SEEN_PERSISTENCE = "file", "startup", "persistence"


def _pinned_above(folder: str, place: str) -> bool:
    """True when *folder* is a folder above *place* the sandbox pins (moving it would move the file),
    below the person's home: the home and everything above it are never Blackbox's alone."""
    homes = {os.path.expanduser("~").rstrip("/"), os.path.realpath(os.path.expanduser("~")).rstrip("/")}
    return folder != place and _under(place, folder) and any(_under(folder, home) and folder != home for home in homes)


def record_seen_refusal(kind: str, path: str, agent: str, instance: str, self_protected: Sequence[str]) -> bool:
    """Record one sandbox refusal an agent's hook read from a tool's output as tamper, when it was
    one: a write to a place something starts from (``startup-item``), or to a file kept closed for
    Blackbox (*self_protected*) or a folder above one (``self-protection-kernel``). True when recorded.

    WHY (KI-693): only the macOS helper reads the kernel's own denial log (:func:`record`); on Linux
    the tool's output is the only sign of a refusal, so without this every refusal the sandbox made
    — the layer that stops what the hook could not judge — went uncounted. The caller calls it only
    where the helper does not report refusals (``sandbox.HELPER_REPORTS_REFUSALS``): never twice."""
    path = os.path.normpath(path) if path.startswith("/") else ""
    if not path:
        return False
    from ... import audit
    from .protect import SANDBOX_AGENT, sandbox_self_hit, sandbox_startup_hit
    if kind == SEEN_PERSISTENCE:
        finding = sandbox_startup_hit(path, agent)
    elif kind in (SEEN_FILE, SEEN_STARTUP_FILE) and any(_under(path, place) or _pinned_above(path, place) for place in self_protected):
        finding = sandbox_self_hit(path, agent)
    else:
        return False
    # The hook that read it knows the agent (KI-697): recorded under it, as its other refusals are.
    recorder = agent if agent and agent.replace("-", "").isalnum() else SANDBOX_AGENT
    audit.record_for(recorder, event="sandbox_deny", findings=[finding.to_dict()],
                     detail={"decision": "block", "tool_name": agent[:MAX_PROGRAM_CHARS] or "program",
                             "tool_call_id": f"sandbox-seen:{time.time():.6f}:{path}", "session_id": instance, "agent": agent})
    return True


def _record_hits(denials: list[FileChange], owners: Optional[dict[int, Any]] = None) -> None:
    """Each sandbox refusal as a File Shield hit, in the same local findings the hooks write."""
    if not denials:
        return
    from ... import audit
    from .protect import SANDBOX_AGENT, sandbox_hit
    for change in denials:   # one record each: the decision travels in the record's detail
        audit.record_for(SANDBOX_AGENT, event="sandbox_deny", findings=[sandbox_hit(change.item, change.path, change.program).to_dict()],
                         detail={"decision": "block", "tool_name": change.program, "tool_call_id": f"sandbox:{change.seq}",
                                 **_owned((owners or {}).get(change.seq))})


def since(seq: int) -> tuple[int, list[FileChange]]:
    """``(newest seq, the changes after *seq*)``, oldest first."""
    with _cond:
        _load()
        return _state["seq"], [row for row in _state["changes"] if row.seq > seq]


def wait_for(seq: int, timeout: float) -> bool:
    """Waits up to *timeout* seconds for a change after *seq*; True when one arrived."""
    with _cond:
        _load()
        return _cond.wait_for(lambda: _state["seq"] > seq, timeout=max(0.0, timeout))


def recent(limit: int = 100) -> list[FileChange]:
    """The newest *limit* changes, newest first."""
    with _cond:
        _load()
        return list(reversed(_state["changes"][-limit:]))


def reset() -> None:
    """Forgets what is in memory (tests; a new Blackbox home)."""
    with _cond:
        _state.update(loaded=False, seq=0, changes=[])
