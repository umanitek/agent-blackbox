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
from typing import Any, Optional, Sequence

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


def record(events: Sequence[Any], mode: ShieldMode, now: Optional[float] = None,
           self_protected: Sequence[str] = ()) -> list[FileChange]:
    """Keeps the events inside the current items and folders; answers the ones kept. Refuses a
    report with a malformed event (nothing kept) or more than :data:`MAX_PER_REPORT` events.
    *self_protected*: the files the sandbox keeps closed for Blackbox (``sandbox.self_protected_files``)
    — a refusal naming one is recorded as a self-protection hit (KI-581), not kept as a change."""
    now = time.time() if now is None else now
    if len(events) > MAX_PER_REPORT:
        raise ShieldApiError(400, f"a file report carries at most {MAX_PER_REPORT} events")
    checked = [_checked(event, now) for event in events]
    with _cond:
        _load()
        kept: list[FileChange] = []
        self_denials = [(os.path.normpath(path), program) for path, kind, _ts, program in checked
                        if kind == DENIED and _inside_any(os.path.normpath(path), self_protected)]
        for path, kind, ts, program in checked:
            scope = _scope(path, mode)
            if scope is None or (kind == DENIED and scope[1] != PROTECTED):
                continue
            _state["seq"] += 1
            kept.append(FileChange(seq=_state["seq"], ts=ts, path=path, kind=kind, item=scope[0], scope=scope[1],
                                   program=program))
        if kept:
            _state["changes"] = (_state["changes"] + kept)[-MAX_KEPT:]
            _save()
            _cond.notify_all()
    _record_hits([change for change in kept if change.kind == DENIED])
    _record_self_hits(self_denials)
    return kept


def _inside_any(path: str, places: Sequence[str]) -> bool:
    """True when *path* is one of *places* or inside one of them (an add-on folder)."""
    return any(_under(path, place) for place in places)


def _record_self_hits(denials: list[tuple[str, str]]) -> None:
    """Each sandbox refusal of a write to a file kept closed for Blackbox, as a self-protection hit."""
    if not denials:
        return
    from ... import audit
    from .protect import SANDBOX_AGENT, sandbox_self_hit
    for path, program in denials:
        audit.record_for(SANDBOX_AGENT, event="sandbox_deny", findings=[sandbox_self_hit(path, program).to_dict()],
                         detail={"decision": "block", "tool_name": program, "tool_call_id": f"sandbox-self:{time.time():.6f}:{path}"})


def _record_hits(denials: list[FileChange]) -> None:
    """Each sandbox refusal as a File Shield hit, in the same local findings the hooks write."""
    if not denials:
        return
    from ... import audit
    from .protect import SANDBOX_AGENT, sandbox_hit
    for change in denials:   # one record each: the decision travels in the record's detail
        audit.record_for(SANDBOX_AGENT, event="sandbox_deny", findings=[sandbox_hit(change.item, change.path, change.program).to_dict()],
                         detail={"decision": "block", "tool_name": change.program, "tool_call_id": f"sandbox:{change.seq}"})


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
