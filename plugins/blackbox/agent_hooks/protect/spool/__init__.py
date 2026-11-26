"""The hook spool: events a coding agent's hook could not hand to the dashboard, recorded once the
dashboard is back — so a refusal is never lost because the dashboard was down.

Linux round L8 (BB-LINUX-PENDING-e6e905, Medium): with the dashboard stopped, a SANDBOXED agent's
refusal left no audit row, finding or session (a hooks-only agent's left two). Inside the sandbox
Blackbox's data folder is read-only, and below Linux 6.12 the kernel kills every process of the
sandbox's PID namespace when the agent ends, so the runner's detached recorder could neither write
nor outlive it. The runner (``judge_here.keep``) now writes such an event, before it ends, into
:func:`folder` (one 0600 file per event, written whole) — and a refusal also into the system
journal (Linux), whose lines the agent can neither change nor delete. :func:`replay`, run by the
dashboard's observer look every few seconds, records them.

Security, said plainly: the spool folder is one the sandbox leaves writable, so the agent can
write, change or delete files in it. Therefore:

* nothing in a spooled file is trusted: each event is judged again here by the same checks
  (``events.judge``) and only the decision the agent was TOLD is kept from the file — a refusal
  stays a refusal ("allowed then, refused now" is recorded as too late: the action ran). A forged
  file can at most make Blackbox record a judgement of a call the agent could have made anyway;
  nothing of it leaves the machine (agent-hook findings are never shared);
* a refusal's journal mark whose file is gone before the replay read it is itself recorded, as a
  HIGH finding (:data:`REMOVED_ID`) — deleting the evidence is visible;
* the folder is opened once without following links and every file relative to it (by path, after
  the same checks, where the system has no such opening — Windows), only names
  the runner writes (:data:`_NAME`) are read or deleted, only regular files the person owns, at
  most ``judge_here.MAX_SPOOLED_BYTES`` each, at most ``judge_here.MAX_SPOOLED`` of them.

Where there is no system journal (macOS, Windows) ``observe.platform.journal_marks`` says so
(None): the spool files alone are the record there.

Usage (the observer's look)::

    spool.replay()   # how many spooled events were recorded
"""

from __future__ import annotations

import json
import logging
import os
import re
import stat
import threading
from dataclasses import replace
from pathlib import Path
from typing import Any, Optional

from ....kernel import constants
from ....kernel.agent_hosts import BY_ID, DECISION_TOO_LATE
from ....kernel.bounded_files import read_json_object, write_json_object
from ..judge_here import JOURNAL_TAG, MAX_SPOOLED, MAX_SPOOLED_BYTES, NOT_CHECKED_IN_TIME, UNSPOOLED

logger = logging.getLogger(__name__)

#: A spool file's name as the runner writes it: ``<ns time>-<pid>-<8 hex>.json``.
_NAME = re.compile(r"^\d{1,20}-\d{1,10}-[0-9a-f]{8}\.json$")
#: The finding for a refusal whose spooled record was removed before the dashboard read it.
REMOVED_ID = "agent:hook-record-removed"
#: The audit event of that finding.
REMOVED_EVENT = "hook_record_removed"
#: How many replayed names are remembered (a journal mark may be read after its file was replayed).
MAX_REMEMBERED = 4 * MAX_SPOOLED
#: What a refusal made while the dashboard was away says when its own message is not known.
AWAY_MESSAGE = "Blackbox refused this action while its dashboard was not running."
_lock = threading.Lock()


def folder() -> Path:
    """Where hooks spool events: in the person's cache folder, which Blackbox's sandbox leaves
    writable (Blackbox's own data folder is read-only inside it)."""
    return Path.home() / ".cache" / "blackbox" / "hook-spool"


def _state_path() -> Path:
    return constants.blackbox_home() / "agent-hooks" / "hook-spool.json"


def _cursor_path() -> Path:
    return constants.blackbox_home() / "agent-hooks" / "hook-journal.cursor"


#: The person this runs as (Windows has no uid; every file's ``st_uid`` is 0 there).
_ME = getattr(os, "getuid", lambda: 0)()
#: Where the folder can be held open and its files reached through it (POSIX); elsewhere by path.
_PINNED = hasattr(os, "O_DIRECTORY") and os.open in os.supports_dir_fd
Folder = int | str


def _open_folder() -> Optional[Folder]:
    """The spool folder, opened without following a link — held open where the system can (so it
    can not be swapped while it is read), else its path once it proved a plain folder of the
    person's; None when it is missing or not such a folder."""
    path = str(folder())
    try:
        if not _PINNED:
            info = os.lstat(path)
            return path if stat.S_ISDIR(info.st_mode) and info.st_uid == _ME else None
        handle = os.open(path, os.O_RDONLY | os.O_DIRECTORY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    if os.fstat(handle).st_uid != _ME:
        os.close(handle)
        return None
    return handle


def _take(where: Folder, name: str) -> Optional[dict[str, Any]]:
    """The event in spool file *name* (None when it is not one the runner wrote), deleted first —
    so a file that breaks the replay is never replayed twice."""
    path, dir_fd = (name, where) if isinstance(where, int) else (os.path.join(where, name), None)
    try:
        file = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0), dir_fd=dir_fd)
    except OSError:
        return None
    try:
        info = os.fstat(file)
        raw = os.read(file, MAX_SPOOLED_BYTES + 1) if stat.S_ISREG(info.st_mode) and info.st_uid == _ME else b""
    finally:
        os.close(file)
    try:
        os.unlink(path, dir_fd=dir_fd)
    except OSError:
        return None   # not ours to delete: not ours to record
    try:
        entry = json.loads(raw.decode("utf-8")) if 0 < len(raw) <= MAX_SPOOLED_BYTES else None
    except ValueError:
        return None
    return entry if isinstance(entry, dict) and isinstance(entry.get("body"), dict) else None


def _record(entry: dict[str, Any]) -> bool:
    """Judge a spooled event again and record it with the decision the agent was told."""
    from .. import events   # late: events imports the guard
    try:
        _answer, judged = events.judge(entry["body"])
    except ValueError:
        return False   # not an event: nothing to record
    if judged is None:
        return False
    if entry.get("late") is True or entry.get("decided") == "block":   # the agent was refused
        message = NOT_CHECKED_IN_TIME if entry.get("late") is True else str(judged.verdict.get("message") or AWAY_MESSAGE)
        judged = replace(judged, verdict={**judged.verdict, "decision": "block", "message": message}, blocked=True, decision="block")
    elif judged.blocked:   # allowed then (the judgement did not refuse it), refused now: the action ran
        judged = replace(judged, decision=DECISION_TOO_LATE)
    events.bookkeep(judged)
    return True


def _removed_finding(mark: dict[str, str]) -> dict[str, Any]:
    agent = mark.get("BLACKBOX_AGENT", "")
    if mark.get("BLACKBOX_SPOOL_ID") == UNSPOOLED:   # the hook could not write its file (spool full, disk full)
        title, advice = "A refused action was recorded from the system journal only", (
            "While Blackbox's dashboard was not running, an agent was refused an action and its hook could not keep the "
            "details; the system journal kept that it happened.")
    else:
        title, advice = "A record of a refused action was removed before Blackbox read it", (
            "While Blackbox's dashboard was not running, an agent was refused an action; the note the hook left for "
            "the dashboard was deleted before it was read. Something on this computer removed it: look at what that "
            "agent did around this time.")
    return {"identifier": REMOVED_ID, "category": "escalation", "severity": "high", "source": "custom", "kind": "flag-only",
            "title": title, "matched": "hook-record-removed", "advice": advice,
            "tool_name": mark.get("BLACKBOX_TOOL", "")[:120], "confirmed": False,
            "evidence": f"{agent} {mark.get('BLACKBOX_EVENT', '')} {mark.get('BLACKBOX_TOOL', '')}".strip()[:300],
            "fields": {"agent": agent[:80], "session": mark.get("BLACKBOX_SESSION", "")[:200]}}


def _record_removed(mark: dict[str, str]) -> None:
    agent = mark.get("BLACKBOX_AGENT", "")
    audit_id = agent if agent in BY_ID else "agent-sandbox"
    from .... import audit   # late: only the observer's look asks
    audit.record_for(audit_id, event=REMOVED_EVENT, findings=[_removed_finding(mark)],
                     detail={"decision": "flag", "spool_id": mark.get("BLACKBOX_SPOOL_ID", "")[:80]})


def _journal() -> list[dict[str, str]]:
    """The refusals' journal marks written since the last look ([] where there is no journal). The
    first look only sets the place: marks older than this install's first look are history (an
    upgrade must not report every earlier refusal as a removed record)."""
    from ...observe import platform   # late: the observer's OS seam
    first = not _cursor_path().exists()
    _cursor_path().parent.mkdir(parents=True, exist_ok=True)
    marks = platform.journal_marks(JOURNAL_TAG, str(_cursor_path())) or []
    return [] if first else marks


def replay() -> int:
    """Record every spooled event and report every refusal whose spooled record was removed; how
    many events were recorded. Fail-open: 0 on any error. Nothing without a Blackbox home."""
    if not constants.blackbox_home().is_dir():
        return 0
    try:
        with _lock:
            return _replay()
    except Exception:   # health: allow BLE001 -- fail open: the observer's look goes on without the spool
        logger.warning("blackbox: the hook spool could not be replayed", exc_info=True)
        return 0


def _replay() -> int:
    marks = _journal()   # read FIRST: the runner writes a file before its mark, so a mark's file is listed below
    state = read_json_object(_state_path()) or {}
    remembered = [name for name in state.get("replayed", []) if isinstance(name, str)][-MAX_REMEMBERED:]
    where = _open_folder()
    recorded, names = 0, []
    if where is not None:
        try:
            names = sorted(name for name in os.listdir(where) if _NAME.match(name))[:MAX_SPOOLED]
            for name in names:
                entry = _take(where, name)
                recorded += bool(entry and _record(entry))
        finally:
            if isinstance(where, int):
                os.close(where)
    done = set(remembered) | {name.removesuffix(".json") for name in names}
    for mark in marks:
        if mark.get("BLACKBOX_SPOOL_ID") not in done:
            _record_removed(mark)
    if names:
        write_json_object(_state_path(), {"replayed": (remembered + [name.removesuffix(".json") for name in names])[-MAX_REMEMBERED:]},
                          what="the hook spool's replayed names")
    return recorded


__all__ = ["AWAY_MESSAGE", "REMOVED_EVENT", "REMOVED_ID", "folder", "replay"]
