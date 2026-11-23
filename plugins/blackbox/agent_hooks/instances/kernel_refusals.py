"""A refusal the OS sandbox made, shown on the agent instance whose program it stopped (KI-568).

File Shield records each sandbox refusal the system protection helper reads from the kernel's log
(``audit`` finding rows of the sandbox recorder, ``event == "sandbox_deny"``): the path, the
program's name and when — never which agent, because the log names a program, not a session.
Real run (test VM, 2026-11-22): Claude Code started through the launcher wrote a script and ran
it; the kernel refused the read, but the instance said ``python3 r.py allow``, refused 0.

This module gives each such refusal to the instance it belongs to: a SANDBOXED instance that was
live when it happened: the one the refused process's ancestry named when the refusal was recorded
(the helper reads its pid from the log), else — the process already gone — the one sandboxed
instance live then; several, or none, leaves it on File Shield's own list only, unattributed
(honest: never guessed, KI-598). The instance counts it as refused and
its timeline gets a ``block`` row whose reason says the kernel stopped it. Each refusal is given
once (its record id is remembered, bounded, with the instance it was given to).

Usage::

    attribute(audit.read_findings(limit=200))   # how many refusals were given to an instance
    owners()                                    # {refusal id: instance key} — who each one was given to
    refusal_id(row)                             # the id a findings row is remembered by
"""

from __future__ import annotations

import os
import threading
import time
from typing import Any, Iterable, Mapping, Optional

from ...audit import SANDBOX_RECORDER
from ...kernel.bounded_files import read_json_object, write_json_object
from . import store
from .model import Action, Instance

#: How long after its last event an instance still counts as live for a refusal (a tool call that
#: runs a long program sends nothing while the program runs).
LIVE_GRACE_SECONDS = 15 * 60
#: The most refusal ids remembered as already given.
MAX_REMEMBERED = 2000
_lock = threading.Lock()


def _given_path():
    return store.folder() / "kernel-refusals.json"


def _read() -> tuple[list[str], dict[str, str]]:
    """The refusal ids already given, oldest first, and the instance each went to (KI-586, KI-588:
    a refusal's notice and File Shield's hit name that instance, not "agent-sandbox")."""
    data = read_json_object(_given_path()) or {}
    ids = data.get("ids")
    owners = data.get("owners")
    given = [str(each) for each in ids] if isinstance(ids, list) else []
    return given, ({str(k): str(v) for k, v in owners.items()} if isinstance(owners, dict) else {})


def owners() -> dict[str, str]:
    """``{refusal id: instance key}`` for every refusal given to an instance (bounded)."""
    return _read()[1]


def refusal_id(row: Mapping[str, Any]) -> str:
    """The id a sandbox refusal's findings row is remembered by (see :func:`owners`)."""
    return _key(row)


def _key(row: Mapping[str, Any]) -> str:
    return str(row.get("tool_call_id") or f"{row.get('ts')}:{(row.get('fields') or {}).get('path', '')}")


def _candidates(ts: float) -> list[Instance]:
    return [item for item in store.all_instances()
            if (item.sandboxed or item.shells_sandboxed) and item.started <= ts + 1 and item.last >= ts - LIVE_GRACE_SECONDS
            and (item.ended is None or item.ended >= ts - 2)]


def _owner(row: Mapping[str, Any], ts: float) -> Optional[Instance]:
    """The instance a refusal belongs to: the one its process's ANCESTRY named when it was recorded
    (``session_id``, KI-598); else, when the process was already gone, the one sandboxed instance live
    then. Two or more live, or none: None — recorded as unattributed, never guessed (KI-598: a
    refusal landed on the NEXT Codex session, and on a Cline session that was not the refuser's)."""
    named = str(row.get("session_id") or "")
    if named:
        return store.get(named)
    found = _candidates(ts)
    return found[0] if len(found) == 1 else None


def _reason(fields: Mapping[str, Any], path: str, program: str) -> str:
    """What the timeline says the kernel stopped: a protected item's read, or — the sandbox's
    self-protection (KI-581) — a write to a file that keeps Blackbox's hook."""
    if fields.get("route") == "self":
        return f"The operating system's sandbox stopped {program} changing {path}, which keeps Blackbox's hook (self-protection)."
    return (f"The operating system's sandbox stopped {program} reaching {os.path.basename(path) or path} "
            f"in your protected {fields.get('kind') or 'item'} {fields.get('item') or ''} (File Shield).").replace("  ", " ")


def attribute(rows: Iterable[Mapping[str, Any]]) -> int:
    """Give each sandbox refusal in *rows* (``audit.read_findings`` rows) to its instance; answers
    how many were given now. Fail-open: a row that does not fit is left alone."""
    with _lock:
        given, owner_of = _read()
        known = set(given)
        added = 0
        for row in sorted(rows, key=lambda each: float(each.get("ts") or 0)):
            if row.get("framework") != SANDBOX_RECORDER or row.get("event") != "sandbox_deny" or _key(row) in known:
                continue
            ts = float(row.get("ts") or 0)
            owner = _owner(row, ts)
            if owner is None:
                continue
            fields = row.get("fields") or {}
            path, program = str(fields.get("path") or ""), str(fields.get("program") or row.get("tool_name") or "a program")
            reason = _reason(fields, path, program)
            owner.refused += 1
            owner.events += 1
            action = Action(ts, "pre_tool", program[:120], path[:300], "block", reason[:300])
            owner.last_action = action
            store.append_action(owner.key, action, owner.events)
            store.put(owner)
            known.add(_key(row))
            given.append(_key(row))
            owner_of[_key(row)] = owner.key
            added += 1
        if added:
            _given_path().parent.mkdir(parents=True, exist_ok=True)
            kept = given[-MAX_REMEMBERED:]
            write_json_object(_given_path(), {"ids": kept, "owners": {each: owner_of[each] for each in kept if each in owner_of},
                                              "at": time.time()}, what="kernel refusals given")
        return added


__all__ = ["LIVE_GRACE_SECONDS", "attribute", "owners", "refusal_id"]
