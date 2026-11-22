"""A refusal the OS sandbox made, shown on the agent instance whose program it stopped (KI-568).

File Shield records each sandbox refusal the system protection helper reads from the kernel's log
(``audit`` finding rows of the sandbox recorder, ``event == "sandbox_deny"``): the path, the
program's name and when — never which agent, because the log names a program, not a session.
Real run (test VM, 2026-11-22): Claude Code started through the launcher wrote a script and ran
it; the kernel refused the read, but the instance said ``python3 r.py allow``, refused 0.

This module gives each such refusal to the instance it belongs to: a SANDBOXED instance that was
live when it happened. When exactly one sandboxed instance was live then, the refusal is its; when
several were, the one whose latest tool call is closest before the refusal; a tie, or none, leaves
it on File Shield's own list only (honest: never guessed). The instance counts it as refused and
its timeline gets a ``block`` row whose reason says the kernel stopped it. Each refusal is given
once (its record id is remembered, bounded).

Usage::

    attribute(audit.read_findings(limit=200))   # how many refusals were given to an instance
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


def _given() -> list[str]:
    data = read_json_object(_given_path()) or {}
    ids = data.get("ids")
    return [str(each) for each in ids] if isinstance(ids, list) else []


def _key(row: Mapping[str, Any]) -> str:
    return str(row.get("tool_call_id") or f"{row.get('ts')}:{(row.get('fields') or {}).get('path', '')}")


def _candidates(ts: float) -> list[Instance]:
    return [item for item in store.all_instances()
            if (item.sandboxed or item.shells_sandboxed) and item.started <= ts + 1 and item.last >= ts - LIVE_GRACE_SECONDS
            and (item.ended is None or item.ended >= ts - 2)]


def _owner(ts: float) -> Optional[Instance]:
    found = _candidates(ts)
    if len(found) <= 1:
        return found[0] if found else None
    def gap(item: Instance) -> float:
        last = item.last_action.ts if item.last_action and item.last_action.ts <= ts + 1 else 0.0
        return ts - last if last else float("inf")
    ranked = sorted(found, key=gap)
    return ranked[0] if gap(ranked[0]) < gap(ranked[1]) else None


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
        given = _given()
        known = set(given)
        added = 0
        for row in sorted(rows, key=lambda each: float(each.get("ts") or 0)):
            if row.get("framework") != SANDBOX_RECORDER or row.get("event") != "sandbox_deny" or _key(row) in known:
                continue
            ts = float(row.get("ts") or 0)
            owner = _owner(ts)
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
            added += 1
        if added:
            _given_path().parent.mkdir(parents=True, exist_ok=True)
            write_json_object(_given_path(), {"ids": given[-MAX_REMEMBERED:], "at": time.time()}, what="kernel refusals given")
        return added


__all__ = ["LIVE_GRACE_SECONDS", "attribute"]
