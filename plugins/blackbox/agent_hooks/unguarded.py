"""The back-stop for an agent run Blackbox does not see: one HIGH finding per agent process that
runs with no Blackbox session, naming the agent and the folder it works in.

Private security finding ``2026-11-25-hooks-only-an-agent-may-write-a-project-`` (macOS round R8,
High): a Claude Code session started in a project whose settings switched every hook off ran
unseen — Blackbox recorded no session, and the only sign was the generic "running without
Blackbox" notice, which named neither the project nor the switch. The hook judgement now refuses
an agent writing such a switch (``detection.hook_switches``); this is the layer behind it, for a
switch the person set, or one written in a way no hook could judge.

The rows come from the live view (``instances.views``: an agent process Blackbox has seen no hook
event from, past the grace period, or one whose command line or project switched its hooks off).
Each process is reported once — by its pid and start time, also across a dashboard restart (the
finding's call id is looked for among the newest findings).

Usage::

    report(tree["unprotected"])   # -> how many findings were recorded
"""

from __future__ import annotations

import logging
import threading
from typing import Any, Iterable, Mapping

from ..kernel.agent_hosts import product_name

logger = logging.getLogger(__name__)

#: The finding's identifier and the ``matched`` it carries.
UNGUARDED_ID = "agent:unguarded-run"
MATCHED = "agent-unguarded"
#: How many of the newest findings are read for a run already reported before a restart.
RECENT_SCANNED = 500
_lock = threading.Lock()
_reported: set[str] = set()


def _call_id(row: Mapping[str, Any]) -> str:
    return f"unguarded:{row.get('agent')}:{int(row.get('pid') or 0)}:{float(row.get('started') or 0):.0f}"


def _finding(row: Mapping[str, Any]) -> dict[str, Any]:
    agent = str(row.get("agent") or "")
    name, folder = product_name(agent), str(row.get("folder") or "") or "a folder Blackbox could not read"
    reason = str(row.get("reason") or "Blackbox has seen no hook event from this process.")
    return {"identifier": UNGUARDED_ID, "category": "escalation", "severity": "high",
            "title": f"{name} is running in {folder} without Blackbox"[:200], "tool_name": agent, "matched": MATCHED,
            "evidence": reason[:300], "confirmed": False, "source": "custom", "kind": "flag-only",
            "advice": (f"Blackbox sees none of what this {name} session does. Fix what the evidence names (a switch that "
                       f"turns hooks off, or hooks {name} has not been told to trust yet), then start it again so "
                       "Blackbox's hooks run."),
            "fields": {"agent": agent, "folder": folder[:400], "pid": int(row.get("pid") or 0)}}


#: The launch kinds an agent's hooks fire from at its start. WHY: an editor app (``ide``: Cursor,
#: Windsurf) runs its hooks only when its agent acts, so an open editor with no hook event is not
#: an unseen run — unless its settings switched the hooks off. The same holds for a server an agent
#: leaves running for its sessions (``background``: Codex's managed app-server daemon, L8).
_STARTS_HOOKED = frozenset({"headless", "sdk", "interactive"})


def _reportable(row: Mapping[str, Any]) -> bool:
    reason = str(row.get("reason") or "")
    return str(row.get("launch") or "") in _STARTS_HOOKED or (bool(reason) and "no hook event" not in reason)


def report(rows: Iterable[Mapping[str, Any]]) -> int:
    """Record one HIGH finding for each run in *rows* (the live view's ``unprotected``) not yet
    reported; how many were recorded. Fail-open: 0 on any error."""
    from .. import audit   # late: only the live view asks
    try:
        fresh = [row for row in rows if row.get("agent") and _call_id(row) not in _reported and _reportable(row)]
        if not fresh:
            return 0
        known = {str(found.get("tool_call_id") or "") for found in audit.read_findings(limit=RECENT_SCANNED)}
        recorded = 0
        for row in fresh:
            call_id = _call_id(row)
            with _lock:
                if call_id in _reported:
                    continue
                _reported.add(call_id)
            if call_id in known:
                continue
            audit.record_for(str(row["agent"]), event="unguarded_run", workspace=str(row.get("folder") or ""),
                             findings=[_finding(row)],
                             detail={"decision": "flag", "tool_name": str(row["agent"]), "tool_call_id": call_id,
                                     "agent": str(row["agent"]), "workspace": str(row.get("folder") or "")})
            recorded += 1
        return recorded
    except Exception:   # health: allow BLE001 -- fail open: the live view is shown without the back-stop's finding
        logger.debug("blackbox: unguarded run not recorded", exc_info=True)
        return 0


__all__ = ["MATCHED", "UNGUARDED_ID", "report"]
