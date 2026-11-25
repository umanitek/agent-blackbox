"""Network Shield's events report: what it refused, told in plain words.

A story is HTML with a few bold spans; every value put in it — a host, an agent's name, all from
outside Blackbox — is escaped first. The source here is the guard's lockdown and block-list
findings on AI-agent tool calls (``audit.read_findings``); an add-on adds its own events
(``ShieldExtension.events``), merged newest first.
"""

from __future__ import annotations

from html import escape
from typing import Any

from ... import audit
from ..contract import EventFact, SessionSummary, ShieldEvent
from .lockdown import BLOCKED_ID, LOCKDOWN_ID

#: Findings scanned for the shield's own (the log holds every finding of every shield).
FINDINGS_SCANNED = 500
MAX_EVENTS = 100
NO_SESSION = SessionSummary(id="", agent="", model="", start="", end="", status="", steps=0)


def _finding_event(row: dict[str, Any]) -> ShieldEvent:
    host = str((row.get("fields") or {}).get("host") or row.get("evidence") or "")
    lockdown = row.get("identifier") == LOCKDOWN_ID
    blocked = row.get("decision") == "block"
    agent = str(row.get("framework") or "An AI agent")
    reason = "is not on the hosts AI agents may reach" if lockdown else "is on your block list"
    return ShieldEvent(
        ts=float(row.get("ts") or 0), identifier=str(row.get("identifier") or ""),
        title=f"{'Stopped' if blocked else 'Flagged'} an AI agent reaching {host}", severity=str(row.get("severity") or "critical"),
        outcome="blocked" if blocked else "flagged", tool=str(row.get("tool_name") or ""), command="", asked="",
        logo="", session=NO_SESSION,
        story=f"<b>{escape(agent)}</b> tried to reach <b>{escape(host)}</b>, which {reason}. "
              + ("Blackbox refused the tool call." if blocked else "Blackbox is in Audit mode, so it only flagged it."),
        what_to_do=(f"If {host} is fine, add it to the hosts AI agents may reach in Network Shield's settings.",),
        facts=(EventFact("Host", host, mono=True), EventFact("Agent", agent)),
    )


def report() -> list[ShieldEvent]:
    """Every event of the shield, newest first (fail-open: empty when the log is unreadable)."""
    try:
        findings = audit.read_findings(limit=FINDINGS_SCANNED)
    except Exception:   # health: allow BLE001 -- the events window never breaks on a bad log
        findings = []
    events = [_finding_event(row) for row in findings if row.get("identifier") in (LOCKDOWN_ID, BLOCKED_ID)]
    return sorted(events, key=lambda event: -event.ts)[:MAX_EVENTS]
