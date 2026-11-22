"""File Shield's events report: what it refused, and what changed in protected and watched places.

Two sources, merged newest first:

* the guard's refusals — ``files:file-hit`` / ``files:folder-hit`` / ``files:protected-mention``
  findings on AI-agent tool calls and prompts (``audit.read_findings``);
* the system protection helper's real-time changes inside a protected item or a watched folder
  (:mod:`.changes`).

A story is HTML with a few bold spans; every value put in it — a path, an agent's name — is
escaped first. Blackbox Desktop's add-on adds its own events (``ShieldExtension.events``).
"""

from __future__ import annotations

from html import escape
from typing import Any

from ... import audit
from ..contract import EventFact, SessionSummary, ShieldEvent
from . import changes
from .protect import FILE_HIT_ID, FOLDER_HIT_ID, MENTION_ID, ROUTES

FINDINGS_SCANNED = 500
MAX_EVENTS = 100
NO_SESSION = SessionSummary(id="", agent="", model="", start="", end="", status="", steps=0)
HIT_IDS = (FILE_HIT_ID, FOLDER_HIT_ID, MENTION_ID)


def _hit_event(row: dict[str, Any]) -> ShieldEvent:
    fields = row.get("fields") or {}
    item = str(fields.get("item") or "")
    path = str(fields.get("path") or item)
    route = str(fields.get("route") or "")
    agent = str(row.get("framework") or "An AI agent")
    mention = row.get("identifier") == MENTION_ID
    blocked = row.get("decision") == "block"
    if mention:
        title = f"A prompt asked an AI agent for {item}"
        story = (f"A prompt to <b>{escape(agent)}</b> names <b>{escape(item)}</b>, which you protected. "
                 "Nothing was opened: any tool call that touches it is refused.")
    else:
        title = f"{'Stopped' if blocked else 'Flagged'} an AI agent reaching {item}"
        story = (f"<b>{escape(agent)}</b> tried to {escape(ROUTES.get(route, 'use'))} <b>{escape(path)}</b>, inside "
                 f"<b>{escape(item)}</b>, which you protected. " + ("Blackbox refused the tool call." if blocked
                 else "Blackbox flagged it."))
    return ShieldEvent(
        ts=float(row.get("ts") or 0), identifier=str(row.get("identifier") or ""), title=title,
        severity=str(row.get("severity") or "critical"), outcome="flagged" if mention else ("blocked" if blocked else "flagged"),
        tool=str(row.get("tool_name") or ""), command="", asked="", logo="", session=NO_SESSION, story=story,
        what_to_do=("If this agent should reach it, remove it from File Shield's protected list (Blackbox asks you first).",),
        facts=(EventFact("Protected", item, mono=True), EventFact("Agent", agent)),
    )


def _change_event(change: changes.FileChange) -> ShieldEvent:
    protected = change.scope == changes.PROTECTED
    title = (f"A program {change.kind} {change.path} — inside protected {change.item}" if protected
             else f"New file activity in {change.item}: {change.kind} {change.path}")
    return ShieldEvent(
        ts=change.ts, identifier=f"files:change-{change.scope}", title=title,
        severity="high" if protected else "info", outcome="seen", tool="", command="", asked="", logo="",
        session=NO_SESSION,
        story=(f"<b>{escape(change.path)}</b> was {escape(change.kind)}" +
               (f", inside <b>{escape(change.item)}</b>, which you protected." if protected
                else f" in the watched folder <b>{escape(change.item)}</b>.")),
        what_to_do=(("If you did not do this, check which programs are running.",) if protected else ()),
        facts=(EventFact("Path", change.path, mono=True), EventFact("Change", change.kind)),
    )


def report() -> list[ShieldEvent]:
    """Every event of the shield, newest first (fail-open: empty parts when a source is unreadable)."""
    try:
        findings = audit.read_findings(limit=FINDINGS_SCANNED)
    except Exception:   # health: allow BLE001 -- the events window never breaks on a bad log
        findings = []
    events = [_hit_event(row) for row in findings if row.get("identifier") in HIT_IDS]
    events += [_change_event(change) for change in changes.recent(MAX_EVENTS)]
    return sorted(events, key=lambda event: -event.ts)[:MAX_EVENTS]


def hits(limit: int = 50) -> list[dict[str, Any]]:
    """The newest refusals as plain rows (the hits list on the page and in Blackbox Desktop)."""
    try:
        findings = audit.read_findings(limit=FINDINGS_SCANNED)
    except Exception:   # health: allow BLE001 -- an unreadable log lists nothing
        return []
    rows = []
    for row in findings:
        if row.get("identifier") not in HIT_IDS:
            continue
        fields = row.get("fields") or {}
        rows.append({"ts": float(row.get("ts") or 0), "kind": str(row.get("identifier") or "").split(":", 1)[-1],
                     "item": str(fields.get("item") or ""), "path": str(fields.get("path") or ""),
                     "route": str(fields.get("route") or ""), "agent": str(row.get("framework") or ""),
                     "tool": str(row.get("tool_name") or ""), "decision": str(row.get("decision") or "")})
    return sorted(rows, key=lambda row: -row["ts"])[:limit]
