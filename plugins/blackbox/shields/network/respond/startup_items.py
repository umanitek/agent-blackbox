"""The persistence watch's events for a person: who wrote each new startup item, how loud to be,
and never a flood.

The system protection helper looks at every place something starts by itself or runs later — launchd
jobs, login items, cron and ``at``, the shell startup files, OpenSSH's login files and the program
folders on the PATH (helper ``observe/persistence.rs`` + ``observe/run_later.rs``) — and reports each
new, changed or removed entry as a ``persistence-*`` event. Its scan can not say WHICH process wrote
the entry (only the OS's file checks, Layer 3, could). So the writer is found in Blackbox's own
records: an AI agent's tool call, recorded by its hook in the :data:`WINDOW_SECONDS` before the entry
appeared, that names the entry's path (``echo … > ~/Library/LaunchAgents/x.plist``, a write tool on
it). Then:

* written by an AI agent → **critical**, naming the agent and its project — an agent leaving
  something that runs outside its sandbox, or later as the person, is the attack;
* otherwise → by what it is: a launchd job or login item judged by its program's signature
  (``monitor.exposure.judge``), a new program on the PATH or a shell startup change
  **informational** (``brew`` and app installers write these all day), an OpenSSH login file or an
  ``at`` job **medium**;
* a **budget** per source (the item's kind and folder): at most :data:`BUDGET` alerts per
  :data:`BUDGET_SECONDS`, the rest folded into one "… and N more" line — a ``brew upgrade`` relinking
  300 programs is one alert, not 300. An agent-written entry is never folded.

Pattern: a **Pipeline** of three pure steps (attribute → grade → budget) over the event list.

Usage::

    alerts = startup_alerts(events, audit.read_audit(limit=MAX_ROWS))
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any, Mapping, Optional, Sequence

from ....kernel.agent_hosts import BY_ID
from ..monitor import exposure

#: How long before an entry appeared an agent's tool call that names it counts as its writer.
WINDOW_SECONDS = 600
#: The agent tool-call records read to find a writer (newest first).
MAX_ROWS = 2000
#: Alerts per source (item kind + folder) per window; the rest are folded into one line.
BUDGET = 3
BUDGET_SECONDS = 600
#: The audit events that carry an agent's tool call.
_CALL_EVENTS = ("pre_tool_call", "post_tool_call")
#: What each kind of entry is, in the person's words (the launchd kinds are ``exposure.ITEM_NAMES``).
RUN_LATER_NAMES = {"shell-startup": "Shell startup file", "ssh-login": "SSH login file", "at-job": "Scheduled job (at)",
                   "path-program": "Program on your PATH"}
_QUIET = {"path-program": "info", "shell-startup": "info", "ssh-login": "medium", "at-job": "medium"}


@dataclass(frozen=True)
class Writer:
    """The AI agent whose recorded tool call named the entry: its product *agent* id, *session* and *project* folder name."""

    agent: str
    session: str
    project: str

    @property
    def name(self) -> str:
        return BY_ID[self.agent].name if self.agent in BY_ID else "Your Hermes agent" if self.agent in ("", "hermes") else self.agent


def _spellings(path: str) -> tuple[str, ...]:
    """*path* as a command may write it: in full, with ``~`` and with ``$HOME`` for the home folder."""
    home = os.path.expanduser("~").rstrip("/")
    forms = [path]
    if home and path.startswith(home + "/"):
        rest = path[len(home):]
        forms += ["~" + rest, "$HOME" + rest, "${HOME}" + rest]
    return tuple(forms)


def writer_of(event: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]) -> Optional[Writer]:
    """The agent whose tool call in the window before *event* named its path (*rows*: audit rows,
    any order); None when no record names it — never a guess."""
    path, ts = str(event.get("id") or ""), float(event.get("ts") or 0)
    if not path.startswith("/"):
        return None   # a login item or profile: named by identifier, not a path an agent writes
    forms = _spellings(path)
    best: Optional[tuple[float, Writer]] = None
    for row in rows:
        when = float(row.get("ts") or 0)
        if row.get("event") not in _CALL_EVENTS or not ts - WINDOW_SECONDS <= when <= ts + 5:
            continue
        detail = row.get("detail") if isinstance(row.get("detail"), Mapping) else {}
        text = json.dumps(detail.get("args"), ensure_ascii=False) if detail.get("args") is not None else ""
        if text and any(form in text for form in forms) and (best is None or when > best[0]):
            project = os.path.basename(str(row.get("workspace") or "").rstrip("/"))
            best = (when, Writer(str(row.get("framework") or ""), str(detail.get("session_id") or ""), project))
    return best[1] if best else None


def grade(event: Mapping[str, Any], writer: Optional[Writer]) -> str:
    """The alert's severity (see the module doc)."""
    if writer is not None and event.get("kind") != "persistence-removed":
        return "critical"
    item_kind = str(event.get("item_kind") or "")
    if event.get("kind") == "persistence-removed":
        return "info"
    if item_kind in _QUIET:
        return _QUIET[item_kind]
    risk, _, _ = exposure.judge(str(event.get("program", "")), startup=True)
    return {"critical": "critical", "high": "high", "medium": "medium"}.get(risk, "low" if risk == "low" else "medium")


def text_of(event: Mapping[str, Any], writer: Optional[Writer]) -> str:
    """One plain sentence: ``New startup item: Launch agent (your account) “com.x” — starts updater``."""
    item_kind = str(event.get("item_kind") or "")
    what = RUN_LATER_NAMES.get(item_kind) or exposure.ITEM_NAMES.get(item_kind, "startup item")
    path = str(event.get("id") or "")
    label = str(event.get("label") or os.path.basename(path.rstrip("/")) or path)
    program = os.path.basename(str(event.get("program") or "").rstrip("/"))
    kind = str(event.get("kind"))
    if item_kind == "path-program":
        head = {"persistence-new": "New program on your PATH", "persistence-changed": "Program on your PATH changed",
                "persistence-removed": "Program removed from your PATH"}[kind]
        target = str(event.get("program") or "")
        sentence = f"{head}: “{label}” in {os.path.dirname(path)}" + (f" (points to {target})" if target and target != path else "")
    else:
        head = {"persistence-new": "New startup item", "persistence-changed": "Startup item changed",
                "persistence-removed": "Startup item removed"}[kind]
        sentence = f"{head}: {what} “{label}”" + (f" — starts {program}" if program and kind != "persistence-removed" else "")
    if writer is not None:
        sentence += f" — written by {writer.name}" + (f" in {writer.project}" if writer.project else "")
    return sentence + "."


def _source(event: Mapping[str, Any]) -> str:
    return f"{event.get('item_kind')}|{os.path.dirname(str(event.get('id') or ''))}"


def startup_alerts(events: Sequence[Mapping[str, Any]], rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The ``persistence-*`` *events* as alerts (``kind``, ``ts``, ``severity``, ``text``, and
    ``path`` / ``agent`` / ``session`` where known), newest first, within each source's budget."""
    kept: list[dict[str, Any]] = []
    spent: dict[str, list[float]] = {}
    folded: dict[str, dict[str, Any]] = {}
    for event in sorted(events, key=lambda e: float(e.get("ts") or 0)):
        writer = writer_of(event, rows)
        alert = {"kind": event["kind"], "ts": event["ts"], "severity": grade(event, writer), "text": text_of(event, writer),
                 **({"path": event["program"]} if event.get("program") else {}),
                 **({"agent": writer.agent, "session": writer.session} if writer else {})}
        source = _source(event)
        recent = [at for at in spent.get(source, []) if float(event["ts"]) - at < BUDGET_SECONDS]
        if writer is None and len(recent) >= BUDGET:
            fold = folded.setdefault(source, {"kind": "persistence-many", "severity": "info", "count": 0, "ts": event["ts"]})
            fold["count"] += 1
            fold["ts"] = event["ts"]
            fold["text"] = (f"… and {fold['count']} more change{'s' if fold['count'] != 1 else ''} in "
                            f"{os.path.dirname(str(event.get('id') or '')) or 'startup items'}.")
            continue
        spent[source] = recent + [float(event["ts"])]
        kept.append(alert)
    return sorted(kept + list(folded.values()), key=lambda alert: -float(alert["ts"]))


__all__ = ["BUDGET", "BUDGET_SECONDS", "MAX_ROWS", "RUN_LATER_NAMES", "WINDOW_SECONDS", "Writer", "grade", "startup_alerts",
           "text_of", "writer_of"]
