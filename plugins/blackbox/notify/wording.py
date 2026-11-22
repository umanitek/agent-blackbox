"""How a notification is worded: WHICH agent, WHAT it did in plain words, and Blackbox's VERDICT.

Every sentence built here is lock-screen safe — an agent's product name, the project folder's
NAME and a fixed description of what happened; never a path, a command, a prompt or an address.
``detail`` carries the finding's own title and evidence (both already redacted where they were
recorded), for a person who chose ``notifications.details``.

Usage::

    wording.finding(row)                 # Notice for one audit finding row, or None
    wording.lifecycle("started", instance_row, sub=None)
"""

from __future__ import annotations

import os
from typing import Any, Mapping, Optional

from ..kernel import threat_ids
from ..kernel.agent_hosts import BY_ID, DECISION_TOO_LATE
from .model import Notice

ELEVATION_ID = "agent:elevation-request"
ROOT_ID = "agent:running-as-root"
#: What a finding of each category is, in the person's words.
WHAT = {
    "injection": "met a prompt-injection attempt", "escalation": "tried a dangerous command",
    "dependency": "tried to install a package on the threat list", "fileaccess": "reached for a sensitive file",
    "skill": "tried to use a suspicious skill", "secret": "was about to expose a secret",
    "ioc": "reached for an address on the threat list",
}
#: What an attempt on Blackbox itself was, by the finding's title (detection.paths.guard_secrets
#: names reading its keys; every other self-protection finding is a change).
SELF_PROTECTION_WHAT = {"Would read Blackbox's key files": "tried to read Blackbox's own keys",
                        "": "tried to change, remove or switch off Blackbox"}
#: Why, in a few words, by where the rule came from.
WHY = {"public": "it matches the verified threat graph", "community": "the community flagged it",
       "heuristic": "it looks like a known attack pattern", "custom": "one of your own rules covers it",
       "secret": "Blackbox's built-in protection covers it"}
_LEVEL = {"critical": "critical", "high": "warning", "medium": "warning"}


def agent_name(agent: str) -> str:
    """The product's name for an agent id (the Hermes agent for Blackbox's own host)."""
    if agent in BY_ID:
        return BY_ID[agent].name
    return "Your Hermes agent" if agent in ("", "hermes") else agent


def project_of(path: Any) -> str:
    return os.path.basename(str(path or "").rstrip("/"))[:80]


def _where(project: str) -> str:
    return f" in {project}" if project else ""


def finding(row: Mapping[str, Any]) -> Optional[Notice]:
    """The notice for one audit finding row (``audit.read_findings``); None for a row with no identifier."""
    identifier = str(row.get("identifier") or "")
    if not identifier:
        return None
    agent = str(row.get("framework") or "hermes")
    name, project = agent_name(agent), project_of(row.get("workspace"))
    ts = float(row.get("ts") or 0)
    stopped = str(row.get("decision") or "") in ("block", "blocked")
    severity = str(row.get("severity") or "")
    instance = str(row.get("session_id") or (row.get("fields") or {}).get("session") or "")
    detail = " — ".join(part for part in (str(row.get("title") or ""), str(row.get("evidence") or "")) if part)[:400]
    common = dict(ts=ts, category="security", agent=agent, agent_name=name, instance=instance, project=project, detail=detail)
    key = f"finding:{identifier}:{ts:.6f}:{row.get('tool_call_id') or ''}"
    if identifier == ROOT_ID:
        return Notice(id=key, kind="running-as-root", level="critical", title=f"{name} is running a program as root",
                      body=f"A program {name} started{_where(project)} is running with administrator (root) rights. "
                           "Open Blackbox to see which.", **common)
    if identifier == ELEVATION_ID:
        return Notice(id=key, kind="elevation-request", level="warning", title=f"{name} asked for administrator rights",
                      body=f"{name}{_where(project)} ran a command that asks for root (sudo). Blackbox let it run and recorded it.",
                      **common)
    what = WHAT.get(str(row.get("category") or ""), "did something Blackbox watches for")
    why = WHY.get(str(row.get("source") or ""), "a Blackbox rule covers it")
    if threat_ids.is_self_protection(identifier):
        # Blackbox protecting itself, said as that (KI-PENDING-c4249e: it read "reached for a sensitive file").
        what, why = SELF_PROTECTION_WHAT.get(str(row.get("title") or ""), SELF_PROTECTION_WHAT[""]), "Blackbox protects itself"
    if str(row.get("decision") or "") == DECISION_TOO_LATE:
        # Decided to stop, but the agent's hook had stopped waiting: the action RAN (KI-PENDING-f5765e).
        return Notice(id=key, kind="too-late", level="critical", title=f"Blackbox could not stop {name} in time",
                      body=f"{name}{_where(project)} {what}. Blackbox decided to stop it, but its answer came after the agent's "
                           f"limit, so the action ran: {why}.", **common)
    if stopped:
        return Notice(id=key, kind="stopped", level="critical" if severity == "critical" else "warning",
                      title=f"Blackbox stopped {name}", body=f"{name}{_where(project)} {what}. Stopped by Blackbox: {why}.", **common)
    return Notice(id=key, kind="flagged", level=_LEVEL.get(severity, "info"), title=f"Blackbox flagged {name}",
                  body=f"{name}{_where(project)} {what}. Flagged, not stopped: {why}.", **common)


def _instance_common(row: Mapping[str, Any]) -> dict[str, Any]:
    agent = str(row.get("agent") or "")
    return dict(agent=agent, agent_name=agent_name(agent), instance=str(row.get("key") or ""), project=str(row.get("folder") or "")[:80])


def lifecycle(kind: str, row: Mapping[str, Any], parent: Optional[Mapping[str, Any]] = None, now: float = 0.0) -> Notice:
    """An agent's (or sub-agent's) start, end or wait as a notice. *row*: its live-tree row;
    *parent*: a sub-agent's session row."""
    session = parent or row
    common = _instance_common(session)
    name, where = common["agent_name"], _where(common["project"])
    sub = f"sub-agent {row.get('type')}" if parent is not None and row.get("type") else "a sub-agent" if parent is not None else ""
    key = f"lifecycle:{kind}:{row.get('key')}:{float(row.get('ended') or row.get('started') or now):.3f}"
    protection = "inside Blackbox's sandbox" if session.get("sandboxed") else "checked by Blackbox's hooks"
    if kind == "started":
        title = f"{name} started {sub}" if sub else f"{name} started"
        body = f"{name}{where} started {sub}." if sub else f"{name} started a session{where}, {protection}."
    elif kind == "ended":
        title = f"{name}: {sub} finished" if sub else f"{name} ended"
        body = f"{sub.capitalize()} of {name}{where} finished." if sub else f"{name}'s session{where} ended."
    else:   # waiting
        waiting_for = str(row.get("waiting_for") or "you")
        title, key = f"{name} is waiting for you", f"lifecycle:waiting:{row.get('key')}:{int(row.get('last') or now)}"
        body = f"{name}{where} is waiting for {waiting_for}."
    return Notice(id=key, ts=now, category="lifecycle", kind=kind if not sub else f"sub-agent-{kind}", level="info",
                  title=title, body=body, **common)


def digest(row: Mapping[str, Any], now: float, *, final: bool) -> Notice:
    """What a session did, in one line (*final*: it just ended)."""
    common = _instance_common(row)
    checked, refused, flagged = int(row.get("checked") or 0), int(row.get("refused") or 0), int(row.get("flagged") or 0)
    too_late = int(row.get("too_late") or 0)
    verdict = "none refused" if not refused else f"{refused} refused"
    if too_late:
        verdict += f", {too_late} not stopped in time"
    if flagged:
        verdict += f", {flagged} flagged"
    subs = len(row.get("sub_agents") or [])
    with_subs = f", {subs} sub-agent{'s' if subs != 1 else ''}" if subs else ""
    key = f"digest:{row.get('key')}:{'end' if final else int(now // 60)}"
    return Notice(id=key, ts=now, category="digest", kind="digest", level="warning" if refused or too_late else "info",
                  title=f"{common['agent_name']}{_where(common['project'])}", body=f"{checked} actions checked{with_subs}: {verdict}.",
                  **common)


def unprotected(row: Mapping[str, Any], now: float) -> Notice:
    agent = str(row.get("agent") or "")
    name = agent_name(agent)
    return Notice(id=f"unprotected:{agent}:{row.get('pid')}:{float(row.get('started') or 0):.0f}", ts=now, category="security",
                  kind="unprotected", level="warning", title=f"{name} is running without Blackbox",
                  body=f"A {name} process is running and Blackbox sees none of its actions. Open Blackbox to see why.",
                  detail=str(row.get("reason") or "")[:300], agent=agent, agent_name=name)


def hooks_off(problem: Mapping[str, Any], agent: str, now: float) -> Notice:
    name = agent_name(agent)
    return Notice(id=f"hooks-off:{agent}:{problem.get('kind')}:{problem.get('file')}", ts=now, category="security", kind="hooks-off",
                  level="warning", title=f"Blackbox's hooks are off for {name}",
                  body=f"A setting keeps Blackbox's hooks from running in {name}. Open Blackbox to see which.",
                  detail=str(problem.get("detail") or "")[:300], agent=agent, agent_name=name)


def summary(count: int, now: float) -> Notice:
    return Notice(id=f"summary:{int(now)}", ts=now, category="security", kind="summary", level="info", title="Blackbox",
                  body=f"{count} more notification{'s' if count != 1 else ''} — open Blackbox to see them.")
