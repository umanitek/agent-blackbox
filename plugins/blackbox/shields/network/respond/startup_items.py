"""The persistence watch's events for a person: who wrote each new startup item, how loud to be,
and never a flood.

The system protection helper looks at every place something starts by itself or runs later — launchd
jobs, login items, cron and ``at``, the shell startup files, OpenSSH's login files and the program
folders on the PATH (helper ``observe/persistence.rs`` + ``observe/run_later.rs``) — and reports each
new, changed or removed entry as a ``persistence-*`` event, with the entry's ``mark`` (size, the
time it was last written and a hash of its content). Its scan can not say WHICH process wrote the
entry (only the OS's file checks, Layer 3, could). So the writer is found in Blackbox's own records,
and only with EVIDENCE (KI-615: a plain-shell append five minutes after an agent's own append to
``~/.ssh/authorized_keys`` was reported "written by Claude Code"): an AI agent's tool call that names
the entry's path (``echo … > ~/Library/LaunchAgents/x.plist``, a write tool on it) AND during which
the entry was written — its write time between the call's start and its end (the matching
``post_tool_call``, else :data:`CALL_SECONDS`). A call that named the path at another time is not
the writer: the alert says the writer is unknown. Only a call that RAN is evidence (KI-636, security
round 6: a REFUSED Read of ``~/.ssh/authorized_keys``, and refused appends in two other sessions, were
named as the writer of a later change by the harness shell and by a script in another session): a
``pre_tool_call`` the hook refused (``decision: block``) never ran, and a call whose
``post_tool_call`` records a refusal (the OS sandbox stopped it, KI-590) did not write — neither is
evidence, nor even "named". A call decided too late (``too-late``) ran, and is. Each entry is reported once (KI-615): the same
file, seen under another spelling (a home reached through a link), with the same content, is one
event. Then:

* written by an AI agent → **critical**, naming the agent and its project — an agent leaving
  something that runs outside its sandbox, or later as the person, is the attack;
* otherwise → by what it is: a launchd job or login item judged by its program's signature
  (``monitor.exposure.judge``), a new program on the PATH or a shell startup change
  **informational** (``brew`` and app installers write these all day), an OpenSSH login file, a cron
  or ``at`` job and the login window's preferences **high** (security-sensitive places, round 7);
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

from ....detection import parse_dependency_installs
from ....kernel.agent_hosts import BY_ID
from ..monitor import exposure

#: How long before an entry appeared an agent's tool call that names it is looked at.
WINDOW_SECONDS = 600
#: How long a tool call with no recorded end is taken to run (its write must fall inside).
CALL_SECONDS = 120
#: Clock slack between a hook's record and a file's write time.
SLACK_SECONDS = 2
#: A record's ``decision`` when the hook refused the call, or the OS sandbox refused it while it ran.
REFUSED = "block"
#: The agent tool-call records read to find a writer (newest first).
MAX_ROWS = 2000
#: Alerts per source (item kind + folder) per window; the rest are folded into one line.
BUDGET = 3
BUDGET_SECONDS = 600
#: What each kind of entry is, in the person's words (the launchd kinds are ``exposure.ITEM_NAMES``).
RUN_LATER_NAMES = {"shell-startup": "Shell startup file", "ssh-login": "SSH login file", "at-job": "Scheduled job (at)",
                   "login-prefs": "Login preferences", "path-program": "Program on your PATH"}
#: The severity of a new or changed entry whose writer is not known, by kind. WHY high for the
#: security-sensitive ones (security round 7): an SSH key added to ``authorized_keys``, a new cron or
#: ``at`` job and a change to the login window's preferences were reported medium — each lets
#: something in or start later with the person's rights, and nobody known made it.
_QUIET = {"path-program": "info", "shell-startup": "info", "ssh-login": "high", "at-job": "high", "cron": "high",
          "login-prefs": "high",
          # Linux's kinds: there is no code signature to judge a Linux program by (phase 1), so a new
          # or changed unit, autostart entry, D-Bus service, session file or root configuration
          # whose writer is not known is high — never "critical" for every package an update installs.
          "systemd-unit": "high", "user-unit": "high", "autostart": "high", "dbus-service": "high",
          "session-start": "high", "root-config": "high"}


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


def written_at(event: Mapping[str, Any]) -> Optional[float]:
    """When the entry was last written, from its ``mark`` (``size:mtime:…``); None when not known."""
    parts = str(event.get("mark") or "").split(":")
    return float(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None


def _detail(row: Mapping[str, Any]) -> Mapping[str, Any]:
    return row["detail"] if isinstance(row.get("detail"), Mapping) else {}


def _refused(row: Mapping[str, Any]) -> bool:
    """True when the hook or the OS sandbox refused the call this record is of (:data:`REFUSED`)."""
    return str(_detail(row).get("decision") or "") == REFUSED


def _call_end(row: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]) -> Optional[float]:
    """When the tool call *row* ended: its own ``post_tool_call`` record, else :data:`CALL_SECONDS`
    after it; None when it was refused — before it ran, or by the sandbox while it ran (KI-636)."""
    if _refused(row):
        return None
    call_id, start = str(_detail(row).get("tool_call_id") or ""), float(row.get("ts") or 0)
    ends = [other for other in rows if call_id and other.get("event") == "post_tool_call"
            and _detail(other).get("tool_call_id") == call_id and float(other.get("ts") or 0) >= start]
    if any(_refused(end) for end in ends):
        return None
    return min((float(end.get("ts") or 0) for end in ends), default=start + CALL_SECONDS)


def _installs_it(event: Mapping[str, Any], args: Any) -> bool:
    """True when the tool call with *args* is a package install that put *event*'s program on the
    PATH: the program, or the file its link points to, is named for a package the command installs.

    WHY (KI-698, macOS round R8): a hooks-only Claude Code's ``npm install -g cowsay@1.6.0`` linked
    ``/opt/homebrew/bin/cowsay`` and the alert said only "New program on your PATH", info, no writer:
    the command names a package, never the path npm writes. The link (``…/node_modules/cowsay/…``,
    pipx's ``venvs/ruff/…``, Homebrew's ``Cellar/jq/…``) names it, and is the evidence."""
    if event.get("item_kind") != "path-program" or not isinstance(args, Mapping) or not isinstance(args.get("command"), str):
        return False
    names = {str(found.get("name") or "").lower() for found in parse_dependency_installs(args["command"])} - {""}
    if not names:
        return False
    path, target = str(event.get("id") or ""), str(event.get("program") or "")
    parts = {os.path.basename(path).lower(), *(part.lower() for part in target.split("/") if part)}
    return any(name in parts or name.rsplit("/", 1)[-1] in parts for name in names)


def _naming_calls(event: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]) -> list[tuple[Mapping[str, Any], float]]:
    """The agents' tool calls that RAN in the window before *event* and name its path, each with
    when it ended, newest first."""
    path, ts = str(event.get("id") or ""), float(event.get("ts") or 0)
    if not path.startswith("/"):
        return []   # a login item or profile: named by identifier, not a path an agent writes
    forms = _spellings(path)
    found = []
    for row in rows:
        when = float(row.get("ts") or 0)
        if row.get("event") != "pre_tool_call" or not ts - WINDOW_SECONDS <= when <= ts + 5:
            continue
        args = _detail(row).get("args")
        text = json.dumps(args, ensure_ascii=False) if args is not None else ""
        if not (text and (any(form in text for form in forms) or _installs_it(event, args))):
            continue
        end = _call_end(row, rows)
        if end is not None:
            found.append((row, end))
    return sorted(found, key=lambda pair: -float(pair[0].get("ts") or 0))


def writer_of(event: Mapping[str, Any], rows: Sequence[Mapping[str, Any]]) -> Optional[Writer]:
    """The agent whose ALLOWED tool call named *event*'s path AND ran while the entry was written
    (*rows*: audit rows, any order); None without that evidence — never a guess, never a refused call."""
    written = written_at(event)
    if written is None:
        return None
    for row, end in _naming_calls(event, rows):
        start = float(row.get("ts") or 0)
        if start - SLACK_SECONDS <= written <= end + SLACK_SECONDS:
            project = os.path.basename(str(row.get("workspace") or "").rstrip("/"))
            return Writer(str(row.get("framework") or ""), str(_detail(row).get("session_id") or ""), project)
    return None


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


def text_of(event: Mapping[str, Any], writer: Optional[Writer], named: bool = False) -> str:
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
    elif named:   # an agent named it, but not while it was written: said, never claimed
        sentence += " — writer unknown (an AI agent's earlier command named this file)"
    return sentence + "."


def _same_entry(event: Mapping[str, Any]) -> tuple[str, str, str]:
    """What makes two events one entry: the kind, the file as the system resolves it (a home
    reached through a link is the same home) and its content mark."""
    path = str(event.get("id") or "")
    return str(event.get("kind")), os.path.realpath(path) if path.startswith("/") else path, str(event.get("mark") or "")


def _once(events: Sequence[Mapping[str, Any]], rows: Sequence[Mapping[str, Any]]) -> list[tuple[Mapping[str, Any], Optional[Writer]]]:
    """Each entry once with its writer, oldest first; of two copies the one with a writer is kept."""
    kept: dict[tuple[str, str, str], tuple[Mapping[str, Any], Optional[Writer]]] = {}
    for event in sorted(events, key=lambda e: float(e.get("ts") or 0)):
        if event.get("item_kind") == "at-job" and os.path.basename(str(event.get("id") or "")).startswith("."):
            continue   # at's own bookkeeping (.SEQ, .lockfile), from a helper older than KI-615's fix
        key, writer = _same_entry(event), writer_of(event, rows)
        if key not in kept or (kept[key][1] is None and writer is not None):
            kept[key] = (event, writer)
    return sorted(kept.values(), key=lambda pair: float(pair[0].get("ts") or 0))


def _source(event: Mapping[str, Any]) -> str:
    return f"{event.get('item_kind')}|{os.path.dirname(str(event.get('id') or ''))}"


def startup_alerts(events: Sequence[Mapping[str, Any]], rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The ``persistence-*`` *events* as alerts (``kind``, ``ts``, ``severity``, ``text``, and
    ``path`` / ``agent`` / ``session`` where known), newest first, within each source's budget."""
    kept: list[dict[str, Any]] = []
    spent: dict[str, list[float]] = {}
    folded: dict[str, dict[str, Any]] = {}
    for event, writer in _once(events, rows):
        named = writer is None and bool(_naming_calls(event, rows))
        alert = {"kind": event["kind"], "ts": event["ts"], "severity": grade(event, writer), "text": text_of(event, writer, named),
                 "item_kind": str(event.get("item_kind") or ""), **({"path": event["program"]} if event.get("program") else {}),
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


__all__ = ["BUDGET", "BUDGET_SECONDS", "CALL_SECONDS", "MAX_ROWS", "REFUSED", "RUN_LATER_NAMES", "SLACK_SECONDS", "WINDOW_SECONDS", "Writer",
           "grade", "startup_alerts", "text_of", "writer_of", "written_at"]
