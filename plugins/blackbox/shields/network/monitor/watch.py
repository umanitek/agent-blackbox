"""What Network Shield's enforcer watches and reports: SSH into this machine, the files that decide
who may log in or where names go, and the malicious connections it cut — kept as alerts. Also a
connection to a listed address that a live collector (an add-on) SAW (:func:`observed`): the
collector only reports the facts; this module decides it is listed and keeps it, and Network
Shield words the notice (engine rule, 2026-11-22 — the collector used to word and send it itself).

The enforcer (a root helper) observes; this module validates and keeps what it says, bounded, in
Blackbox's own folder (``network-shield/watch.json``). It never receives a file's contents or a
key: a file change is only its path, what changed (added / removed / modified), the change in
line count and a short sha256 prefix. Every value is checked here before it is kept (strict:
one bad item refuses the whole report, so a confused helper is noticed, not half-believed).

**In the report** (``POST …/enforcer-report``; all optional, an older helper sends none)::

    "watch": {"remote_login": true,
              "sessions": [{"remote_ip": "192.168.64.1", "remote_port": 50000, "since": 1795219000}],
              "files": [{"path": "/Users/me/.ssh/authorized_keys", "exists": true,
                         "changed_at": 1795219000, "sha_prefix": "3fa1c09b"}]},
    "events": [{"kind": "ssh-session-new", "ts": 1795219000, "remote_ip": "192.168.64.1", "remote_port": 50000},
               {"kind": "file-changed", "ts": ..., "path": "/etc/hosts", "change": "modified",
                "lines_delta": 1, "sha_prefix": "9b2e11aa"},
               {"kind": "connection-cut", "ts": ..., "remote_ip": "45.130.148.102"},
               {"kind": "remote-login-changed", "ts": ..., "on": true}]

Usage::

    record(body, now)        # from enforcement.record_report (raises ShieldApiError(400) on bad input)
    ssh_view()               # the ``ssh`` read: Remote Login, sessions, watched files, recent events
    alerts(20)               # newest first, each with a sentence written for a person
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from typing import Any, Mapping, Optional

from ....kernel import constants
from ....kernel.bounded_files import read_json_object, write_json_object
from ....shields.shield_api import ShieldApiError

#: Kept events (newest first), and the most one report may carry.
MAX_EVENTS = 300
MAX_EVENTS_PER_REPORT = 200
MAX_SESSIONS = 200
MAX_FILES = 100
#: A snapshot older than this is not "watching now" (the helper reports every 30 s, at once on news).
STALE_AFTER_SECONDS = 180
#: The watched files, by full path: a user's ``.ssh`` files, and the system's hosts / sshd files.
_USER_FILE = re.compile(r"^/Users/[^/\x00-\x1f]{1,64}/\.ssh/(authorized_keys|known_hosts|config)$")
_SYSTEM_FILES = {"/etc/hosts": "hosts file", "/private/etc/hosts": "hosts file",
                 "/etc/ssh/sshd_config": "SSH server settings", "/private/etc/ssh/sshd_config": "SSH server settings"}
_SHA_PREFIX = re.compile(r"^[0-9a-f]{0,16}$")
#: ``firewall-restored``: another program removed or changed the Threat Firewall's rules and the
#: helper loaded them again at once (KI-688).
KINDS = ("ssh-session-new", "ssh-session-ended", "file-changed", "connection-cut", "remote-login-changed", "firewall-restored")
#: Not from the helper: a connection a live collector saw (:func:`observed`).
SEEN = "connection-seen"
#: One sighting per process and address in this long (the collector reports every reading).
SEEN_AGAIN_AFTER_SECONDS = 3600
MAX_PROGRAM_CHARS = 64
_PROGRAM = re.compile(r"^[^/\x00-\x1f]{1,64}$")
CHANGES = ("added", "removed", "modified")
SEVERITY = {"ssh-session-new": "high", "ssh-session-ended": "info", "file-changed": "medium",
            "connection-cut": "high", "remote-login-changed": "medium", "firewall-restored": "high", SEEN: "high"}

_lock = threading.Lock()


def _path() -> Any:
    return constants.blackbox_home() / "network-shield" / "watch.json"


def _refuse(message: str) -> ShieldApiError:
    return ShieldApiError(400, message)


def label(path: str) -> str:
    """What a watched file is, for a person (``me · authorized_keys``); "" for an unknown path."""
    found = _USER_FILE.match(path)
    if found:
        return f"{path.split('/')[2]} · {found.group(1)}"
    return _SYSTEM_FILES.get(path, "")


def _ip(value: Any) -> str:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        raise _refuse("each SSH session and cut names a valid IP address") from None


def _whole(value: Any, field: str, top: int) -> int:
    if type(value) is not int or not 0 <= value <= top:
        raise _refuse(f"{field} must be a whole number from 0 to {top}")
    return value


def _ts(value: Any, now: float) -> float:
    return float(min(now, _whole(value, "ts", 4_102_444_800)))


def _file_path(value: Any) -> str:
    path = str(value or "")
    if not label(path):
        raise _refuse("a watched file must be a user's .ssh file, /etc/hosts or sshd_config")
    return path


def _sha(value: Any) -> str:
    text = str(value or "")
    if not _SHA_PREFIX.match(text):
        raise _refuse("sha_prefix must be up to 16 lower-case hex digits")
    return text


def _event(item: Any, now: float) -> dict[str, Any]:
    if not isinstance(item, dict) or item.get("kind") not in KINDS:
        raise _refuse(f"each event has a kind: {', '.join(KINDS)}")
    kind = item["kind"]
    event: dict[str, Any] = {"kind": kind, "ts": _ts(item.get("ts", int(now)), now)}
    if kind == "firewall-restored":   # its kind and time are the whole event
        return event
    if kind in ("ssh-session-new", "ssh-session-ended"):
        event.update(remote_ip=_ip(item.get("remote_ip")), remote_port=_whole(item.get("remote_port", 0), "remote_port", 65535))
    elif kind == "connection-cut":
        event["remote_ip"] = _ip(item.get("remote_ip"))
    elif kind == "remote-login-changed":
        if not isinstance(item.get("on"), bool):
            raise _refuse("remote-login-changed says on: true or false")
        event["on"] = item["on"]
    else:
        if item.get("change") not in CHANGES:
            raise _refuse(f"a file change is one of: {', '.join(CHANGES)}")
        delta = item.get("lines_delta", 0)
        if type(delta) is not int or abs(delta) > 1_000_000:
            raise _refuse("lines_delta must be a whole number")
        event.update(path=_file_path(item.get("path")), change=item["change"], lines_delta=delta, sha_prefix=_sha(item.get("sha_prefix")))
    return event


def observed(body: Mapping[str, Any], listed: frozenset[str], now: float) -> Optional[dict[str, Any]]:
    """The event for one connection a live collector saw — ``{pid, program, remote_ip,
    remote_port, ts}`` (``program``: the process's NAME, never a path) — or None when the address
    is not on *listed* (Blackbox's own list decides, never the reporter) or this process was
    already seen talking to it within :data:`SEEN_AGAIN_AFTER_SECONDS`. Raises 400 on bad input."""
    program = str(body.get("program") or "")
    if not _PROGRAM.match(program):
        raise _refuse(f"program is the process's name (no path), 1 to {MAX_PROGRAM_CHARS} characters")
    event = {"kind": SEEN, "ts": _ts(body.get("ts", int(now)), now), "remote_ip": _ip(body.get("remote_ip")),
             "remote_port": _whole(body.get("remote_port", 0), "remote_port", 65535),
             "pid": _whole(body.get("pid"), "pid", 2**31 - 1), "program": program}
    if event["remote_ip"] not in listed:
        return None
    for before in events(MAX_EVENTS):
        if (before.get("kind") == SEEN and before.get("pid") == event["pid"] and before.get("remote_ip") == event["remote_ip"]
                and event["ts"] - float(before.get("ts") or 0) < SEEN_AGAIN_AFTER_SECONDS):
            return None
    return event


def _snapshot(raw: Any, now: float) -> dict[str, Any]:
    if not isinstance(raw, dict) or not isinstance(raw.get("remote_login", False), bool):
        raise _refuse("watch must be an object with remote_login true or false")
    sessions, files = raw.get("sessions", []), raw.get("files", [])
    if not isinstance(sessions, list) or len(sessions) > MAX_SESSIONS or not isinstance(files, list) or len(files) > MAX_FILES:
        raise _refuse(f"watch holds at most {MAX_SESSIONS} sessions and {MAX_FILES} files")
    kept_sessions = []
    for session in sessions:
        if not isinstance(session, dict):
            raise _refuse("each session is an object")
        kept_sessions.append({"remote_ip": _ip(session.get("remote_ip")),
                              "remote_port": _whole(session.get("remote_port", 0), "remote_port", 65535),
                              "since": _ts(session.get("since", int(now)), now)})
    kept_files = []
    for entry in files:
        if not isinstance(entry, dict) or not isinstance(entry.get("exists"), bool):
            raise _refuse("each watched file says whether it exists")
        changed = entry.get("changed_at")
        kept_files.append({"path": _file_path(entry.get("path")), "label": label(str(entry.get("path"))), "exists": entry["exists"],
                           "changed_at": None if changed is None else _ts(changed, now), "sha_prefix": _sha(entry.get("sha_prefix"))})
    return {"remote_login": bool(raw.get("remote_login", False)), "sessions": kept_sessions, "files": kept_files, "at": now}


def validate(body: Mapping[str, Any], now: float) -> tuple[Optional[dict[str, Any]], list[dict[str, Any]]]:
    """(the watch snapshot or None, the events) of one report; raises 400 on anything invalid."""
    raw_events = body.get("events", [])
    if not isinstance(raw_events, list) or len(raw_events) > MAX_EVENTS_PER_REPORT:
        raise _refuse(f"events must be a list of at most {MAX_EVENTS_PER_REPORT}")
    snapshot = _snapshot(body["watch"], now) if body.get("watch") is not None else None
    return snapshot, [_event(item, now) for item in raw_events]


def record(snapshot: Optional[dict[str, Any]], events: list[dict[str, Any]]) -> None:
    """Keeps a validated snapshot (replacing the last) and events (newest first, bounded)."""
    with _lock:
        state = read_json_object(_path()) or {}
        if snapshot is not None:
            state["snapshot"] = snapshot
        state["events"] = (sorted(events, key=lambda e: -e["ts"]) + list(state.get("events", [])))[:MAX_EVENTS]
        state["cut_total"] = int(state.get("cut_total", 0)) + sum(1 for e in events if e["kind"] == "connection-cut")
        write_json_object(_path(), state, what="Network Shield's watch")


def events(limit: int = 100) -> list[dict[str, Any]]:
    """The latest events, newest first."""
    return list((read_json_object(_path()) or {}).get("events", []))[:max(0, limit)]


def cut_total() -> int:
    return int((read_json_object(_path()) or {}).get("cut_total", 0))


def text_of(event: Mapping[str, Any]) -> str:
    """One event as a sentence for a person (plain text; a story escapes it again)."""
    kind = event.get("kind")
    if kind == "ssh-session-new":
        return f"Someone connected to this machine over SSH from {event.get('remote_ip')}."
    if kind == "ssh-session-ended":
        return f"The SSH session from {event.get('remote_ip')} ended."
    if kind == "connection-cut":
        return f"Cut a connection to {event.get('remote_ip')}, which the verified threat graph lists as malicious."
    if kind == SEEN:
        return (f"{event.get('program')} (process {event.get('pid')}) is talking to {event.get('remote_ip')}:"
                f"{event.get('remote_port')}, which the verified threat graph lists as malicious.")
    if kind == "firewall-restored":
        return "Something removed or changed the Threat Firewall's rules; Blackbox put them back at once."
    if kind == "remote-login-changed":
        return "Remote Login (SSH) was switched on." if event.get("on") else "Remote Login (SSH) was switched off."
    change = {"added": "appeared", "removed": "was removed", "modified": "changed"}.get(str(event.get("change")), "changed")
    delta = int(event.get("lines_delta") or 0)
    lines = f" ({delta:+d} line{'s' if abs(delta) != 1 else ''})" if delta else ""
    return f"The {label(str(event.get('path')))} file {change}{lines}."


def alerts(limit: int = 20) -> list[dict[str, Any]]:
    """The latest events as alerts: kind, ts, severity and a sentence, newest first."""
    return [{"kind": e["kind"], "ts": e["ts"], "severity": SEVERITY.get(e["kind"], "info"), "text": text_of(e),
             **{key: e[key] for key in ("remote_ip", "path") if key in e}} for e in events(limit)]


def ssh_view(limit: int = 50, now: Optional[float] = None) -> dict[str, Any]:
    """The ``ssh`` read: Remote Login, open sessions, watched files and the recent watch events.
    *watching* is True only while the helper's snapshot is fresh."""
    state = read_json_object(_path()) or {}
    snapshot = state.get("snapshot") or {}
    now = time.time() if now is None else now
    fresh = bool(snapshot) and now - float(snapshot.get("at") or 0) < STALE_AFTER_SECONDS
    return {"watching": fresh, "remote_login": bool(snapshot.get("remote_login")),
            "sessions": list(snapshot.get("sessions", [])), "files": list(snapshot.get("files", [])),
            "updated_at": snapshot.get("at"), "events": alerts(limit), "cut_total": int(state.get("cut_total", 0))}
