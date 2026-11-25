"""What the root helper reports about remote access — validated strictly, kept bounded, read back.

In the enforcer report, under its own key (so an older add-on ignores it)::

    "remote": {"snapshot": {"sessions": [{"id": "ssh-812-192.168.64.1-52344", "how": "ssh",
                                          "method": "publickey", "fingerprint": "SHA256:…",
                                          "user": "admin", "remote_ip": "192.168.64.1",
                                          "remote_port": 52344, "local_port": 22, "pid": 812,
                                          "started": 1795219000,
                                          "processes": [{"pid": 813, "name": "zsh", "path": "/bin/zsh"}]}],
                            "services": {"remote_login": true, "screen_sharing": false, …}},
               "events": [{"kind": "remote-session-new", …}, {"kind": "remote-auth-failed", …}],
               "lock_active": false}

One bad item refuses the whole report (a confused helper is noticed, not half-believed). Never a
command's arguments or anything typed: processes are names and executable paths only. Kept in
Blackbox's folder (``network-shield/remote.json``): the latest snapshot, events (newest first),
and the failed logins of the last day (for the window that brute-force auto-block reads).
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from typing import Any, Mapping, Optional

from .....kernel import constants
from .....kernel.bounded_files import read_json_object, write_json_object
from .....shields.shield_api import ShieldApiError

HOWS = ("ssh", "tailscale-ssh", "screen-sharing", "remote-desktop", "smb", "remote-apple-events")
METHODS = ("", "publickey", "password", "keyboard-interactive")
SERVICES = ("remote_login", "screen_sharing", "remote_management", "file_sharing", "remote_apple_events")
KINDS = ("remote-session-new", "remote-session-ended", "remote-auth-failed", "remote-service-changed",
         "remote-end-refused", "remote-auto-blocked")
REASONS = ("", "closed", "ended")
MAX_SESSIONS = 100
MAX_PROCESSES = 20
MAX_EVENTS = 300
MAX_EVENTS_PER_REPORT = 200
MAX_FAILURES = 2000
FAILURES_KEPT_SECONDS = 24 * 3600
STALE_AFTER_SECONDS = 180

_SESSION_ID = re.compile(r"^[a-z-]{2,24}-\d{1,10}-[0-9A-Fa-f:.]{2,45}-\d{1,5}$")
_USER = re.compile(r"^[A-Za-z0-9._@+-]{0,64}$")
_FINGERPRINT = re.compile(r"^(SHA256:[A-Za-z0-9+/=]{1,80})?$")
_NAME = re.compile(r"^[\x20-\x7e]{0,64}$")
_PATH = re.compile(r"^(/[\x20-\x7e]{0,511})?$")
_lock = threading.Lock()


def _path() -> Any:
    return constants.blackbox_home() / "network-shield" / "remote.json"


def _refuse(message: str) -> ShieldApiError:
    return ShieldApiError(400, f"remote: {message}")


def _ip(value: Any, optional: bool = False) -> Optional[str]:
    if optional and value in (None, ""):
        return None
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        raise _refuse("an address is not a valid IP address") from None


def _whole(value: Any, field: str, top: int) -> int:
    if type(value) is not int or not 0 <= value <= top:
        raise _refuse(f"{field} must be a whole number from 0 to {top}")
    return value


def _match(pattern: re.Pattern[str], value: Any, field: str) -> str:
    text = "" if value is None else value
    if not isinstance(text, str) or not pattern.match(text):
        raise _refuse(f"{field} is not in the expected form")
    return text


def _one_of(value: Any, allowed: tuple[str, ...], field: str) -> str:
    if value not in allowed:
        raise _refuse(f"{field} must be one of: {', '.join(a or '(none)' for a in allowed)}")
    return value


def _session(raw: Any, now: float) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise _refuse("each session is an object")
    processes = raw.get("processes", [])
    if not isinstance(processes, list) or len(processes) > MAX_PROCESSES:
        raise _refuse(f"a session lists at most {MAX_PROCESSES} processes")
    kept = []
    for process in processes:
        if not isinstance(process, dict):
            raise _refuse("each process is an object")
        kept.append({"pid": _whole(process.get("pid"), "pid", 99_999_999), "name": _match(_NAME, process.get("name"), "a process name"),
                     "path": _match(_PATH, process.get("path"), "a process path")})
    return {"id": _match(_SESSION_ID, raw.get("id"), "a session id"), "how": _one_of(raw.get("how"), HOWS, "how"),
            "method": _one_of(raw.get("method", ""), METHODS, "method"),
            "fingerprint": _match(_FINGERPRINT, raw.get("fingerprint", ""), "a key fingerprint"),
            "user": _match(_USER, raw.get("user", ""), "a user"), "remote_ip": _ip(raw.get("remote_ip")),
            "remote_port": _whole(raw.get("remote_port", 0), "remote_port", 65535),
            "local_port": _whole(raw.get("local_port", 0), "local_port", 65535),
            "pid": _whole(raw.get("pid"), "pid", 99_999_999),
            "started": float(min(now, _whole(raw.get("started", int(now)), "started", 4_102_444_800))), "processes": kept}


def _event(raw: Any, now: float) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise _refuse("each event is an object")
    kind = _one_of(raw.get("kind"), KINDS, "an event's kind")
    event: dict[str, Any] = {"kind": kind, "ts": float(min(now, _whole(raw.get("ts", int(now)), "ts", 4_102_444_800)))}
    if kind == "remote-service-changed":
        if not isinstance(raw.get("on"), bool):
            raise _refuse("a service change says on: true or false")
        event.update(service=_one_of(raw.get("service"), SERVICES, "service"), on=raw["on"])
        return event
    if kind == "remote-end-refused":
        event.update(session_id=_match(_SESSION_ID, raw.get("session_id"), "a session id"),
                     reason=_match(_NAME, str(raw.get("reason") or "")[:64], "a reason"))
        return event
    event.update(how=_one_of(raw.get("how", "ssh"), HOWS, "how"), method=_one_of(raw.get("method", ""), METHODS, "method"),
                 user=_match(_USER, raw.get("user", ""), "a user"), remote_ip=_ip(raw.get("remote_ip"), optional=True))
    if kind in ("remote-session-new", "remote-session-ended"):
        event.update(session_id=_match(_SESSION_ID, raw.get("session_id"), "a session id"),
                     remote_port=_whole(raw.get("remote_port", 0), "remote_port", 65535),
                     reason=_one_of(raw.get("reason", ""), REASONS, "reason"))
    return event


def validate(raw: Any, now: float) -> Optional[dict[str, Any]]:
    """The validated ``remote`` part of a report (None when absent); raises 400 on anything invalid."""
    if raw is None:
        return None
    if not isinstance(raw, dict) or not isinstance(raw.get("lock_active", False), bool):
        raise _refuse("must be an object with lock_active true or false")
    snapshot, events = raw.get("snapshot") or {}, raw.get("events", [])
    if not isinstance(snapshot, dict) or not isinstance(events, list) or len(events) > MAX_EVENTS_PER_REPORT:
        raise _refuse(f"snapshot is an object and events a list of at most {MAX_EVENTS_PER_REPORT}")
    sessions, services = snapshot.get("sessions", []), snapshot.get("services", {})
    if not isinstance(sessions, list) or len(sessions) > MAX_SESSIONS or not isinstance(services, dict):
        raise _refuse(f"at most {MAX_SESSIONS} sessions, and services an object")
    for name, on in services.items():
        _one_of(name, SERVICES, "a service")
        if not isinstance(on, bool):
            raise _refuse("each service is true or false")
    return {"sessions": [_session(s, now) for s in sessions], "services": dict(services),
            "events": [_event(e, now) for e in events], "lock_active": raw.get("lock_active", False)}


def record(part: Optional[dict[str, Any]], now: float) -> None:
    """Keeps a validated report part: the snapshot replaces the last; events and failures add up."""
    if part is None:
        return
    with _lock:
        state = read_json_object(_path()) or {}
        state["snapshot"] = {"sessions": part["sessions"], "services": part["services"], "lock_active": part["lock_active"], "at": now}
        events = sorted(part["events"], key=lambda e: -e["ts"])
        state["events"] = (events + list(state.get("events", [])))[:MAX_EVENTS]
        failures = [{"ts": e["ts"], "ip": e.get("remote_ip"), "user": e.get("user", ""), "how": e.get("how", "")}
                    for e in events if e["kind"] == "remote-auth-failed" and e.get("remote_ip")]
        kept = [f for f in failures + list(state.get("failures", [])) if now - float(f["ts"]) < FAILURES_KEPT_SECONDS]
        state["failures"] = kept[:MAX_FAILURES]
        write_json_object(_path(), state, what="Network Shield's remote-access record")


def note(event: dict[str, Any]) -> None:
    """Adds one event made on this side (e.g. an address auto-blocked) to the record."""
    with _lock:
        state = read_json_object(_path()) or {}
        state["events"] = ([event] + list(state.get("events", [])))[:MAX_EVENTS]
        write_json_object(_path(), state, what="Network Shield's remote-access record")


def state() -> dict[str, Any]:
    return read_json_object(_path()) or {}


def live_sessions(now: Optional[float] = None) -> list[dict[str, Any]]:
    """The sessions of the latest snapshot, or none when it is stale (the helper went quiet)."""
    snapshot = state().get("snapshot") or {}
    now = time.time() if now is None else now
    if not snapshot or now - float(snapshot.get("at") or 0) >= STALE_AFTER_SECONDS:
        return []
    return list(snapshot.get("sessions", []))


def failures_since(since: float) -> list[dict[str, Any]]:
    """Failed logins since *since*, newest first."""
    return [f for f in state().get("failures", []) if float(f["ts"]) >= since]


def failure_timeline(now: float, minutes: int = 30) -> list[int]:
    """Failed logins per minute over the last *minutes* (oldest first) — the page's chart."""
    buckets = [0] * minutes
    for failure in failures_since(now - minutes * 60):
        index = minutes - 1 - int((now - float(failure["ts"])) // 60)
        if 0 <= index < minutes:
            buckets[index] += 1
    return buckets


LABELS = {"ssh": "SSH", "tailscale-ssh": "Tailscale SSH", "screen-sharing": "Screen Sharing",
          "remote-desktop": "Remote Management", "smb": "file sharing", "remote-apple-events": "Remote Apple Events"}
SERVICE_LABELS = {"remote_login": "Remote Login (SSH)", "screen_sharing": "Screen Sharing", "remote_management": "Remote Management",
                  "file_sharing": "File Sharing", "remote_apple_events": "Remote Apple Events"}
SEVERITY = {"remote-session-new": "high", "remote-session-ended": "info", "remote-auth-failed": "medium",
            "remote-service-changed": "medium", "remote-end-refused": "medium", "remote-auto-blocked": "high",
            "remote-gateway-not-blocked": "high"}


def text_of(event: Mapping[str, Any]) -> str:
    """One event as a sentence for a person."""
    kind, how = event.get("kind"), LABELS.get(str(event.get("how")), "remote access")
    who = f" as {event['user']}" if event.get("user") else ""
    where = f" from {event['remote_ip']}" if event.get("remote_ip") else ""
    if kind == "remote-session-new":
        key = " with a key" if event.get("method") == "publickey" else " with a password" if event.get("method") in ("password", "keyboard-interactive") else ""
        return f"Someone logged in over {how}{who}{where}{key}."
    if kind == "remote-session-ended":
        return f"The {how} session{where} was ended by you." if event.get("reason") == "ended" else f"The {how} session{where} ended."
    if kind == "remote-auth-failed":
        return f"A failed {how} login{who}{where}."
    if kind == "remote-service-changed":
        return f"{SERVICE_LABELS.get(str(event.get('service')), 'A remote-access service')} was switched {'on' if event.get('on') else 'off'}."
    if kind == "remote-auto-blocked":
        return f"Blocked {event.get('remote_ip')} after repeated failed logins."
    if kind == "remote-gateway-not-blocked":   # made on this side only (protect/remote_lock), never by the helper
        return (f"Repeated failed logins came through your router ({event.get('remote_ip')}). It was not blocked — that "
                "would cut off every remote connection. Turn off the port forward or lock remote access.")
    return f"Could not end that session: {event.get('reason') or 'it changed'}."


def alerts(limit: int = 20) -> list[dict[str, Any]]:
    """The latest events as alerts (kind, ts, severity, sentence), newest first."""
    return [{"kind": e["kind"], "ts": e["ts"], "severity": SEVERITY.get(e["kind"], "info"), "text": text_of(e),
             **{key: e[key] for key in ("remote_ip",) if e.get(key)}} for e in list(state().get("events", []))[:max(0, limit)]]
