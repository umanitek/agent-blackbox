"""Remote access — who is in this machine right now, and how (MONITOR: read-only).

Every way in: SSH (and Tailscale SSH), Screen Sharing / VNC, Remote Management, file sharing and
Remote Apple Events — reported live by the root helper from macOS's own login log and the
inbound sessions (:mod:`.records`); remote-control apps and tunnels, which connect out instead
of waiting on a port, recognised by the program itself (:mod:`.catalog`); the names behind the
addresses (:mod:`.names`). Nothing here changes the system: locking, blocking and ending
sessions live in ``network.protect.remote_lock`` and ``network.respond.sessions``.

Usage::

    part = validate(body.get("remote"), now)   # from the enforcer report (400 on bad input)
    record(part, now)
    view(now)                                   # the ``remote-access`` read (without protect's settings)
    alerts(20)                                  # newest first, each with a sentence
"""

from __future__ import annotations

import time
from typing import Any, Optional

from . import catalog, names, records
from .records import alerts, failure_timeline, failures_since, live_sessions, note, record, validate

__all__ = ["alerts", "catalog", "failures_since", "live_sessions", "note", "record", "validate", "view"]


def _who(session: dict[str, Any]) -> dict[str, Any]:
    address = str(session["remote_ip"])
    return {"ip": address, "tailscale_name": names.tailscale_name(address), "host": names.host_name(address)}


def lock_active(now: Optional[float] = None) -> bool:
    """Whether the helper reports Lock remote access APPLIED, from a fresh snapshot (a stale one —
    a helper that stopped reporting — never counts as locked)."""
    now = time.time() if now is None else now
    snapshot = records.state().get("snapshot") or {}
    return bool(snapshot.get("lock_active")) and now - float(snapshot.get("at") or 0) < records.STALE_AFTER_SECONDS


def view(now: Optional[float] = None, failures_window_minutes: int = 10) -> dict[str, Any]:
    """Sessions (who / how / user / since / duration / processes), recent events, failed logins
    (per source over the window, plus a per-minute timeline), services, remote-control apps and
    tunnels. *watching* is False while the helper's snapshot is stale or absent."""
    now = time.time() if now is None else now
    state = records.state()
    snapshot = state.get("snapshot") or {}
    sessions = [{**session, "who": _who(session), "how_label": records.LABELS.get(session["how"], session["how"]),
                 "duration": max(0, int(now - float(session["started"])))} for session in live_sessions(now)]
    by_source: dict[str, dict[str, Any]] = {}
    for failure in failures_since(now - failures_window_minutes * 60):
        entry = by_source.setdefault(str(failure["ip"]), {"ip": failure["ip"], "count": 0, "users": [], "last": 0.0})
        entry["count"] += 1
        entry["last"] = max(entry["last"], float(failure["ts"]))
        if failure.get("user") and failure["user"] not in entry["users"] and len(entry["users"]) < 5:
            entry["users"].append(failure["user"])
    found = catalog.read()
    return {
        "watching": bool(snapshot) and now - float(snapshot.get("at") or 0) < records.STALE_AFTER_SECONDS,
        "sessions": sessions,
        "recent": alerts(30),
        "failed_logins": sorted(by_source.values(), key=lambda entry: -entry["count"]),
        "failed_timeline": failure_timeline(now),
        "services": {name: bool((snapshot.get("services") or {}).get(name)) for name in records.SERVICES},
        "service_labels": records.SERVICE_LABELS,
        "apps": found["apps"],
        "tunnels": found["tunnels"],
        "lock_active": bool(snapshot.get("lock_active")),
    }
