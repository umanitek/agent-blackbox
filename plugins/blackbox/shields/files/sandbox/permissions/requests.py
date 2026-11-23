"""Permission requests: an agent inside the sandbox wanted a permission it does not have, and the
person is asked (Allow once / Always for this agent here / Keep blocked).

What raises one is always something Blackbox SAW, never the agent's word: a sandbox refusal read
from a sandboxed tool's output (``agent_hooks`` RefusalSeen, wired by the dashboard) or a broker
asked while the permission is on "ask". The agent, instance and project come from Blackbox's own
attribution. A forged request can only raise ONE de-duplicated, rate-limited question:

* one open request per (instance, permission); a second sighting refreshes nothing;
* after "Keep blocked" the same (instance, permission) is not asked again for
  :data:`COOLDOWN_SECONDS`;
* at most :data:`MAX_OPEN` open requests and :data:`MAX_PER_MINUTE` new ones a minute;
* ``what`` (the words shown) is built by Blackbox and capped at :data:`MAX_WHAT_CHARS`.

Kept in memory in the dashboard process (the broker): a request is a question for now, not a
record — the audit log keeps ``permission_requested`` and the answer.

Pattern: **Repository** (one bounded in-memory store behind functions).

Usage::

    request = raise_request("docker", "claude-code", "s-1", "/Users/me/shop", "Docker", 4242)
    pending()                         # [PermissionRequest(...)]
    take(request.id)                  # the request, removed (answered)
"""

from __future__ import annotations

import hashlib
import threading
import time
from typing import Optional

from .model import PermissionRequest

MAX_OPEN, MAX_PER_MINUTE = 20, 10
COOLDOWN_SECONDS = 15 * 60
MAX_WHAT_CHARS = 200
_lock = threading.Lock()
_open: dict[str, PermissionRequest] = {}
_kept_blocked: dict[tuple[str, str], float] = {}
_recent: list[float] = []


def digest(permission: str, agent: str, project: str, what: str = "") -> str:
    """The request's identity: sha256 of what it is for (a grant is bound to it)."""
    return hashlib.sha256("\x00".join((permission, agent, project, what)).encode("utf-8")).hexdigest()


def raise_request(permission: str, agent: str, instance: str, project: str, what: str, pid: int = 0,
                  now: Optional[float] = None) -> Optional[PermissionRequest]:
    """Opens a request, or answers None when one is open for (instance, permission), the person
    kept it blocked lately, or the bounds are reached."""
    now = time.time() if now is None else now
    key = (instance or agent, permission)
    with _lock:
        if any((each.instance or each.agent, each.permission) == key for each in _open.values()):
            return None
        if now - _kept_blocked.get(key, 0.0) < COOLDOWN_SECONDS:
            return None
        _recent[:] = [ts for ts in _recent if now - ts < 60]
        if len(_open) >= MAX_OPEN or len(_recent) >= MAX_PER_MINUTE:
            return None
        sealed = digest(permission, agent, project, what[:MAX_WHAT_CHARS])
        request = PermissionRequest(id=sealed[:16] + hashlib.sha256(f"{instance}{now}".encode()).hexdigest()[:8],
                                    permission=permission, agent=agent, instance=instance, project=project,
                                    what=what[:MAX_WHAT_CHARS], digest=sealed, pid=pid, created=now)
        _open[request.id] = request
        _recent.append(now)
        return request


OPEN, COOLING = "open", "cooling"


def state(instance: str, permission: str, now: Optional[float] = None) -> Optional[str]:
    """``open`` while a request for (instance, permission) waits, ``cooling`` after the person
    kept it blocked lately, None otherwise."""
    now = time.time() if now is None else now
    with _lock:
        if any((each.instance or each.agent, each.permission) == (instance, permission) for each in _open.values()):
            return OPEN
        return COOLING if now - _kept_blocked.get((instance, permission), 0.0) < COOLDOWN_SECONDS else None


def pending() -> list[PermissionRequest]:
    """Every open request, oldest first."""
    with _lock:
        return sorted(_open.values(), key=lambda each: each.created)


def get(request_id: str) -> Optional[PermissionRequest]:
    with _lock:
        return _open.get(request_id)


def take(request_id: str) -> Optional[PermissionRequest]:
    """Removes and answers the open request *request_id* (None when there is none)."""
    with _lock:
        return _open.pop(request_id, None)


def keep_blocked(request: PermissionRequest, now: Optional[float] = None) -> None:
    """Starts the cool-down for the request's (instance, permission)."""
    with _lock:
        _kept_blocked[(request.instance or request.agent, request.permission)] = time.time() if now is None else now
        if len(_kept_blocked) > MAX_OPEN * 10:   # bounded: the oldest cool-downs go first
            for key, _ in sorted(_kept_blocked.items(), key=lambda item: item[1])[:MAX_OPEN]:
                del _kept_blocked[key]


def reset() -> None:
    """Tests: forget everything."""
    with _lock:
        _open.clear()
        _kept_blocked.clear()
        _recent.clear()


__all__ = [
    "COOLDOWN_SECONDS",
    "COOLING",
    "MAX_OPEN",
    "MAX_PER_MINUTE",
    "MAX_WHAT_CHARS",
    "OPEN",
    "digest",
    "get",
    "keep_blocked",
    "pending",
    "raise_request",
    "reset",
    "state",
    "take",
]
