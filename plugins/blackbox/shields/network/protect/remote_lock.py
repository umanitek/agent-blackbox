"""Lock remote access, block who keeps guessing, and end a session — Network Shield's remote-access
protections (PROTECT). Each becomes part of the plan the root helper applies (``remote``).

* **Lock remote access** (one switch): the remote-access ports — SSH, Screen Sharing, Remote
  Management, file sharing, Remote Apple Events — refuse everyone but this machine (pf, ahead of
  SSH lockdown's allow list). Remote-control apps connect OUT to their vendor's relay, which pf
  cannot tell apart by app: while locked, their relay domains (:func:`catalog.relay_domains`)
  are refused by DNS Shield — so that part needs DNS Shield on, and an app that connects by
  address still gets through. Per-app blocking comes with the signed Network Extension.
* **Brute-force auto-block** (opt-in, off by default): an address with N failed logins within M
  minutes is refused inbound for a cooling period.
* **Blocked addresses**: blocked by the user (or by auto-block), each with an expiry.
* **End session**: a session the user confirmed ending, handed to the helper once, with the pid
  and start the watch reported (the helper checks it is still exactly that session).

Settings and blocks are Desktop's own (``network-shield/remote-lock.json``); the public shield's
settings schema is not touched. Defaults: everything off.

**Undo:** switching the lock off drops its pf rules and the relay domains at the helper's next
plan (seconds); unblocking an address — or its expiry — removes it from the pf table; switching
auto-block off stops new blocks (existing ones still expire, or can be unblocked); an end request
is one-shot and changes nothing that persists. With Network Shield off the plan's remote part is
all-off.
"""

from __future__ import annotations

import ipaddress
import json
import threading
import time
from typing import Any, Mapping, Optional

from ....kernel import constants
from ....kernel.bounded_files import read_json_object, write_json_object
from ....shields.network import mode as mode_module
from ....shields.shield_api import ShieldApiError
from ..monitor import remote_access

DEFAULT_BRUTE_FORCE = {"enabled": False, "failures": 5, "window_minutes": 10, "block_minutes": 60}
LIMITS = {"failures": (3, 50), "window_minutes": (1, 120), "block_minutes": (5, 10080)}
MAX_BLOCKED = 1000
DEFAULT_BLOCK_MINUTES = 24 * 60
#: An end request the helper has not acted on within this is dropped (the session changed).
END_EXPIRES_SECONDS = 120
#: An unblocked address's earlier failures stop counting: ``forgiven`` {ip: when} is kept this long
#: (the longest window failures are counted over), then dropped.
FORGIVEN_SECONDS = LIMITS["window_minutes"][1] * 60
#: Kinds of session that have a process of their own to end.
ENDABLE = ("ssh", "screen-sharing", "remote-desktop")

_lock = threading.Lock()


def _path() -> Any:
    return constants.blackbox_home() / "network-shield" / "remote-lock.json"


def _read() -> dict[str, Any]:
    state = read_json_object(_path()) or {}
    return {"lock": bool(state.get("lock", False)), "brute_force": {**DEFAULT_BRUTE_FORCE, **(state.get("brute_force") or {})},
            "blocked": list(state.get("blocked", [])), "end": list(state.get("end", [])),
            "forgiven": dict(state.get("forgiven") or {})}


def _write(state: dict[str, Any]) -> None:
    write_json_object(_path(), state, what="Network Shield's remote-access protections")


def _prune(state: dict[str, Any], now: float) -> dict[str, Any]:
    state["blocked"] = [b for b in state["blocked"] if float(b.get("until") or 0) > now][-MAX_BLOCKED:]
    state["end"] = [e for e in state["end"] if now - float(e.get("at") or 0) < END_EXPIRES_SECONDS]
    state["forgiven"] = {ip: at for ip, at in state["forgiven"].items() if now - float(at or 0) < FORGIVEN_SECONDS}
    return state


def settings(now: Optional[float] = None) -> dict[str, Any]:
    """The lock, the auto-block settings and the blocked addresses (expired ones left out)."""
    now = time.time() if now is None else now
    state = _prune(_read(), now)
    return {"lock": state["lock"], "brute_force": state["brute_force"], "blocked": state["blocked"]}


def update(body: Mapping[str, Any]) -> dict[str, Any]:
    """Saves ``{"lock": bool, "brute_force": {"enabled", "failures", "window_minutes", "block_minutes"}}``
    (either part optional); anything invalid is refused with a sentence and nothing is stored."""
    with _lock:
        state = _read()
        if "lock" in body:
            if not isinstance(body["lock"], bool):
                raise ShieldApiError(400, "lock must be true or false")
            state["lock"] = body["lock"]
        if "brute_force" in body:
            raw = body["brute_force"]
            if not isinstance(raw, dict):
                raise ShieldApiError(400, "brute_force must be an object")
            merged = dict(state["brute_force"])
            if "enabled" in raw:
                if not isinstance(raw["enabled"], bool):
                    raise ShieldApiError(400, "brute_force.enabled must be true or false")
                merged["enabled"] = raw["enabled"]
            for key, (low, high) in LIMITS.items():
                if key in raw:
                    if type(raw[key]) is not int or not low <= raw[key] <= high:
                        raise ShieldApiError(400, f"brute_force.{key} must be a whole number from {low} to {high}")
                    merged[key] = raw[key]
            state["brute_force"] = merged
        _write(state)
    return settings()


def _address(value: Any) -> str:
    try:
        address = ipaddress.ip_address(str(value))
    except ValueError:
        raise ShieldApiError(400, "that is not an IP address") from None
    if address.is_loopback or address.is_unspecified:
        raise ShieldApiError(400, "this machine's own address cannot be blocked")
    return str(address)


def block(value: Any, minutes: int = DEFAULT_BLOCK_MINUTES, reason: str = "blocked by you", now: Optional[float] = None) -> dict[str, Any]:
    """Refuses *value* inbound for *minutes* (5 minutes to 7 days)."""
    now = time.time() if now is None else now
    if type(minutes) is not int or not 5 <= minutes <= 10080:
        raise ShieldApiError(400, "minutes must be a whole number from 5 to 10080")
    address = _address(value)
    with _lock:
        state = _prune(_read(), now)
        state["blocked"] = [b for b in state["blocked"] if b["ip"] != address]
        state["blocked"].append({"ip": address, "until": now + minutes * 60, "reason": reason[:64], "at": now})
        _write(state)
    return settings(now)


def unblock(value: Any, now: Optional[float] = None) -> dict[str, Any]:
    """Lets *value* in again, and forgives its failed logins so far: only failures AFTER the
    unblock count toward blocking it again (E2E B6: its old failures re-blocked it at once)."""
    now = time.time() if now is None else now
    address = _address(value)
    with _lock:
        state = _prune(_read(), now)
        state["blocked"] = [b for b in state["blocked"] if b["ip"] != address]
        state["forgiven"][address] = now
        _write(state)
    return settings(now)


def check_failures(now: Optional[float] = None) -> list[str]:
    """Brute-force auto-block: addresses with too many failed logins inside the window (never one
    the user always allows) are blocked for the cooling period. Answers the newly blocked."""
    now = time.time() if now is None else now
    state = _read()
    rules, forgiven = state["brute_force"], state["forgiven"]
    if not rules["enabled"]:
        return []
    allowed = set(mode_module.option(mode_module.current(), mode_module.OPT_ALLOW))
    counts: dict[str, int] = {}
    for failure in remote_access.failures_since(now - rules["window_minutes"] * 60):
        address = str(failure["ip"])
        if float(failure["ts"]) > float(forgiven.get(address) or 0):
            counts[address] = counts.get(address, 0) + 1
    already = {b["ip"] for b in settings(now)["blocked"]}
    newly = []
    for address, count in counts.items():
        if count >= rules["failures"] and address not in already and address not in allowed:
            try:
                block(address, rules["block_minutes"], f"{count} failed logins", now)
            except ShieldApiError:
                continue
            remote_access.note({"kind": "remote-auto-blocked", "ts": now, "remote_ip": address, "how": "ssh", "method": "", "user": ""})
            newly.append(address)
    return newly


def request_end(session: Mapping[str, Any], now: Optional[float] = None) -> None:
    """Queues ending *session* (a live one from the watch) for the helper's next plan."""
    now = time.time() if now is None else now
    if session.get("how") not in ENDABLE:
        raise ShieldApiError(409, "This kind of session has no process of its own to end.")
    # The helper never ends pid 0/1 (launchd); queuing it would answer "requested" for an end
    # that cannot happen (E2E B5). Said now, in the window, instead.
    if not isinstance(session.get("pid"), int) or session["pid"] <= 1:
        raise ShieldApiError(409, "Blackbox cannot tell which process serves this session, so it cannot end it.")
    with _lock:
        state = _prune(_read(), now)
        state["end"] = [e for e in state["end"] if e["session_id"] != session["id"]]
        state["end"].append({"session_id": session["id"], "pid": int(session["pid"]), "started": int(session["started"]), "at": now})
        _write(state)


def plan_part(enabled: bool, now: Optional[float] = None) -> dict[str, Any]:
    """The plan's ``remote`` part: all off while the shield is off."""
    now = time.time() if now is None else now
    if not enabled:
        return {"lock": False, "block": [], "end": []}
    state = _prune(_read(), now)
    return {"lock": state["lock"], "block": sorted(b["ip"] for b in state["blocked"]),
            "end": [{"session_id": e["session_id"], "pid": e["pid"], "started": e["started"]} for e in state["end"]]}


def relay_domains(enabled: bool) -> list[str]:
    """Remote-control apps' relay domains while the lock is on (for DNS Shield to refuse)."""
    return remote_access.catalog.relay_domains() if enabled and _read()["lock"] else []


def version(enabled: bool, now: Optional[float] = None) -> str:
    """What the remote part of the plan is now (a cache key: a change rebuilds the plan)."""
    return json.dumps([plan_part(enabled, now), relay_domains(enabled)], sort_keys=True)
