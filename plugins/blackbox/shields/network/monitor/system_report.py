"""The root helper's system report — exposure, persistence, tampering and posture — validated and
kept (``POST …/api/system-report``, sent by the helper's system loop, ``helper/src/platform/macos/system_guard.rs``).

Validated strictly, like the enforcer's report: one bad item refuses the whole report, so nothing
unexpected is ever stored or shown. Kept in ``<BLACKBOX_HOME>/network-shield/system.json``: the
latest snapshot (replacing the last), when each listener and startup item was first seen, and the
events (newest first, bounded). Observing only.

Usage::

    record(validate(body, now))        # the system-report write
    snapshot()                         # the latest look (None before the helper reported)
    events(50)                         # newest first
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

MAX_LISTENERS = 300
MAX_ITEMS = 1000
MAX_EVENTS = 300
MAX_EVENTS_PER_REPORT = 300
MAX_FIRST_SEEN = 3000
STALE_AFTER_SECONDS = 60
PROTOCOLS = ("tcp4", "tcp6", "udp4", "udp6")
ITEM_KINDS = ("launch-agent", "launch-daemon", "user-agent", "cron", "periodic", "login-item", "profile",
              "system-extension", "kernel-extension",
              # Linux's (helper platform/linux/observe/persistence.rs KINDS)
              "systemd-unit", "user-unit", "autostart", "dbus-service", "session-start", "root-config",
              # what runs later (helper observe/run_later.rs): events only, never in the snapshot
              "shell-startup", "ssh-login", "at-job", "login-prefs", "path-program")
PROXIES = ("http", "https", "socks", "auto-config", "auto-discovery")
STATES = ("on", "off", "unknown", "block-all")
FIXES = ("firewall-on", "stealth-on", "guest-off", "screen-sharing-off", "file-sharing-off", "remote-login-off",
         "remote-management-off")
EVENT_KINDS = ("listener-new", "listener-closed", "persistence-new", "persistence-changed", "persistence-removed",
               "dns-changed", "proxy-set", "proxy-removed", "vpn-added", "firewall-changed", "helper-modified",
               "dns-restored", "dns-restore-failed", "fix-applied", "fix-undone", "fix-failed")
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")
_lock = threading.Lock()


def _path() -> Any:
    return constants.blackbox_home() / "network-shield" / "system.json"


def _refuse(message: str) -> ShieldApiError:
    return ShieldApiError(400, message)


def _text(value: Any, field: str, limit: int = 512, empty: bool = True) -> str:
    if not isinstance(value, str) or len(value) > limit or _CONTROL.search(value) or (not empty and not value):
        raise _refuse(f"{field} must be plain text up to {limit} characters")
    return value


def _whole(value: Any, field: str, top: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= top:
        raise _refuse(f"{field} must be a whole number from 0 to {top}")
    return value


def _flag(value: Any, field: str) -> bool:
    if not isinstance(value, bool):
        raise _refuse(f"{field} must be true or false")
    return value


def _ip(value: Any, field: str) -> str:
    try:
        return str(ipaddress.ip_address(_text(value, field, 64, empty=False)))
    except ValueError:
        raise _refuse(f"{field} must be an IP address") from None


def _choice(value: Any, field: str, allowed: tuple[str, ...]) -> str:
    if value not in allowed:
        raise _refuse(f"{field} must be one of: {', '.join(allowed)}")
    return value


def _list(value: Any, field: str, top: int) -> list[Any]:
    if not isinstance(value, list) or len(value) > top:
        raise _refuse(f"{field} must be a list of at most {top}")
    return value


def _listener(item: Any) -> dict[str, Any]:
    if not isinstance(item, Mapping):
        raise _refuse("each listener must be an object")
    return {"protocol": _choice(item.get("protocol"), "protocol", PROTOCOLS), "address": _ip(item.get("address"), "address"),
            "port": _whole(item.get("port"), "port", 65535), "program": _text(item.get("program", ""), "program", 1024),
            "pid": _whole(item.get("pid", 0), "pid", 10**9), "since": _whole(item.get("since", 0), "since", 10**11)}


def _item(item: Any) -> dict[str, Any]:
    if not isinstance(item, Mapping):
        raise _refuse("each startup item must be an object")
    return {"kind": _choice(item.get("kind"), "kind", ITEM_KINDS), "id": _text(item.get("id"), "id", 512, empty=False),
            "label": _text(item.get("label", ""), "label"), "program": _text(item.get("program", ""), "program")}


def _tamper(raw: Any) -> Optional[dict[str, Any]]:
    if raw is None:
        return None
    if not isinstance(raw, Mapping):
        raise _refuse("tamper must be an object")
    return {"dns_servers": [_ip(s, "dns server") for s in _list(raw.get("dns_servers", []), "dns_servers", 10)],
            "proxy": [_choice(p, "proxy", PROXIES) for p in _list(raw.get("proxy", []), "proxy", len(PROXIES))],
            "vpn_count": _whole(raw.get("vpn_count", 0), "vpn_count", 1000),
            "firewall": _choice(raw.get("firewall", "unknown"), "firewall", STATES),
            "helper_files": _whole(raw.get("helper_files", 0), "helper_files", 10)}


def _posture(raw: Any) -> Optional[dict[str, Any]]:
    if raw is None or raw == {}:
        return None
    if not isinstance(raw, Mapping):
        raise _refuse("posture must be an object")
    facts: dict[str, Any] = {key: _choice(raw.get(key, "unknown"), key, STATES)
                             for key in ("filevault", "firewall", "stealth", "gatekeeper", "sip")}
    updates = raw.get("updates") or {}
    if not isinstance(updates, Mapping):
        raise _refuse("updates must be an object")
    facts["updates"] = {key: _text(updates.get(key, ""), f"updates.{key}", 16) for key in ("check", "download", "security")}
    for key in ("remote_login", "screen_sharing", "remote_management", "file_sharing"):
        facts[key] = _flag(raw.get(key, False), key)
    airdrop = []
    for entry in _list(raw.get("airdrop", []), "airdrop", 50):
        if not isinstance(entry, Mapping):
            raise _refuse("each airdrop entry must be an object")
        airdrop.append({"user": _text(entry.get("user"), "user", 64, empty=False), "mode": _text(entry.get("mode", ""), "mode", 32)})
    facts["airdrop"] = airdrop
    facts["screen_lock"] = _text(raw.get("screen_lock", "unknown"), "screen_lock", 32)
    facts["guest"] = _text(raw.get("guest", ""), "guest", 8)
    # Whether sudo needs no password (only root reads the rules; a helper from before this says nothing).
    facts["passwordless_sudo"] = _choice(raw.get("passwordless_sudo", "unknown"), "passwordless_sudo", ("yes", "no", "unknown"))
    if "disk_encryption" in raw:   # a Linux helper's facts (platform/linux/observe/posture.rs)
        facts.update(_linux_posture(raw, updates))
    return facts


#: The facts only a Linux helper reports, and the values each may take.
LINUX_FACTS = {"disk_encryption": STATES, "secure_boot": STATES, "autologin": STATES, "ssh_password_logins": ("yes", "no", "unknown")}


def _linux_posture(raw: Mapping[str, Any], updates: Mapping[str, Any]) -> dict[str, Any]:
    facts: dict[str, Any] = {"os": "linux"}
    for key, allowed in LINUX_FACTS.items():
        facts[key] = _choice(raw.get(key, "unknown"), key, allowed)
    facts["updates_automatic"] = _choice(updates.get("automatic", "unknown"), "updates.automatic", STATES)
    return facts


def _event(raw: Any, now: float) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise _refuse("each event must be an object")
    kind = _choice(raw.get("kind"), "event kind", EVENT_KINDS)
    ts = raw.get("ts", now)
    event: dict[str, Any] = {"kind": kind, "ts": float(ts) if isinstance(ts, (int, float)) and not isinstance(ts, bool) and 0 < ts <= now + 300 else now}
    if kind.startswith("listener-"):
        event.update({k: v for k, v in _listener({**raw, "pid": 0, "since": 0}).items() if k not in ("pid", "since")})
    elif kind.startswith("persistence-"):
        event["item_kind"] = _choice(raw.get("item_kind"), "item_kind", ITEM_KINDS)
        event["id"] = _text(raw.get("id"), "id", 512, empty=False)
        event["label"] = _text(raw.get("label", ""), "label")
        event["program"] = _text(raw.get("program", ""), "program")
        event["mark"] = _text(raw.get("mark", ""), "mark", 160)   # size:mtime:hash — dedupe and the writer's evidence (KI-615)
    elif kind == "dns-changed":
        event["servers"] = [_ip(s, "server") for s in _list(raw.get("servers", []), "servers", 10)]
        event["was"] = [_ip(s, "server") for s in _list(raw.get("was", []), "was", 10)]
    elif kind in ("proxy-set", "proxy-removed"):
        event["proxies"] = [_choice(p, "proxy", PROXIES) for p in _list(raw.get("proxies", []), "proxies", len(PROXIES))]
    elif kind == "vpn-added":
        event["count"] = _whole(raw.get("count", 0), "count", 1000)
    elif kind == "firewall-changed":
        event["state"] = _choice(raw.get("state"), "state", STATES)
        event["was"] = _choice(raw.get("was", "unknown"), "was", STATES)
    elif kind == "dns-restored":
        event["was"] = [_ip(s, "server") for s in _list(raw.get("was", []), "was", 10)]
    elif kind.startswith("fix-"):
        event["fix"] = _choice(raw.get("fix"), "fix", FIXES)
        event["how"] = _text(raw.get("how", ""), "how", 32)
        event["error"] = _text(raw.get("error", ""), "error", 300)
    elif kind == "dns-restore-failed":
        event["error"] = _text(raw.get("error", ""), "error", 300)
    return event


def validate(body: Mapping[str, Any], now: float) -> dict[str, Any]:
    """The report as it will be kept; raises a 400 refusal on anything unexpected."""
    if not isinstance(body, Mapping):
        raise _refuse("the report must be an object")
    watching = _flag(body.get("watching", False), "watching")
    report: dict[str, Any] = {"watching": watching, "at": now,
                              "events": [_event(e, now) for e in _list(body.get("events", []), "events", MAX_EVENTS_PER_REPORT)]}
    if watching:
        report["exposure"] = [_listener(i) for i in _list(body.get("exposure", []), "exposure", MAX_LISTENERS)]
        report["persistence"] = [_item(i) for i in _list(body.get("persistence", []), "persistence", MAX_ITEMS)]
        report["tamper"] = _tamper(body.get("tamper"))
        report["posture"] = _posture(body.get("posture"))
        report["fixes"] = [_choice(f, "fix", FIXES) for f in _list(body.get("fixes", []), "fixes", len(FIXES))]
    return report


def _key(entry: Mapping[str, Any]) -> str:
    if "item_kind" in entry:
        return f"item|{entry['item_kind']}|{entry['id']}"
    if "id" in entry:
        return f"item|{entry['kind']}|{entry['id']}"
    return f"listener|{entry['protocol']}|{entry['address']}|{entry['port']}|{entry['program']}"


def record(report: Mapping[str, Any]) -> dict[str, Any]:
    """Keeps a validated report; answers how many events it added."""
    with _lock:
        state = read_json_object(_path()) or {}
        first_seen: dict[str, float] = dict(state.get("first_seen") or {})
        for event in report["events"]:
            if event["kind"] in ("listener-new", "persistence-new"):
                first_seen.setdefault(_key(event), event["ts"])
        if report["watching"]:
            for entry in report["exposure"] + report["persistence"]:
                first_seen.setdefault(_key(entry), entry.get("since") or report["at"])
            state["snapshot"] = {key: report[key] for key in ("at", "exposure", "persistence", "tamper", "posture", "fixes")}
            if report["posture"] is None and (state.get("snapshot_posture")):
                state["snapshot"]["posture"] = state["snapshot_posture"]
            if report["posture"] is not None:
                state["snapshot_posture"] = report["posture"]
        else:
            state.setdefault("snapshot", {})["at"] = 0
        state["first_seen"] = dict(sorted(first_seen.items(), key=lambda kv: -kv[1])[:MAX_FIRST_SEEN])
        state["events"] = (sorted(report["events"], key=lambda e: -e["ts"]) + list(state.get("events", [])))[:MAX_EVENTS]
        write_json_object(_path(), state, what="Network Shield's system watch")
    return {"recorded": len(report["events"])}


def snapshot(now: Optional[float] = None) -> Optional[dict[str, Any]]:
    """The latest look while it is fresh (the helper reports at least every 10 s), else None."""
    state = read_json_object(_path()) or {}
    snap = state.get("snapshot") or {}
    now = time.time() if now is None else now
    if not snap or now - float(snap.get("at") or 0) > STALE_AFTER_SECONDS:
        return None
    return snap


def first_seen(entry: Mapping[str, Any]) -> Optional[float]:
    return (read_json_object(_path()) or {}).get("first_seen", {}).get(_key(entry))


def events(limit: int = 100) -> list[dict[str, Any]]:
    return list((read_json_object(_path()) or {}).get("events", []))[:max(0, limit)]
