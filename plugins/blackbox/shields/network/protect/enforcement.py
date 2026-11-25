"""The contract between Network Shield (the policy) and its enforcer (the native root helper).

The enforcer decides nothing. It pulls :func:`plan` — what DNS must refuse, which IPs the
firewall must drop, what is always allowed — and applies it; it pushes back
:func:`record_report` — whether it is running, its counters and the names it refused. All
policy lives here, in the plugin, so every surface (dashboard, Hermes Desktop, a
companion app) shows the same shield.

**The plan** (``GET /api/shields/network-shield/api/enforcement``)::

    {"version": "<sha256 of the content>", "unchanged": false, "graph_ready": true,
     "dns": {"enabled": true, "verified": [...], "lists": [...], "block": [...]},
     "firewall": {"enabled": false, "ips": [...], "spared": [...], "never_block": [...]},
     "cut": {"enabled": true, "ips": [...]},          # malicious IPs connected right now: cut them
     "ssh": {"lockdown": false, "allow": ["192.168.1.0/24"]},
     "watch": true,                                    # watch SSH and the login files (shield on)
     "allow": [...]}

The firewall part states what it spares (KI-680): ``spared`` — the verified graph's addresses it
did NOT drop (a public resolver, the person's allow list) — and ``never_block`` — every address it
never drops whatever the graph says (``never_block.NEVER_BLOCK_IPS`` and the allow list's
addresses), so the person can see 1.1.1.1 is safe even when the graph does not list it at all
(Linux round L3: the graph's SafeDep 1.1.1.1 entry was outside the verified scope, so ``spared`` was
rightly empty and the plan said nothing about resolvers).

``"keep_verified": true`` (the graph's lists are unavailable or partial — the store is down, or
not read yet after a restart) tells the helper to keep the verified domains and firewall addresses
it last applied and add these: a source that is down never clears protection (E2E recheck
2026-11-21: the node went down, the plan's lists were empty, the table was emptied).

``?have=<version>`` answers ``{"version": ..., "unchanged": true}`` when nothing changed, so
the enforcer's minute-by-minute poll costs nothing. The verified graph's lists are applied only
while the shield is on; with the shield off the plan switches everything off.

**The report** (``POST /api/shields/network-shield/api/enforcer-report``)::

    {"running": true, "dns_active": true, "firewall_active": false, "version": "<plan version>",
     "cut_active": true, "ssh_lockdown_active": false,            # optional (older helpers)
     "queries": 1200, "firewall_dropped": 3,
     "blocks": [{"domain": "evil.example", "list": "verified", "count": 2, "ts": 1795219000}],
     "resolved": [{"ip": "93.184.215.14", "domain": "example.com", "ts": 1795219000}],   # optional (KI-588)
     "watch": {...}, "events": [...]}                             # optional — see :mod:`.watch`

Stored bounded in Blackbox's own folder (``network-shield/state.json``): per-name counts (the
busiest :data:`MAX_COUNTED` names) and the latest :data:`MAX_RECENT` blocks.

**Undo:** switched off (the shield, or one protection), :func:`plan` answers every protection
off (DNS, firewall, cut, SSH lockdown, watch) and the root helper restores the saved DNS servers
and removes its pf anchor — exactly what it changed, nothing else.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import threading
import time
from pathlib import Path
from typing import Any, Iterable, Mapping, NamedTuple, Optional

from ....kernel import constants
from ....kernel.bounded_files import read_json_object, write_json_object
from ....shields.contract import ShieldMode
from ....shields.shield_api import ShieldApiError
from ....shields.network import mode as mode_module
from ....shields.network.addresses import public_only
from . import blocklists, never_block, remote_lock
from ..monitor import remote_access, resolved, watch

LISTS = ("verified", "lists", "block")
MAX_RECENT = 300
MAX_COUNTED = 2000
MAX_BLOCKS_PER_REPORT = 500
#: A report older than this means the enforcer is not running any more.
STALE_AFTER_SECONDS = 180
_lock = threading.Lock()


def _state_path() -> Path:
    return constants.blackbox_home() / "network-shield" / "state.json"


def _is_ip(entry: str) -> bool:
    """True for an IP address (``normalise_entry`` stores IPs in canonical form)."""
    return ":" in entry or entry.replace(".", "").isdigit()


def _ips(entries: Iterable[str]) -> list[str]:
    return [entry for entry in entries if _is_ip(entry)]


def _names(entries: Iterable[str]) -> list[str]:
    return [entry for entry in entries if not _is_ip(entry)]


#: The last plan built, by what it was built from (a plan over ~1.2M names costs seconds to sort
#: and hash; the enforcer asks every 15 s, so it is built once per change, not once per ask).
_plan_cache: dict[str, Any] = {"key": None, "plan": None}
#: How many spared verified names a plan reports (the count is what matters; names are a sample).
MAX_SPARED = 200


def plan(mode: ShieldMode, indicators: Optional[Any], have: str = "", cut_ips: Iterable[str] = (),
         syncing: bool = False) -> dict[str, Any]:
    """What the enforcer must apply now under *mode*, given the verified graph's *indicators*
    (``ruleset.network_indicators()``; None before the graph is synced) and *cut_ips* (the listed
    addresses this machine is connected to right now — the API reads them from the monitor only
    while ``cut`` is on). *syncing*: this node is still downloading the graph, so lists read from
    every asset it holds so far are NOT the whole graph (KI-683). Built once per change
    (:data:`_plan_cache`); ``have`` equal to its version answers ``unchanged``."""
    chosen_lists = tuple(sorted(mode_module.option(mode, mode_module.OPT_LISTS)))
    cut = tuple(sorted(set(cut_ips)))
    key = (json.dumps(mode.as_json(include_personal=True), sort_keys=True), id(indicators),
           getattr(indicators, "built_at", None), tuple((pack_id, blocklists.version(pack_id)) for pack_id in chosen_lists), cut,
           remote_lock.version(mode.enabled), syncing)
    with _lock:
        cached = _plan_cache["plan"] if _plan_cache["key"] == key else None
    if cached is None:
        cached = _build_plan(mode, indicators, cut, syncing)
        with _lock:
            _plan_cache["key"], _plan_cache["plan"] = key, cached
    if have and have == cached["version"]:
        return {"version": cached["version"], "unchanged": True}
    return cached


def firewall_ips(mode: ShieldMode, listed_ips: Iterable[str]) -> frozenset[str]:
    """What the Threat Firewall drops under *mode*: the public addresses of *listed_ips* (the
    verified graph's) but the never-block ones and the person's allow list (``never_block``,
    KI-674), and every address on the person's own block list (theirs: never overridden)."""
    drop, _spared = never_block.split_ips(public_only(listed_ips), mode_module.option(mode, mode_module.OPT_ALLOW))
    return frozenset(drop) | frozenset(_ips(mode_module.option(mode, mode_module.OPT_BLOCK)))


class _GraphPart(NamedTuple):
    """The verified graph's share of a plan under one allow list: the domains refused and spared,
    the addresses dropped (before the person's own block list) and spared."""

    verified: list[str]
    spared_verified: list[str]
    dropped: frozenset[str]
    spared_ips: list[str]


_graph_cache: dict[str, Any] = {"key": None, "part": None}


def _graph_part(indicators: Optional[Any], allowed: set[str], dns_on: bool, firewall_on: bool) -> _GraphPart:
    """:class:`_GraphPart` for *indicators*, worked out once per graph build and allow list.

    WHY kept (KI-701, macOS round R8): a person's new DNS block reached DNS Shield only 1–3 minutes
    later. Every settings change rebuilt the whole plan, and with a complete graph that means judging
    ~1.16 M verified domains against the never-block list again — a block-list change does not
    change that part. Only the person's own lists are worked out again now."""
    key = (id(indicators), getattr(indicators, "built_at", None), tuple(sorted(allowed)), dns_on, firewall_on)
    with _lock:
        if _graph_cache["key"] == key:
            return _graph_cache["part"]
    verified, spared_verified = never_block.split(indicators.domains if dns_on and indicators else (), allowed)
    ips = public_only(indicators.ips if indicators else ()) if firewall_on else []
    drop, spared_ips = never_block.split_ips(ips, allowed)
    part = _GraphPart(verified, spared_verified, frozenset(drop), list(spared_ips))
    with _lock:
        _graph_cache["key"], _graph_cache["part"] = key, part
    return part


def _build_plan(mode: ShieldMode, indicators: Optional[Any], cut_ips: tuple[str, ...] = (), syncing: bool = False) -> dict[str, Any]:
    protections = mode_module.protections(mode)
    dns_on, firewall_on = mode_module.DNS in protections, mode_module.FIREWALL in protections
    cut_on, ssh_on = mode_module.CUT in protections, mode_module.SSH_LOCKDOWN in protections
    allowed = set(mode_module.option(mode, mode_module.OPT_ALLOW))
    block = mode_module.option(mode, mode_module.OPT_BLOCK)
    chosen = set(mode_module.option(mode, mode_module.OPT_LISTS))
    list_names: set[str] = set()
    if dns_on:
        for pack in mode_module.list_packs():
            if pack.id in chosen and pack.status == "supported":
                list_names |= blocklists.domains(pack)
    # Never refused, whatever a list or the graph says (never_block; finding 13). Spared VERIFIED
    # entries are reported in the plan, so the person sees them.
    graph = _graph_part(indicators, allowed, dns_on, firewall_on)
    verified, spared_verified = graph.verified, graph.spared_verified
    listed, _spared_lists = never_block.split(list_names, allowed)
    # Complete = every asset read AND the node done downloading (KI-683, Linux round L3: 5 minutes
    # into a first sync the plan said complete with 30,694 of ~1.16 M domains and 1 address, which
    # would have let the helper drop the lists it kept after a store reset).
    complete = bool(indicators is not None and getattr(indicators, "complete", False)) and not syncing
    dropped = graph.dropped | frozenset(_ips(block)) if firewall_on else frozenset()
    content = {
        "graph_ready": indicators is not None,
        "graph_complete": complete,
        # Fail-safe: lists read while the graph or its store is down, not read yet or only partly
        # read are not the whole truth — the helper keeps the ones it last applied and adds these
        # (helper plan.rs Kept). Only switching a protection off, or a COMPLETE list, clears.
        "keep_verified": not complete,
        "dns": {"enabled": dns_on,
                "verified": verified,
                "lists": listed,
                "spared": spared_verified[:MAX_SPARED],
                # Lock remote access: remote-control apps' relay domains refused too (remote_lock).
                "block": sorted(set(_names(block)) | set(remote_lock.relay_domains(mode.enabled))) if dns_on else []},
        "firewall": {"enabled": firewall_on, "ips": sorted(dropped),
                     # Verified addresses spared (a public resolver, the allow list): reported, never silently dropped.
                     "spared": graph.spared_ips[:MAX_SPARED] if firewall_on else [],
                     # The person's own block list is theirs: an address on it is dropped, so not "never".
                     "never_block": [ip for ip in never_block.never_dropped(allowed) if ip not in dropped] if firewall_on else []},
        "cut": {"enabled": cut_on, "ips": never_block.split_ips(public_only(cut_ips), allowed)[0] if cut_on else []},
        "ssh": {"lockdown": ssh_on, "allow": sorted(mode_module.option(mode, mode_module.OPT_SSH_ALLOW)) if ssh_on else []},
        "watch": mode.enabled,
        "remote": remote_lock.plan_part(mode.enabled),
        "allow": sorted(allowed),
    }
    return {"version": _version(content), "unchanged": False, **content}


def _version(content: Mapping[str, Any]) -> str:
    """The SHA-256 of *content*'s sorted-key JSON text, hashed chunk by chunk. WHY: a complete graph's
    plan is ~45 MB of JSON; serialising it whole (and encoding that copy) to hash it made a ~100 MB
    peak in the dashboard on every plan change (KI-675). The digest is the same as of the whole text."""
    digest = hashlib.sha256()
    for chunk in json.JSONEncoder(sort_keys=True).iterencode(content):
        digest.update(chunk.encode("utf-8"))
    return digest.hexdigest()


def _int(value: Any, field: str) -> int:
    if type(value) is not int or value < 0:
        raise ShieldApiError(400, f"{field} must be a whole number")
    return value


#: The helper's per-protection results (``protections`` in its report, helper/PLAN.md — optional,
#: additive): which it reports, and the most an error message may hold.
PROTECTION_RESULTS = ("dns", "firewall", "cut", "ssh_lockdown", "remote_lock")
MAX_ERROR = 200


def _protection_results(raw: Any) -> dict[str, dict[str, Any]]:
    """``{"dns": {"applied": bool, "error": str|None}, …}`` checked; absent → {} (older helpers)."""
    if raw is None:
        return {}
    if not isinstance(raw, dict) or not set(raw) <= set(PROTECTION_RESULTS):
        raise ShieldApiError(400, f"protections must map {', '.join(PROTECTION_RESULTS)} to their result")
    results = {}
    for name, result in raw.items():
        error = result.get("error") if isinstance(result, dict) else None
        if not isinstance(result, dict) or not isinstance(result.get("applied"), bool) or not (error is None or isinstance(error, str)):
            raise ShieldApiError(400, f"protections.{name} must be {{applied: true/false, error: text or null}}")
        results[name] = {"applied": result["applied"], "error": " ".join(error.split())[:MAX_ERROR] if error else None}
    return results


#: How the helper authenticated (helper/PLAN.md): signed plans, a pre-key helper, or a bad key.
AUTH_STATES = ("signed", "legacy", "broken")
MAX_ERROR_TEXT = 300


def _health(body: Mapping[str, Any]) -> dict[str, Any]:
    """The helper's wave-2 health fields, validated (all optional: older helpers send none)."""
    auth = body.get("auth")
    if auth is not None and auth not in AUTH_STATES:
        raise ShieldApiError(400, f"auth must be one of {', '.join(AUTH_STATES)}")
    health: dict[str, Any] = {"auth": auth}
    for flag in ("pf_enabled", "resolver_ok"):
        value = body.get(flag)
        if value is not None and not isinstance(value, bool):
            raise ShieldApiError(400, f"{flag} must be true or false")
        health[flag] = value
    error = body.get("last_error")
    if error is not None and not isinstance(error, str):
        raise ShieldApiError(400, "last_error must be text")
    health["last_error"] = error[:MAX_ERROR_TEXT] if error else None
    return health


def record_report(body: Mapping[str, Any], now: Optional[float] = None) -> dict[str, Any]:
    """Validates and stores one enforcer report; answers the stored summary."""
    now = time.time() if now is None else now
    for flag in ("running", "dns_active", "firewall_active"):
        if not isinstance(body.get(flag), bool):
            raise ShieldApiError(400, f"{flag} must be true or false")
    for flag in ("cut_active", "ssh_lockdown_active"):   # optional: helpers before these protections
        if not isinstance(body.get(flag, False), bool):
            raise ShieldApiError(400, f"{flag} must be true or false")
    results = _protection_results(body.get("protections"))
    health = _health(body)
    snapshot, watched = watch.validate(body, now)
    remote = remote_access.validate(body.get("remote"), now)   # before anything is stored: one bad part refuses all
    looked_up = resolved.validate(body.get("resolved"), now)
    raw_blocks = body.get("blocks", [])
    if not isinstance(raw_blocks, list) or len(raw_blocks) > MAX_BLOCKS_PER_REPORT:
        raise ShieldApiError(400, f"blocks must be a list of at most {MAX_BLOCKS_PER_REPORT}")
    blocks = []
    for item in raw_blocks:
        name = mode_module.normalise_entry(item.get("domain")) if isinstance(item, dict) else None
        if name is None or item.get("list") not in LISTS:
            raise ShieldApiError(400, "each block names a domain and its list (verified, lists or block)")
        blocks.append({"domain": name, "list": item["list"], "count": max(1, min(_int(item.get("count", 1), "count"), 1_000_000)),
                       "ts": float(min(now, _int(item.get("ts", int(now)), "ts")))})
    with _lock:
        state = read_state()
        counts: dict[str, dict[str, Any]] = state.get("counts", {})
        for block in blocks:
            entry = counts.setdefault(block["domain"], {"list": block["list"], "count": 0, "last": 0.0})
            entry["count"] += block["count"]
            entry["last"] = max(entry["last"], block["ts"])
        busiest = sorted(counts.items(), key=lambda item: -item[1]["count"])[:MAX_COUNTED]
        recent = (blocks[::-1] + state.get("recent", []))[:MAX_RECENT]
        state = {
            "enforcer": {"running": body["running"], "dns_active": body["dns_active"],
                         "firewall_active": body["firewall_active"], "cut_active": body.get("cut_active", False),
                         "ssh_lockdown_active": body.get("ssh_lockdown_active", False), "version": str(body.get("version") or "")[:64],
                         "protections": results, **health, "reported_at": now},
            "queries": _int(body.get("queries", 0), "queries"),
            "firewall_dropped": _int(body.get("firewall_dropped", 0), "firewall_dropped"),
            "blocked_total": state.get("blocked_total", 0) + sum(block["count"] for block in blocks),
            "counts": dict(busiest), "recent": recent,
        }
        write_json_object(_state_path(), state, what="Network Shield's enforcer state")
    watch.record(snapshot, watched)
    resolved.record(looked_up)   # memory only (privacy: a browsing history never reaches the disk)
    remote_access.record(remote, now)
    remote_lock.check_failures(now)   # brute-force auto-block (opt-in) reads the failed logins just kept
    return summary(state, now)


def read_state() -> dict[str, Any]:
    """The stored state (empty when the enforcer never reported)."""
    return read_json_object(_state_path()) or {}


def summary(state: Optional[Mapping[str, Any]] = None, now: Optional[float] = None) -> dict[str, Any]:
    """The enforcer's status for the card and the app: is it running, and what it blocked."""
    state = read_state() if state is None else state
    now = time.time() if now is None else now
    enforcer = state.get("enforcer") or {}
    fresh = bool(enforcer) and now - float(enforcer.get("reported_at", 0)) < STALE_AFTER_SECONDS
    return {
        "installed": bool(enforcer),
        "running": fresh and bool(enforcer.get("running")),
        "dns_active": fresh and bool(enforcer.get("dns_active")),
        "firewall_active": fresh and bool(enforcer.get("firewall_active")),
        "cut_active": fresh and bool(enforcer.get("cut_active")),
        "ssh_lockdown_active": fresh and bool(enforcer.get("ssh_lockdown_active")),
        # Lock remote access is reported in the helper's remote-watch part (its own freshness).
        "remote_lock_active": remote_access.lock_active(now),
        # Why a protection is not applied, as the helper said (fresh reports only; helper/PLAN.md).
        "errors": {name: result["error"] for name, result in (enforcer.get("protections") or {}).items()
                   if fresh and not result.get("applied") and result.get("error")},
        # The helper's own health (fresh reports only): how it authenticated, its last error,
        # whether pf is really enabled and its resolver answers (None = it did not say).
        "auth": enforcer.get("auth") if fresh else None,
        "last_error": enforcer.get("last_error") if fresh else None,
        "pf_enabled": enforcer.get("pf_enabled") if fresh else None,
        "resolver_ok": enforcer.get("resolver_ok") if fresh else None,
        "cut_total": watch.cut_total(),
        "reported_at": enforcer.get("reported_at"),
        "queries": state.get("queries", 0),
        "firewall_dropped": state.get("firewall_dropped", 0),
        "blocked_total": state.get("blocked_total", 0),
    }


def recent_blocks(limit: int = 100) -> list[dict[str, Any]]:
    """The latest refused names, newest first."""
    return list(read_state().get("recent", []))[:max(0, limit)]


def top_blocked(limit: int = 20) -> list[dict[str, Any]]:
    """The most often refused names, busiest first."""
    counts = read_state().get("counts", {})
    return [{"domain": name, **entry} for name, entry in list(counts.items())[:max(0, limit)]]
