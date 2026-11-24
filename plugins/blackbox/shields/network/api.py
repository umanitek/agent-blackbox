"""Network Shield's API — the core: what the shield decides, detects and is told.

Served at ``/api/shields/network-shield/api/<name>`` (``dashboard/shields_routes/api_routes.py``).
An add-on registered beside the plugin may add richer views (more endpoints, a live collector's
feeds) through the extension point (``ShieldExtension.api``); these paths and their JSON are the
contract a companion app's screens use.

Reads (``GET``):
  ``overview``     the mode, its protections, the helper's status, list sizes, the busiest refused
                   names, the latest alerts, whether the helper is installed and an add-on registered
  ``connections``  one network monitor reading (apps, connections in and out, internet rates with
                   this machine's own local traffic kept apart, threats — public addresses only;
                   each connection's ``dropped`` / ``cut``: what the Threat Firewall did to it)
  ``system``       system status: CPU, memory, disks, interfaces, uptime (:mod:`.system`)
  ``enforcement``  the helper's plan (``?have=<version>`` answers ``unchanged``)
  ``blocks``       the latest refused names
  ``ssh``          Remote Login, open SSH sessions, the watched login files, the latest watch events
  ``remote-access`` who is in this machine and how: live sessions, failed logins, the remote-access
                   services, remote-control apps and tunnels, the lock and blocked addresses
  ``address``      ``?ip=``: the name DNS Shield saw that address looked up as, ``country`` /
                   ``network`` "unknown" (:mod:`.monitor.resolved`; memory only, no outside lookups)
  ``system-plan`` · ``exposure`` · ``posture``  the system watch (:mod:`.system_api`)

Writes (``POST``, the dashboard's token):
  ``enforcer-report``  the helper's report (running state, counters, refused names, watch events)
  ``observed-connection``  a connection a live collector (an add-on) saw:
                   ``{pid, program, remote_ip, remote_port, ts}`` — Network Shield decides whether
                   the address is listed, keeps it and words the notice
  ``end-session`` · ``block-address`` · ``unblock-address`` · ``remote-settings``  remote access
  ``system-report`` · ``posture-fix`` · ``posture-refresh`` · ``tamper-guard``  the system watch

The live reads run only while the shield is on (409 otherwise: the shield is opt-in, and off it
watches nothing). The helper's own endpoints answer off too, with an all-off plan.
"""

from __future__ import annotations

import ipaddress
import time
from typing import Any, Callable, Mapping

from .. import extensions
from ..shield_api import ShieldApi, ShieldApiError, ShieldContext
from . import helper, mode as mode_module, monitor, system, system_api
from .. import helper_link
from .addresses import public_only
from .monitor import remote_access, resolved, watch
from .protect import connection_state, enforcement, remote_lock, weakening
from .respond import sessions, system_alerts

OFF = "Switch Network Shield on to see this machine's network."
#: Alerts in the overview (newest first).
MAX_ALERTS = 20


def require_on() -> Any:
    """The current mode, or a 409 while the shield is off (a live read never runs off)."""
    current = mode_module.current()
    if not current.enabled:
        raise ShieldApiError(409, OFF)
    return current


def malicious_ips(context: ShieldContext) -> frozenset[str]:
    """The verified graph's malicious addresses known now (public ones only; never waits)."""
    indicators = context.indicators_now()
    return public_only(indicators.ips) if indicators is not None else frozenset()


def alerts(limit: int = MAX_ALERTS) -> list[dict[str, Any]]:
    """The shield's latest alerts — SSH and login files, remote access, the system watch — newest first."""
    merged = watch.alerts(limit) + remote_access.alerts(limit) + system_alerts.alerts(limit)
    return sorted(merged, key=lambda alert: -float(alert["ts"]))[:limit]


def _syncing(context: ShieldContext) -> bool:
    """True while this node is still downloading the threat graph — the ONE answer the overview and
    the helper's plan both use (KI-683)."""
    return (context.graph_sync_state() if context.graph_sync_state else "") == "syncing"


def _graph_state(context: ShieldContext, indicators: Any) -> dict[str, Any]:
    """The threat graph as the overview reports it. *ready*: lists are in hand AND the graph can be
    read now; *keeping_last_lists*: the graph is down, so DNS Shield and the firewall keep the lists
    they last applied (the helper's keep rule) — said plainly, never shown as ready (E2E recheck
    2026-11-21)."""
    reachable = context.graph_reachable() if context.graph_reachable else None
    have = indicators is not None
    # "complete" is the WHOLE graph: lists read from every asset this node holds AND the node no
    # longer downloading. WHY (KI-533, E2E full3): during a first sync it said complete with 8,820
    # of ~1.16 M domains, because every asset downloaded SO FAR had been read.
    syncing = _syncing(context)
    # *loading*: no lists read yet (a dashboard restart reads them in the background) — a page says
    # "loading", never "0 domains and 0 addresses" while protection is intact (KI-538).
    return {"ready": have and reachable is not False, "reachable": reachable, "loading": not have,
            "keeping_last_lists": have and reachable is False, "syncing": syncing,
            "complete": bool(indicators and indicators.complete) and not syncing,
            "domains": len(indicators.domains) if indicators else 0,
            "ips": len(indicators.ips) if indicators else 0}


def overview(context: ShieldContext, _params: Mapping[str, str]) -> dict[str, Any]:
    current = mode_module.current()
    indicators = context.indicators_now()   # never waits: the first build runs in the background
    return {
        "mode": current.as_json(),
        "protections": list(mode_module.protections(current)),
        "blocking": context.blocking,
        "helper": helper.installed(),
        "addons": bool(extensions.providers()),
        "enforcer": enforcement.summary(),
        "graph": _graph_state(context, indicators),
        "top_blocked": enforcement.top_blocked(),
        "alerts": alerts(),
    }


def connections(context: ShieldContext, _params: Mapping[str, str]) -> Any:
    """One monitor reading; each connection says whether the Threat Firewall drops it or it was
    cut (``dropped`` / ``cut``, :mod:`.protect.connection_state`)."""
    current = require_on()
    listed = malicious_ips(context)
    return connection_state.with_enforcement(monitor.read(listed), current, listed).as_json()


def system_status(_context: ShieldContext, _params: Mapping[str, str]) -> dict[str, Any]:
    require_on()
    return system.reading()


def _connected_threats(context: ShieldContext, current: Any) -> frozenset[str]:
    """The listed addresses this machine is connected to now — read only while ``cut`` is on."""
    if mode_module.CUT not in mode_module.protections(current):
        return frozenset()
    reading = monitor.read(malicious_ips(context))
    return frozenset(c.remote_ip for process in reading.processes for c in process.connections if c.threat)


def enforcement_plan(context: ShieldContext, params: Mapping[str, str]) -> Any:
    """The helper's DNS / firewall / cut / SSH plan, signed for the helper's nonce (helper_link):
    a keyed helper obeys only a plan signed with its key, so an unsigned answer applies nothing."""
    current = mode_module.current()
    plan = enforcement.plan(current, context.network_indicators(), have=str(params.get("have") or "")[:64],
                            cut_ips=_connected_threats(context, current), syncing=_syncing(context))
    return helper_link.signed(plan, params)


def blocks(_context: ShieldContext, params: Mapping[str, str]) -> dict[str, Any]:
    limit = int(params["limit"]) if str(params.get("limit", "")).isdigit() else 100
    return {"recent": enforcement.recent_blocks(min(limit, enforcement.MAX_RECENT)), "top": enforcement.top_blocked()}


def ssh(_context: ShieldContext, _params: Mapping[str, str]) -> dict[str, Any]:
    require_on()
    return watch.ssh_view()


def enforcer_report(context: ShieldContext, body: Mapping[str, Any]) -> dict[str, Any]:
    helper_link.require_signed_report(context)   # once paired, only this Mac's helper may report
    return enforcement.record_report(body)


def observed_connection(context: ShieldContext, body: Mapping[str, Any]) -> dict[str, Any]:
    """A connection a live collector (an add-on) saw. WHY a collector and not the core: the
    core's own reading (:func:`connections`, nettop + ps) takes seconds and runs with the plan; a
    collector may read the sockets natively and far more often. It only reports facts — whether
    the address is listed, and what the person is told, is decided here."""
    require_on()
    event = watch.observed(body, malicious_ips(context), time.time())
    if event is None:
        return {"recorded": False}
    watch.record(None, [event])
    return {"recorded": True}


#: What the core says about an address's country and network: it has no source for them, and
#: asking an outside service would tell it which addresses this machine talks to (privacy).
UNKNOWN = "unknown"


def address(_context: ShieldContext, params: Mapping[str, str]) -> dict[str, Any]:
    """``address?ip=<ip>``: the name DNS Shield saw it looked up as (KI-588 c) —
    ``{ip, domain, seen_at, source, country, network}``; ``domain`` "" and ``source`` "" when no
    lookup through DNS Shield gave it; country and network are always "unknown" (no source, and no
    outside lookups). 400 for something that is not an IP address."""
    require_on()
    try:
        ip = str(ipaddress.ip_address(str(params.get("ip") or "")[:64]))
    except ValueError:
        raise ShieldApiError(400, "ip must be an IP address") from None
    found = resolved.lookup(ip)
    return {"ip": ip, "domain": found.domain if found else "", "seen_at": found.seen_at if found else None,
            "source": "dns-shield" if found else "", "country": UNKNOWN, "network": UNKNOWN}


def remote(_context: ShieldContext, _params: Mapping[str, str]) -> dict[str, Any]:
    require_on()
    return {**remote_access.view(), **remote_lock.settings()}


def _remote_write(action: Callable[[Mapping[str, Any]], Any]) -> Callable[[ShieldContext, Mapping[str, Any]], Any]:
    def write(_context: ShieldContext, body: Mapping[str, Any]) -> Any:
        require_on()
        return action(body)
    return write


API = ShieldApi(
    reads={"overview": overview, "connections": connections, "system": system_status, "enforcement": enforcement_plan,
           "blocks": blocks, "ssh": ssh, "remote-access": remote, "address": address, **system_api.READS},
    writes={"enforcer-report": enforcer_report, "observed-connection": observed_connection,
            "end-session": _remote_write(sessions.end_session), "block-address": _remote_write(sessions.block_address),
            "unblock-address": _remote_write(sessions.unblock_address),
            "remote-settings": _remote_write(sessions.remote_settings), **system_api.WRITES},
    weakening=weakening.JUDGES,   # the writes that turn protection down wait for the person
)
