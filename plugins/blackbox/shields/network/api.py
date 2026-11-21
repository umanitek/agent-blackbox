"""Network Shield's API — the core: what the shield decides, detects and is told.

Served at ``/api/shields/network-shield/api/<name>`` (``dashboard/shields_routes/api_routes.py``).
Blackbox Desktop's add-on adds its richer views (every process explained, the history, the
security review, its native collector's feeds) through the extension point
(``ShieldExtension.api``); these paths and their JSON are the contract Desktop's screens use.

Reads (``GET``):
  ``overview``     the mode, its protections, the helper's status, list sizes, the busiest refused
                   names, the latest alerts, whether the helper / Blackbox Desktop are installed
  ``connections``  one network monitor reading (apps, connections in and out, internet rates with
                   this machine's own local traffic kept apart, threats — public addresses only)
  ``system``       system status: CPU, memory, disks, interfaces, uptime (:mod:`.system`)
  ``enforcement``  the helper's plan (``?have=<version>`` answers ``unchanged``)
  ``blocks``       the latest refused names
  ``ssh``          Remote Login, open SSH sessions, the watched login files, the latest watch events
  ``remote-access`` who is in this machine and how: live sessions, failed logins, the remote-access
                   services, remote-control apps and tunnels, the lock and blocked addresses
  ``system-plan`` · ``exposure`` · ``posture``  the system watch (:mod:`.system_api`)

Writes (``POST``, the dashboard's token):
  ``enforcer-report``  the helper's report (running state, counters, refused names, watch events)
  ``end-session`` · ``block-address`` · ``unblock-address`` · ``remote-settings``  remote access
  ``system-report`` · ``posture-fix`` · ``posture-refresh`` · ``tamper-guard``  the system watch

The live reads run only while the shield is on (409 otherwise: the shield is opt-in, and off it
watches nothing). The helper's own endpoints answer off too, with an all-off plan.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from .. import extensions
from ..shield_api import ShieldApi, ShieldApiError, ShieldContext
from . import helper, helper_link, mode as mode_module, monitor, system, system_api
from .addresses import public_only
from .monitor import remote_access, watch
from .protect import enforcement, remote_lock, weakening
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


def overview(context: ShieldContext, _params: Mapping[str, str]) -> dict[str, Any]:
    current = mode_module.current()
    indicators = context.indicators_now()   # never waits: the first build runs in the background
    return {
        "mode": current.as_json(),
        "protections": list(mode_module.protections(current)),
        "blocking": context.blocking,
        "helper": helper.installed(),
        "desktop": bool(extensions.providers()),
        "enforcer": enforcement.summary(),
        "graph": {"ready": indicators is not None,
                  "complete": bool(indicators and indicators.complete),
                  "domains": len(indicators.domains) if indicators else 0,
                  "ips": len(indicators.ips) if indicators else 0},
        "top_blocked": enforcement.top_blocked(),
        "alerts": alerts(),
    }


def connections(context: ShieldContext, _params: Mapping[str, str]) -> Any:
    require_on()
    return monitor.read(malicious_ips(context)).as_json()


def system_status(_context: ShieldContext, _params: Mapping[str, str]) -> dict[str, Any]:
    require_on()
    return system.reading()


def _connected_threats(context: ShieldContext, current: Any) -> frozenset[str]:
    """The listed addresses this machine is connected to now — read only while ``cut`` is on."""
    if mode_module.CUT not in mode_module.protections(current):
        return frozenset()
    reading = monitor.read(malicious_ips(context))
    return frozenset(c.remote_ip for process in reading.processes for c in process.connections if c.threat)


def enforcement_plan(context: ShieldContext, params: Mapping[str, str]) -> dict[str, Any]:
    current = mode_module.current()
    return enforcement.plan(current, context.network_indicators(), have=str(params.get("have") or "")[:64],
                            cut_ips=_connected_threats(context, current))


def blocks(_context: ShieldContext, params: Mapping[str, str]) -> dict[str, Any]:
    limit = int(params["limit"]) if str(params.get("limit", "")).isdigit() else 100
    return {"recent": enforcement.recent_blocks(min(limit, enforcement.MAX_RECENT)), "top": enforcement.top_blocked()}


def ssh(_context: ShieldContext, _params: Mapping[str, str]) -> dict[str, Any]:
    require_on()
    return watch.ssh_view()


def enforcer_report(_context: ShieldContext, body: Mapping[str, Any]) -> dict[str, Any]:
    return enforcement.record_report(body)


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
           "blocks": blocks, "ssh": ssh, "remote-access": remote, **system_api.READS},
    writes={"enforcer-report": enforcer_report,
            "end-session": _remote_write(sessions.end_session), "block-address": _remote_write(sessions.block_address),
            "unblock-address": _remote_write(sessions.unblock_address),
            "remote-settings": _remote_write(sessions.remote_settings), **system_api.WRITES},
    weakening=weakening.JUDGES,   # the writes that turn protection down wait for the person
)
