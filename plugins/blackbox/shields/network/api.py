"""Network Shield's own API in the public plugin — what works without Blackbox Desktop.

Served at ``/api/shields/network-shield/api/<name>`` (``dashboard/shields_routes/api_routes.py``):

Reads (``GET``):
  ``overview``     the mode, its protections, the verified graph's list sizes, and whether Blackbox
                   Desktop is installed (``desktop``)
  ``connections``  one network monitor reading: the apps online, their connections in and out,
                   internet rates with this machine's own local traffic kept apart, and each
                   remote address checked against the verified graph (public addresses only)
  ``system``       system status: CPU (total, per core, load), memory, swap, disks, disk and
                   per-interface rates, uptime, processes, battery (:mod:`.system`)

Blackbox Desktop's add-on adds its own endpoints and a fuller ``overview`` / ``connections``
(``ShieldExtension.api``). The live reads run only while the shield is on (409 otherwise: the
shield is opt-in, and off it watches nothing).
"""

from __future__ import annotations

from typing import Any, Mapping

from .. import extensions
from ..shield_api import ShieldApi, ShieldApiError, ShieldContext
from . import mode as mode_module, monitor, system
from .addresses import public_only

OFF = "Switch Network Shield on to see this machine's network."


def _on() -> Any:
    current = mode_module.current()
    if not current.enabled:
        raise ShieldApiError(409, OFF)
    return current


def malicious_ips(context: ShieldContext) -> frozenset[str]:
    """The verified graph's malicious addresses known now (public ones only; never waits)."""
    indicators = context.indicators_now()
    return public_only(indicators.ips) if indicators is not None else frozenset()


def overview(context: ShieldContext, _params: Mapping[str, str]) -> dict[str, Any]:
    current = mode_module.current()
    indicators = context.indicators_now()   # never waits: the first build runs in the background
    return {
        "mode": current.as_json(),
        "protections": list(mode_module.protections(current)),
        "blocking": context.blocking,
        "desktop": bool(extensions.providers()),
        "graph": {"ready": indicators is not None,
                  "complete": bool(indicators and indicators.complete),
                  "domains": len(indicators.domains) if indicators else 0,
                  "ips": len(indicators.ips) if indicators else 0},
    }


def connections(context: ShieldContext, _params: Mapping[str, str]) -> Any:
    _on()
    return monitor.read(malicious_ips(context)).as_json()


def system_status(_context: ShieldContext, _params: Mapping[str, str]) -> dict[str, Any]:
    _on()
    return system.reading()


API = ShieldApi(reads={"overview": overview, "connections": connections, "system": system_status})
