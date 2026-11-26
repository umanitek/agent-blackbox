"""Per connection: whether the Threat Firewall is dropping it and whether it was cut (KI-588 d).

The monitor's reading says which connections go to a listed address; the enforcer's report says
whether the Threat Firewall is applied (``firewall_active``) and which listed connections it cut
(``connection-cut`` watch events, by remote address). Until now a companion app saw only the two
counters (``firewall_active``, ``cut_total``) and could not say what happened to ONE connection.

* ``dropped`` — the Threat Firewall is applied now (the helper's fresh report) and the remote
  address is one the plan tells it to drop: a public address the verified graph lists, or an
  address on the person's own block list — the same set :func:`.enforcement.plan` sends.
* ``cut`` — the helper reported cutting a connection to that address within
  :data:`CUT_RECENT_SECONDS` (a cut connection is gone; one still shown was opened again).

Facts only, from what the helper reported; nothing here acts. Undo: nothing to undo (read-only).

Usage::

    marked = with_enforcement(reading, mode, malicious_ips)   # the reading, each Connection marked
"""

from __future__ import annotations

import time
from dataclasses import replace
from typing import AbstractSet, Optional

from ....shields.contract import ShieldMode
from ..monitor import Reading, watch
from . import enforcement

#: How long after the helper cut a connection to an address a connection to it counts as cut.
CUT_RECENT_SECONDS = 600
#: How many watch events are read for recent cuts (the watch keeps at most 300).
EVENTS_READ = 300


def _dropped_addresses(mode: ShieldMode, malicious_ips: AbstractSet[str]) -> frozenset[str]:
    """The addresses the Threat Firewall drops now (empty while it is not applied)."""
    if not enforcement.summary()["firewall_active"]:
        return frozenset()
    return enforcement.firewall_ips(mode, malicious_ips)


def _cut_addresses(now: float) -> frozenset[str]:
    return frozenset(str(event.get("remote_ip")) for event in watch.events(EVENTS_READ)
                     if event.get("kind") == "connection-cut" and now - float(event.get("ts") or 0) <= CUT_RECENT_SECONDS)


def with_enforcement(reading: Reading, mode: ShieldMode, malicious_ips: AbstractSet[str],
                     now: Optional[float] = None) -> Reading:
    """*reading* with each connection's ``dropped`` / ``cut`` set (see the module doc)."""
    if not reading.available:
        return reading
    now = time.time() if now is None else now
    dropped, cut = _dropped_addresses(mode, malicious_ips), _cut_addresses(now)
    if not dropped and not cut:
        return reading
    processes = tuple(replace(process, connections=tuple(
        replace(c, dropped=c.remote_ip.lower() in dropped, cut=c.remote_ip.lower() in cut) for c in process.connections))
        for process in reading.processes)
    return replace(reading, processes=processes)


__all__ = ["CUT_RECENT_SECONDS", "with_enforcement"]
