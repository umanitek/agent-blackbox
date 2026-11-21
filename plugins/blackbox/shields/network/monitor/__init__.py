"""Network Shield's monitor: which apps and AI agents talk to which servers, live.

One :func:`read` combines three read-only, unprivileged sources into a :class:`Reading`:

* per-process connections, byte counts, TCP state and direction (``nettop`` on macOS —
  :mod:`.nettop`; a connection on a port this machine listens on is inbound);
* the process table — CPU and memory per process, and the tree, so a connection a child of an AI agent makes (a ``node`` or ``curl`` it
  started) is attributed to that agent, and Blackbox's own processes are labelled
  (:mod:`.processes`);
* the verified graph's malicious IP list (handed in — the shield never reads the graph itself):
  every remote address is checked with one set lookup, so every connection is checked on every
  reading. A match is shown, never acted on here; the Threat Firewall is what blocks.

Rates (bytes per second) are worked out PER CONNECTION against the previous reading (kept in
this process), then summed apart: internet (every non-loopback connection) and local (loopback —
this machine's own services talking to each other, counted at both ends, so never internet).

Pattern: Pipeline (read -> attribute -> check -> rate), each step a small pure function.

Usage::

    reading = read(malicious_ips=frozenset({"45.130.148.102"}))
    reading.as_json()     # {"taken_at": ..., "processes": [...], "threats": 0, ...}
"""

from __future__ import annotations

import threading
import time
from dataclasses import replace
from typing import AbstractSet

from . import nettop
from .processes import ProcessTree, classify
from .records import Connection, ProcessTraffic, Reading

__all__ = ["Connection", "ProcessTraffic", "ProcessTree", "Reading", "classify", "read", "with_rates"]

_previous_lock = threading.Lock()
_previous: dict[str, object] = {"at": 0.0, "bytes": {}}
#: The longest gap between two readings a rate is worked out over (longer: start again).
MAX_RATE_GAP_SECONDS = 120


def read(malicious_ips: AbstractSet[str] = frozenset()) -> Reading:
    """One reading of this machine, with each remote address checked against *malicious_ips*."""
    now = time.time()
    reason = nettop.available()
    if reason:
        return Reading(taken_at=now, available=False, reason=reason)
    tree = ProcessTree.read()
    processes = [_attributed(process, tree, malicious_ips) for process in nettop.read()]
    processes = with_rates(processes, now)
    processes.sort(key=lambda p: (not p.agent, -(p.rate_in + p.rate_out), -(p.bytes_in + p.bytes_out)))
    threats = len({c.remote_ip for p in processes for c in p.connections if c.threat})
    inbound = sum(1 for p in processes for c in p.connections if c.direction == "in" and not c.local)
    total = sum(1 for p in processes for c in p.connections if not c.local)   # loopback is not the network
    return Reading(taken_at=now, available=True, processes=tuple(processes), threats=threats,
                   connections_in=inbound, connections_out=total - inbound,
                   rate_in=sum(p.rate_in for p in processes), rate_out=sum(p.rate_out for p in processes),
                   local_rate_in=sum(p.local_rate_in for p in processes), local_rate_out=sum(p.local_rate_out for p in processes))


def _attributed(process: ProcessTraffic, tree: ProcessTree, malicious_ips: AbstractSet[str]) -> ProcessTraffic:
    connections = tuple(replace(c, threat="verified threat graph") if c.remote_ip.lower() in malicious_ips else c
                        for c in process.connections)
    return replace(process, agent=tree.agent_of(process.pid), blackbox=tree.is_blackbox(process.pid),
                   connections=connections, cpu=tree.cpu.get(process.pid, 0.0), memory_bytes=tree.memory.get(process.pid, 0))


def _key(pid: int, c: Connection) -> tuple:
    return (pid, c.protocol, c.local_port, c.remote_ip, c.remote_port, c.direction)


def with_rates(processes: list[ProcessTraffic], now: float) -> list[ProcessTraffic]:
    """Each connection with its bytes per second since the previous call (0 for a new one), and
    each process with its internet and local rates — the sums over its connections."""
    with _previous_lock:
        elapsed = now - float(_previous["at"])
        before: dict = _previous["bytes"]   # type: ignore[assignment]
        _previous["at"] = now
        _previous["bytes"] = {_key(p.pid, c): (c.bytes_in, c.bytes_out) for p in processes for c in p.connections}
    if elapsed <= 0 or elapsed > MAX_RATE_GAP_SECONDS:
        return processes
    rated = []
    for process in processes:
        connections = []
        for c in process.connections:
            old_in, old_out = before.get(_key(process.pid, c), (c.bytes_in, c.bytes_out))
            connections.append(replace(c, rate_in=max(0, int((c.bytes_in - old_in) / elapsed)),
                                       rate_out=max(0, int((c.bytes_out - old_out) / elapsed))))
        internet = [c for c in connections if not c.local]
        local = [c for c in connections if c.local]
        rated.append(replace(process, connections=tuple(connections),
                             rate_in=sum(c.rate_in for c in internet), rate_out=sum(c.rate_out for c in internet),
                             local_rate_in=sum(c.rate_in for c in local), local_rate_out=sum(c.rate_out for c in local)))
    return rated
