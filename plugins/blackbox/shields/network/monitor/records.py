"""The network monitor's records: one connection, one process with its connections, one reading.

Frozen dataclasses with ``as_json()`` (the shields' record convention), so the monitor's
reading crosses to the dashboard and any companion app as plain JSON.
"""

from __future__ import annotations

from dataclasses import dataclass

from ...json_records import JsonValue, _record_json


@dataclass(frozen=True)
class Connection:
    """One connection of a process: *protocol* is ``tcp4``/``tcp6``/``udp4``/``udp6``, or
    ``quic4``/``quic6`` for QUIC (HTTP/3, carried over UDP);
    *threat* names the verified graph's listing of the remote address ("" when none).

    *direction* is ``in`` when the remote side opened it (its local port is one this machine
    listens on), else ``out``; *state* is TCP's (``Established``, ``SynSent``, …; "" for UDP).
    *local* is True for a loopback connection (127.0.0.0/8, ::1): this machine talking to itself,
    never internet traffic. *rate_in* / *rate_out* are its bytes per second since the last reading.
    *dropped*: the Threat Firewall is applied and drops this remote address; *cut*: the helper cut
    a connection to it lately (``protect.connection_state``, KI-588) — both False otherwise.
    """

    protocol: str
    remote_ip: str
    remote_port: int
    bytes_in: int
    bytes_out: int
    threat: str = ""
    local_port: int = 0
    state: str = ""
    direction: str = "out"
    local: bool = False
    rate_in: int = 0
    rate_out: int = 0
    dropped: bool = False
    cut: bool = False

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)


@dataclass(frozen=True)
class ProcessTraffic:
    """One process with network activity.

    *agent* is the AI agent it belongs to (itself or an ancestor, "Claude Code"), "" for none;
    *blackbox* marks Blackbox's own processes (its DKG node, graph store and engine);
    *cpu* is its CPU use in percent of one core and *memory_bytes* its resident memory (``ps``).
    *bytes_in* / *bytes_out* are its internet bytes since it started (the operating system's count
    minus its open loopback connections); *rate_in* / *rate_out* its internet bytes per second
    since the previous reading, summed over its non-loopback connections (0 on the first one).
    The ``local_`` counterparts are its loopback traffic — this machine talking to itself.
    """

    pid: int
    name: str
    bytes_in: int
    bytes_out: int
    rate_in: int = 0
    rate_out: int = 0
    agent: str = ""
    blackbox: bool = False
    connections: tuple[Connection, ...] = ()
    cpu: float = 0.0
    memory_bytes: int = 0
    local_bytes_in: int = 0
    local_bytes_out: int = 0
    local_rate_in: int = 0
    local_rate_out: int = 0

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)


@dataclass(frozen=True)
class Reading:
    """One reading of the whole machine.

    *taken_at* is unix seconds; *available* is False (with *reason*) where the monitor cannot
    read this operating system yet; *threats* counts distinct listed remote addresses;
    *connections_in* / *connections_out* count connections by who opened them; *rate_in* /
    *rate_out* are the whole machine's INTERNET bytes per second and *local_rate_in* /
    *local_rate_out* its loopback ones (never added together: a loopback byte is counted at both ends).
    """

    taken_at: float
    available: bool
    reason: str = ""
    processes: tuple[ProcessTraffic, ...] = ()
    threats: int = 0
    connections_in: int = 0
    connections_out: int = 0
    rate_in: int = 0
    rate_out: int = 0
    local_rate_in: int = 0
    local_rate_out: int = 0

    def as_json(self) -> dict[str, JsonValue]:
        return _record_json(self)
