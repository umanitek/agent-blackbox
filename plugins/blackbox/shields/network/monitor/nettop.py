"""Reads per-process connections and byte counts from macOS ``nettop`` (no admin rights needed).

``nettop -L 1 -x -n -J state,bytes_in,bytes_out`` prints CSV: a header naming the columns
(``,state,bytes_in,bytes_out,``), then for each process a line ``name.pid,,bytes_in,bytes_out,``
followed by its sockets ``tcp4 192.168.1.53:65515<->142.251.211.69:443,Established,2896,2942,``.
IPv6 endpoints separate the port with a dot (``fe80::1%en0.5353``).

A socket with a ``*`` remote is left out of the connections; a TCP one in state ``Listen`` names
a port this machine serves, so a connection on that local port was opened by the other side
(``direction: in``). The parser follows the header, so the older two-column form
(``-J bytes_in,bytes_out``) still parses (no state, every connection ``out``).
"""

from __future__ import annotations

import ipaddress
from typing import Optional

from . import platform
from .records import Connection, ProcessTraffic

_PROTOCOLS = ("tcp4", "tcp6", "udp4", "udp6")


def available() -> Optional[str]:
    """None when this machine can be read, else why not (one sentence for a person)."""
    return platform.traffic_unavailable()


def read() -> list[ProcessTraffic]:
    """Reads the connection table once (:func:`platform.connection_table`) and parses it; empty
    when it cannot be read."""
    text = platform.connection_table()
    return parse(text) if text is not None else []


def parse(text: str) -> list[ProcessTraffic]:
    """Parses ``nettop`` CSV into processes that have at least one connection with a remote."""
    lines = text.splitlines()
    header = next((i for i, line in enumerate(lines) if line.startswith(",") and "bytes_in" in line), None)
    if header is None:
        return []
    columns = lines[header].strip(",").split(",")
    rows = [row for row in (_split(line, columns) for line in lines[header + 1:]) if row is not None]
    listening = {_local_port(label) for label, values in rows if values.get("state") == "Listen"}
    processes: list[tuple[int, str, int, int, list[Connection]]] = []
    for label, values in rows:
        protocol, _, endpoints = label.partition(" ")
        if protocol in _PROTOCOLS and endpoints:
            connection = _connection(protocol, endpoints, values, listening)
            if connection and processes:
                processes[-1][4].append(connection)
            continue
        name, _, pid = label.rpartition(".")
        if name and pid.isdigit():
            processes.append((int(pid), name, _number(values.get("bytes_in", "")), _number(values.get("bytes_out", "")), []))
    return [_process(pid, name, bytes_in, bytes_out, found) for pid, name, bytes_in, bytes_out, found in processes if found]


def _process(pid: int, name: str, bytes_in: int, bytes_out: int, found: list[Connection]) -> ProcessTraffic:
    """One process; its loopback bytes kept apart from its internet bytes."""
    local_in = sum(c.bytes_in for c in found if c.local)
    local_out = sum(c.bytes_out for c in found if c.local)
    return ProcessTraffic(pid=pid, name=name, bytes_in=max(0, bytes_in - local_in), bytes_out=max(0, bytes_out - local_out),
                          connections=tuple(found), local_bytes_in=local_in, local_bytes_out=local_out)


def is_loopback(address: str) -> bool:
    """True for 127.0.0.0/8, ::1 and an IPv4-mapped loopback (``::ffff:127.0.0.1``)."""
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return address == "localhost"
    mapped = getattr(ip, "ipv4_mapped", None)
    return ip.is_loopback or bool(mapped and mapped.is_loopback)


def _split(line: str, columns: list[str]) -> Optional[tuple[str, dict[str, str]]]:
    """``label,v1,v2,…,`` split from the right by the header's columns, so a label containing
    commas stays whole."""
    if not line.endswith(","):
        return None
    parts = line[:-1].rsplit(",", len(columns))
    if len(parts) != len(columns) + 1 or not parts[0]:
        return None
    return parts[0], dict(zip(columns, (value.strip() for value in parts[1:])))


def _number(text: str) -> int:
    text = text.strip()
    return int(text) if text.isdigit() else 0


def _port_of(endpoint: str, protocol: str) -> tuple[str, str]:
    """(address, port) of one endpoint; IPv6 separates the port with a dot."""
    address, _, port = endpoint.rpartition("." if protocol.endswith("6") else ":")
    return address.split("%", 1)[0], port


def _local_port(label: str) -> int:
    protocol, _, endpoints = label.partition(" ")
    _address, port = _port_of(endpoints.partition("<->")[0], protocol)
    return int(port) if port.isdigit() else -1


def _connection(protocol: str, endpoints: str, values: dict[str, str], listening: set[int]) -> Optional[Connection]:
    local, arrow, remote = endpoints.partition("<->")
    if not arrow:
        return None
    ip, port = _port_of(remote, protocol)
    if not ip or ip == "*" or not port.isdigit():
        return None
    _local_address, local_port = _port_of(local, protocol)
    local_number = int(local_port) if local_port.isdigit() else 0
    inbound = protocol.startswith("tcp") and local_number in listening
    return Connection(protocol=protocol, remote_ip=ip, remote_port=int(port),
                      bytes_in=_number(values.get("bytes_in", "")), bytes_out=_number(values.get("bytes_out", "")),
                      local_port=local_number, state=values.get("state", ""), direction="in" if inbound else "out",
                      local=is_loopback(ip))
