"""Network Shield's Linux monitor (``shields/network/monitor/platform/linux.py``, Linux deep
layers step 3) renders ``ss`` and the kernel's routing tables into the macOS tools' formats, so the monitor's existing
parsers read Linux unchanged.

Contract, on ss output in iproute2 6.x's format and the kernel's routing tables (``fixtures/linux_monitor/``; the module is
loaded by path, so this runs on every OS): connections parse through ``nettop.parse`` with the
right process, state, direction, bytes and QUIC label; listeners through ``listening.parse`` with
every-interface and loopback told apart; gateways through ``gateways.parse``; and executables are
read from ``/proc`` links, falling back to the argv path for another user's process.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

from plugins.blackbox.shields.network.monitor import gateways, listening, nettop

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = Path(__file__).resolve().parent / "fixtures" / "linux_monitor"


def _load():
    spec = importlib.util.spec_from_file_location("blackbox_monitor_linux", ROOT / "plugins/blackbox/shields/network/monitor/platform/linux.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module   # its dataclass looks its module up by name
    spec.loader.exec_module(module)
    return module


linux = _load()


def _fixture(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def test_connections_parse_through_nettops_parser_per_process():
    processes = {process.pid: process for process in nettop.parse(linux.render_connections(_fixture("ss_tuanpiH.txt")))}
    assert set(processes) == {2300, 3100, 3300, 4100}, "sockets with no visible owner are left out"
    git = processes[3300]
    assert git.name == "git-remote-http" and git.bytes_in == 58211 and git.bytes_out == 1820
    (connection,) = git.connections
    assert (connection.protocol, connection.remote_ip, connection.remote_port, connection.state, connection.direction) == (
        "tcp4", "140.82.112.4", 443, "Established", "out")


def test_a_connection_to_a_listening_port_is_inbound_and_loopback_is_kept_apart():
    processes = {process.pid: process for process in nettop.parse(linux.render_connections(_fixture("ss_tuanpiH.txt")))}
    (inbound,) = processes[3100].connections
    assert inbound.direction == "in" and inbound.local_port == 8080 and inbound.remote_ip == "192.168.64.1"
    local = processes[4100]
    assert local.connections[0].local and local.bytes_in == 0 and local.local_bytes_in == 120


def test_ipv6_and_quic_rows_read_with_their_protocol():
    firefox = next(process for process in nettop.parse(linux.render_connections(_fixture("ss_tuanpiH.txt"))) if process.pid == 2300)
    by_protocol = {connection.protocol: connection for connection in firefox.connections}
    assert set(by_protocol) == {"tcp6", "quic4"}, "the unconnected mDNS socket is left out"
    assert by_protocol["tcp6"].remote_ip == "2606:4700::1111" and by_protocol["tcp6"].bytes_in == 4400
    assert by_protocol["quic4"].remote_ip == "142.250.74.46" and by_protocol["quic4"].remote_port == 443


def test_listeners_parse_through_lsofs_parser():
    found = listening.parse(linux.render_listeners(_fixture("ss_ltnpH.txt")))
    assert {(l.address, l.port) for l in found[900]} == {("*", 22)}, "0.0.0.0 and [::] both read as every interface"
    assert found[900][0].open_to_network
    assert [(l.address, l.port, l.open_to_network) for l in found[700]] == [("[::1]", 631, False)]
    assert [(l.address, l.open_to_network) for l in found[612]] == [("127.0.0.53", False)], "the %lo suffix is dropped"
    assert found[1500] == found[1501], "a shared socket is listed under each process, as lsof does"
    assert 5000 not in {l.port for listeners in found.values() for l in listeners}, "no visible owner, not listed"


def test_gateways_parse_through_netstats_parser():
    table = linux.render_routes(_fixture("proc_net_route.txt"), _fixture("proc_net_ipv6_route.txt"))
    assert gateways.parse(table) == frozenset({"192.168.64.1", "fe80::1"}), "gateway-less defaults (VPN, unreachable) name none"


def test_executables_come_from_proc_links_then_the_argv_path(tmp_path):
    proc = tmp_path / "proc"
    for pid in (10, 11, 12):
        (proc / str(pid)).mkdir(parents=True)
    os.symlink("/usr/bin/anydesk (deleted)", proc / "10" / "exe")
    (proc / "11" / "cmdline").write_bytes(b"/usr/sbin/sshd\0-D\0")          # root's: exe unreadable
    (proc / "12" / "cmdline").write_bytes(b"bash\0")                         # neither: left out
    assert linux.process_paths(proc_root=str(proc)) == "10 /usr/bin/anydesk\n11 /usr/sbin/sshd\n"


def test_nothing_readable_renders_to_nothing():
    assert nettop.parse(linux.render_connections("")) == []
    assert linux.render_listeners("") == "" and linux.render_routes("", "") == ""


def test_the_routing_table_is_read_from_the_kernels_tables(tmp_path):
    (tmp_path / "net").mkdir()
    (tmp_path / "net" / "route").write_text(_fixture("proc_net_route.txt"), encoding="utf-8")
    assert gateways.parse(linux.routing_table(proc_root=str(tmp_path))) == frozenset({"192.168.64.1"})
    assert linux.routing_table(proc_root=str(tmp_path / "none")) == ""
