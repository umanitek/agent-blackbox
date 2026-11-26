"""Network Shield's Linux monitor (``shields/network/monitor/platform/linux.py``, Linux deep
layers step 3) renders ``ss`` and the kernel's routing tables into the macOS tools' formats, so the monitor's existing
parsers read Linux unchanged.

Contract, on REAL ss output and routing tables recorded in Linux round L2 (``fixtures/linux_monitor/``; the module is
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


#: Every fixture file is REAL output (LES-153), recorded in Linux round L2 on Ubuntu 24.04.5 / kernel
#: 7.0 / iproute2 6.x as the person: ``ss -tuanpiH``, ``ss -ltnpH``, /proc/net/route and
#: /proc/net/ipv6_route before the install (the person's own view: no process owns a socket
#: they can see), and — ``*_agents_running.txt`` — with Blackbox and four agents running (a
#: verbatim excerpt of that capture: each row with its ``-i`` information line).
#: Two forms no L2 machine showed (an owned IPv6 and QUIC row, a socket two processes share) are
#: written inline in their tests, in iproute2 6.x's format.


def _agents():
    return {process.pid: process for process in nettop.parse(linux.render_connections(_fixture("ss_tuanpiH_agents_running.txt")))}


def test_before_the_install_the_persons_own_view_names_no_process_and_reads_cleanly():
    assert nettop.parse(linux.render_connections(_fixture("ss_tuanpiH.txt"))) == [], "no socket has a visible owner"
    assert listening.parse(linux.render_listeners(_fixture("ss_ltnpH.txt"))) == {}


def test_connections_parse_through_nettops_parser_per_process():
    processes = _agents()
    assert set(processes) == {44810, 54866, 74413, 77259}, "sockets with no visible owner (sshd, TIME-WAIT) are left out"
    codex = processes[74413]
    assert codex.name == "codex" and codex.bytes_in == 64805 and codex.bytes_out == 18672, "bytes come from the -i line"
    (connection,) = codex.connections
    assert (connection.protocol, connection.remote_ip, connection.remote_port, connection.state, connection.direction) == (
        "tcp4", "172.66.0.243", 443, "Established", "out")
    assert processes[77259].name == ".cline", "a dot-named program keeps its name"


def test_a_connection_to_a_listening_port_is_inbound_and_loopback_is_kept_apart():
    processes = _agents()
    (inbound,) = processes[54866].connections                 # the dashboard, answering a hook
    assert inbound.direction == "in" and inbound.local and inbound.remote_port == 35174
    assert processes[54866].bytes_in == 0 and processes[54866].local_bytes_in == 37922
    (store,) = processes[44810].connections                    # the DKG node, talking to its store
    assert store.direction == "out" and store.local and store.remote_port == 9999


def test_ipv6_and_quic_rows_read_with_their_protocol():
    text = ("udp   ESTAB  0      0       192.168.64.5:51023     142.250.74.46:443   users:((\"firefox\",pid=2300,fd=121))\n"
            "udp   UNCONN 0      0              0.0.0.0:5353          0.0.0.0:*     users:((\"firefox\",pid=2300,fd=90))\n"
            "tcp   ESTAB  0      0      [2001:db8::5]:44322 [2606:4700::1111]:443   users:((\"firefox\",pid=2300,fd=88))\n"
            "\t cubic wscale:8,7 rto:212 bytes_sent:900 bytes_acked:901 bytes_received:4400 segs_out:12\n")
    (firefox,) = nettop.parse(linux.render_connections(text))
    by_protocol = {connection.protocol: connection for connection in firefox.connections}
    assert set(by_protocol) == {"tcp6", "quic4"}, "the unconnected mDNS socket is left out"
    assert by_protocol["tcp6"].remote_ip == "2606:4700::1111" and by_protocol["tcp6"].bytes_in == 4400
    assert by_protocol["quic4"].remote_ip == "142.250.74.46" and by_protocol["quic4"].remote_port == 443


def test_listeners_parse_through_lsofs_parser():
    found = listening.parse(linux.render_listeners(_fixture("ss_ltnpH_agents_running.txt")))
    assert set(found) == {44810, 54866}, "the unowned listeners (resolved, sshd, the store, 36815) are not listed"
    assert [(l.address, l.port, l.open_to_network) for l in found[54866]] == [("127.0.0.1", 9700, False)]
    assert ("*", 37015, True) in [(l.address, l.port, l.open_to_network) for l in found[44810]], "0.0.0.0 reads as every interface"
    shared = listening.parse(linux.render_listeners(
        'LISTEN 0      4096               *:9090             *:*    users:(("prometheus",pid=1500,fd=8),("prometheus",pid=1501,fd=8))\n'
        'LISTEN 0      4096           [::1]:631           [::]:*    users:(("cupsd",pid=700,fd=7))\n'
        'LISTEN 0      4096   127.0.0.53%lo:53         0.0.0.0:*    users:(("systemd-resolve",pid=612,fd=14))\n'))
    assert shared[1500] == shared[1501], "a shared socket is listed under each process, as lsof does"
    assert [(l.address, l.port, l.open_to_network) for l in shared[700]] == [("[::1]", 631, False)]
    assert [(l.address, l.open_to_network) for l in shared[612]] == [("127.0.0.53", False)], "the %lo suffix is dropped"


def test_gateways_parse_through_netstats_parser():
    table = linux.render_routes(_fixture("proc_net_route.txt"), _fixture("proc_net_ipv6_route.txt"))
    assert gateways.parse(table) == frozenset({"192.168.64.1"}), "docker0's and the link's own routes name no gateway"


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


def test_a_connection_to_a_port_another_user_serves_is_inbound_and_the_listener_is_not_attributed():
    """Peer review of 035d09bba9: unprivileged, ss names no process for another user's listening
    socket; its port must still mark connections to it as inbound."""
    text = ("tcp   LISTEN 0      4096         0.0.0.0:8443        0.0.0.0:*\n"
            "tcp   ESTAB  0      0       198.51.100.7:8443   203.0.113.98:40000 users:((\"worker\",pid=900,fd=9))\n")
    processes = nettop.parse(linux.render_connections(text))
    assert [process.pid for process in processes] == [900], "the unowned listener is attributed to no process"
    (connection,) = processes[0].connections
    assert (connection.direction, connection.local_port, connection.remote_ip) == ("in", 8443, "203.0.113.98")
