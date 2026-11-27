"""Network Shield's depth (plugins/blackbox/shields/network: watch.py, enforcement.py, monitor/).

Founder direction (Amos, 2026-11-21): detailed network stats with CPU per app, connections in and
out, SSH and hosts-file monitoring with an alert on every new SSH session, SSH lockdown, and
malicious connections cut automatically.

Contracts: the enforcer's watch report is validated strictly (a bad event refuses the whole
report; a file outside the watched set, a bad address or a key-like value never gets in); events
are kept newest first and bounded and become alerts and shield events with escaped stories; the
plan carries cut addresses (public, not allowed), SSH lockdown and the watch only while the
shield is on; ``ssh_allow`` takes only addresses and networks; the monitor tells inbound from
outbound and reads CPU and memory; the ``ssh`` read refuses while off.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from plugins.blackbox.shields.network import mode as network_mode
from plugins.blackbox.shields.network import api
from plugins.blackbox.shields.network.protect import enforcement
from plugins.blackbox.shields.network.respond import events
from plugins.blackbox.shields.network.monitor import watch
from plugins.blackbox.shields.network.monitor import nettop
from plugins.blackbox.shields.shield_api import AssistantAnswer, ShieldApiError, ShieldContext

NOW = 1_795_219_000.0
KEYS = "/Users/me/.ssh/authorized_keys"


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setattr(enforcement, "_plan_cache", {"key": None, "plan": None})
    return tmp_path


def _report(**extra):
    return {"running": True, "dns_active": False, "firewall_active": False, **extra}


def _on(*protections, **options):
    return network_mode.build(enabled=True, protections=protections, **options)


# ------------------------------------------------------------------ the watch report


@pytest.mark.parametrize("bad", [
    {"events": [{"kind": "teleport", "ts": 1}]},
    {"events": [{"kind": "ssh-session-new", "ts": 1, "remote_ip": "not-an-ip", "remote_port": 22}]},
    {"events": [{"kind": "file-changed", "ts": 1, "path": "/Users/me/secrets.txt", "change": "modified"}]},
    {"events": [{"kind": "file-changed", "ts": 1, "path": KEYS, "change": "modified", "sha_prefix": "ssh-ed25519 AAAA"}]},
    {"events": [{"kind": "remote-login-changed", "ts": 1, "on": "yes"}]},
    {"events": [{"kind": "connection-cut", "ts": 1, "remote_ip": "45.130.148.102"}] * 201},
    {"watch": {"remote_login": True, "files": [{"path": "/etc/passwd", "exists": True}]}},
    {"cut_active": "yes"},
])
def test_a_bad_watch_report_is_refused_whole(bad):
    with pytest.raises(ShieldApiError) as refused:
        enforcement.record_report(_report(**bad), now=NOW)
    assert refused.value.status == 400
    assert watch.events() == [] and enforcement.read_state() == {}


def test_events_become_alerts_newest_first_and_bounded():
    enforcement.record_report(_report(cut_active=True, events=[
        {"kind": "ssh-session-new", "ts": int(NOW) - 10, "remote_ip": "192.168.64.1", "remote_port": 50000},
        {"kind": "file-changed", "ts": int(NOW) - 5, "path": KEYS, "change": "modified", "lines_delta": 1, "sha_prefix": "3fa1c09b"},
        {"kind": "connection-cut", "ts": int(NOW), "remote_ip": "45.130.148.102"},
    ]), now=NOW)
    alerts = watch.alerts()
    assert [a["kind"] for a in alerts] == ["connection-cut", "file-changed", "ssh-session-new"]
    assert alerts[2]["text"] == "Someone connected to this machine over SSH from 192.168.64.1." and alerts[2]["severity"] == "high"
    assert alerts[1]["text"] == "The me · authorized_keys file changed (+1 line)."
    assert enforcement.summary(now=NOW)["cut_total"] == 1 and enforcement.summary(now=NOW)["cut_active"] is True
    for _ in range(4):
        enforcement.record_report(_report(events=[{"kind": "ssh-session-ended", "ts": int(NOW), "remote_ip": "10.0.0.2"}] * 100), now=NOW)
    assert len(watch.events(1000)) == watch.MAX_EVENTS


def test_the_snapshot_is_the_ssh_read_and_goes_stale(monkeypatch):
    enforcement.record_report(_report(watch={
        "remote_login": True, "sessions": [{"remote_ip": "192.168.64.1", "remote_port": 50000, "since": int(NOW)}],
        "files": [{"path": "/etc/hosts", "exists": True, "changed_at": None, "sha_prefix": "9b2e11aa"}]}), now=NOW)
    view = watch.ssh_view(now=NOW + 5)
    assert view["watching"] and view["remote_login"] and view["sessions"][0]["remote_ip"] == "192.168.64.1"
    assert view["files"] == [{"path": "/etc/hosts", "label": "hosts file", "exists": True, "changed_at": None, "sha_prefix": "9b2e11aa"}]
    assert watch.ssh_view(now=NOW + watch.STALE_AFTER_SECONDS + 1)["watching"] is False
    monkeypatch.setattr(network_mode, "current", lambda: network_mode.build())
    with pytest.raises(ShieldApiError) as refused:
        api.ssh(None, {})
    assert refused.value.status == 409


def test_watch_stories_escape_every_value(monkeypatch):
    monkeypatch.setattr(watch, "events", lambda limit=100: [{"kind": "file-changed", "ts": NOW, "change": "added",
                                                            "path": "/Users/<img src=x>/.ssh/config", "lines_delta": 0, "sha_prefix": ""}])
    story = events.report()[0].story
    assert "<img" not in story and "&lt;img src=x&gt; · config" in story


# ------------------------------------------------------------------ the plan


def test_cut_ssh_and_watch_are_in_the_plan_only_while_on():
    off = enforcement.plan(network_mode.build(protections=(network_mode.CUT, network_mode.SSH_LOCKDOWN)), None,
                           cut_ips=["45.130.148.102"])
    assert off["cut"] == {"enabled": False, "ips": []} and off["ssh"] == {"lockdown": False, "allow": []} and off["watch"] is False
    on = enforcement.plan(_on(network_mode.CUT, network_mode.SSH_LOCKDOWN, ssh_allow=("192.168.1.0/24",), allow=("203.0.113.9",)),
                          None, cut_ips=["45.130.148.102", "192.168.54.1", "203.0.113.9"])
    assert on["cut"] == {"enabled": True, "ips": ["45.130.148.102"]}   # never a private or allowed address
    assert on["ssh"] == {"lockdown": True, "allow": ["192.168.1.0/24"]} and on["watch"] is True
    again = enforcement.plan(_on(network_mode.CUT, network_mode.SSH_LOCKDOWN, ssh_allow=("192.168.1.0/24",), allow=("203.0.113.9",)),
                             None, cut_ips=[], have=on["version"])
    assert again["unchanged"] is False, "a changed set of connected threats is a new plan"


def test_the_plan_reads_the_monitor_only_while_cut_is_on(monkeypatch):
    reads = []
    connection = SimpleNamespace(remote_ip="45.130.148.102", threat="verified threat graph")
    monkeypatch.setattr(api.monitor, "read", lambda ips: reads.append(ips) or SimpleNamespace(
        processes=[SimpleNamespace(connections=[connection])]))
    context = ShieldContext(network_indicators=lambda: SimpleNamespace(ips=frozenset({"45.130.148.102"}), domains=frozenset(), built_at=1.0),
                            ask_assistant=lambda message: AssistantAnswer(ok=True))
    monkeypatch.setattr(network_mode, "current", lambda: _on(network_mode.DNS))
    assert api.enforcement_plan(context, {})["cut"]["ips"] == [] and reads == []
    monkeypatch.setattr(network_mode, "current", lambda: _on(network_mode.CUT))
    assert api.enforcement_plan(context, {})["cut"]["ips"] == ["45.130.148.102"] and len(reads) == 1


@pytest.mark.parametrize("sources, ok", [
    (["192.168.1.0/24", "10.0.0.5", "fd00::/8"], True),
    (["192.168.1.7/24"], True),                       # host bits cleared, not refused
    (["example.com"], False), (["10.0.0.0/33"], False),
    ([f"10.0.{n // 250}.{n % 250 + 1}" for n in range(101)], False),   # too many (duplicates fold first: review 2026-11-26)
    (["1.2.3.4"] * 101, True),
])
def test_ssh_allow_takes_addresses_and_networks_only(sources, ok):
    _id, section, errors = network_mode.validate({"shields": {"network-shield": {"ssh_allow": sources}}})
    assert (not errors) is ok
    if ok:
        assert all("/" in s or s.count(".") == 3 or ":" in s for s in section["ssh_allow"])
        assert "192.168.1.0/24" in section["ssh_allow"] or sources[0] != "192.168.1.7/24"


# ------------------------------------------------------------------ the monitor

NETTOP = """,state,bytes_in,bytes_out,
sshd.90,,10,20,
tcp4 *:22<->*:*,Listen,,,
tcp6 *.22<->*.*,Listen,,,
tcp4 192.168.64.27:22<->192.168.64.1:50000,Established,10,20,
curl.42,,100,900,
tcp4 192.168.64.27:51000<->45.130.148.102:443,SynSent,100,900,
"""


def test_the_monitor_tells_inbound_from_outbound():
    sshd, curl = nettop.parse(NETTOP)
    assert (sshd.connections[0].direction, sshd.connections[0].local_port, sshd.connections[0].state) == ("in", 22, "Established")
    assert (curl.connections[0].direction, curl.connections[0].remote_port, curl.connections[0].state) == ("out", 443, "SynSent")


# ------------------------------------------------------------------ a connection a live collector saw
# Engine rule (2026-11-22): every notification comes from the core. A live collector (an add-on)
# used to word and send "talking to a listed address" itself; it now reports the facts
# (POST observed-connection) and Network Shield decides, keeps and words it.

LISTED = "45.130.148.102"


def _listed_context():
    return ShieldContext(network_indicators=lambda: SimpleNamespace(ips=frozenset({LISTED}), domains=frozenset(), built_at=1.0),
                         ask_assistant=lambda message: AssistantAnswer(ok=True))


def _seen(**more):
    return {"pid": 4242, "program": "curl", "remote_ip": LISTED, "remote_port": 443, "ts": int(NOW), **more}


def test_a_connection_to_a_listed_address_is_kept_once_and_worded_by_network_shield(monkeypatch):
    from plugins.blackbox.shields.network import notices
    monkeypatch.setattr(network_mode, "current", lambda: _on(network_mode.DNS))
    write = api.API.writes["observed-connection"]
    assert write(_listed_context(), _seen()) == {"recorded": True}
    assert write(_listed_context(), _seen(ts=int(NOW) + 5)) == {"recorded": False}        # the same process again: once
    assert write(_listed_context(), _seen(pid=99, ts=int(NOW) + 6)) == {"recorded": True}   # another process: news
    kept = [event for event in watch.events() if event["kind"] == watch.SEEN]
    assert len(kept) == 2 and kept[0]["program"] == "curl" and kept[0]["remote_port"] == 443
    monkeypatch.setattr(notices.system_report, "snapshot", dict)
    seen = [alert for alert in notices.shield_alerts() if alert.kind == "connection-seen"]
    assert seen and seen[0].title == "Network Shield · Connection to a listed threat"
    for alert in seen:   # lock-screen safe: neither the address nor the program's name
        assert LISTED not in alert.text and "curl" not in alert.text and alert.category == "security"
        assert LISTED in alert.detail and "curl" in alert.detail


def test_an_address_the_list_does_not_hold_is_never_kept(monkeypatch):
    monkeypatch.setattr(network_mode, "current", lambda: _on(network_mode.DNS))
    assert api.API.writes["observed-connection"](_listed_context(), _seen(remote_ip="8.8.8.8")) == {"recorded": False}
    assert watch.events() == []


@pytest.mark.parametrize("bad", [
    {"program": "/usr/bin/curl"}, {"program": ""}, {"pid": -1}, {"pid": "12"}, {"remote_ip": "evil"}, {"remote_port": 70000},
])
def test_a_bad_observation_is_refused(monkeypatch, bad):
    monkeypatch.setattr(network_mode, "current", lambda: _on(network_mode.DNS))
    with pytest.raises(ShieldApiError) as refused:
        api.API.writes["observed-connection"](_listed_context(), _seen(**bad))
    assert refused.value.status == 400 and watch.events() == []


def test_an_observation_is_refused_while_the_shield_is_off(monkeypatch):
    monkeypatch.setattr(network_mode, "current", lambda: network_mode.build())
    with pytest.raises(ShieldApiError) as refused:
        api.API.writes["observed-connection"](_listed_context(), _seen())
    assert refused.value.status == 409
