"""Network Shield's remote access (Blackbox Desktop add-on): who is in this machine and how,
Lock remote access, brute-force auto-block, blocked addresses and ending a session.

Contracts: the helper's ``remote`` report part is validated strictly (one bad item refuses the
whole report and nothing is kept); a valid one shows as live sessions with who / how / duration;
failed logins count per source in a window and auto-block only when switched on (never an
always-allowed address); the plan's remote part is all-off while the shield is off and follows
the lock (relay domains refused only with DNS Shield) — switching the lock off undoes it; ending
a session accepts only a live session of a kind with its own process, once, expiring; remote-
control apps and tunnels are recognised by the program; the reads and writes refuse while off.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.shields.network import mode as network_mode
from plugins.blackbox.shields.shield_api import ShieldApiError
from plugins.blackbox.shields.network import api
from plugins.blackbox.shields.network.monitor import remote_access
from plugins.blackbox.shields.network.monitor.remote_access import catalog, names, records
from plugins.blackbox.shields.network.protect import enforcement, remote_lock
from plugins.blackbox.shields.network.respond import sessions

NOW = 1_795_219_000.0
SESSION = {"id": "ssh-812-192.168.64.1-52344", "how": "ssh", "method": "publickey", "fingerprint": "SHA256:AbC123",
           "user": "admin", "remote_ip": "192.168.64.1", "remote_port": 52344, "local_port": 22, "pid": 812,
           "started": int(NOW) - 90, "processes": [{"pid": 813, "name": "zsh", "path": "/bin/zsh"}]}


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setattr(enforcement, "_plan_cache", {"key": None, "plan": None})
    monkeypatch.setattr(catalog, "read", lambda: {"apps": [], "tunnels": []})   # no ps / nettop in tests
    monkeypatch.setattr(names, "host_name", lambda address: "")                   # no reverse DNS in tests
    monkeypatch.setattr(names, "tailscale_name", lambda address: "")
    monkeypatch.setattr(network_mode, "current", lambda: network_mode.build(enabled=True))
    return tmp_path


def _report(remote=None, **extra):
    body = {"running": True, "dns_active": False, "firewall_active": False, **extra}
    if remote is not None:
        body["remote"] = remote
    return body


def _remote(sessions=(SESSION,), events=(), services=None):
    return {"snapshot": {"sessions": list(sessions), "services": services or {"remote_login": True}},
            "events": list(events), "lock_active": False}


def _failed(ip, ts=NOW, user="root"):
    return {"kind": "remote-auth-failed", "ts": int(ts), "how": "ssh", "method": "password", "user": user, "remote_ip": ip}


# ------------------------------------------------------------------ the helper's report


@pytest.mark.parametrize("bad", [
    {**SESSION, "how": "telepathy"},
    {**SESSION, "id": "ssh 812; rm -rf /"},
    {**SESSION, "processes": [{"pid": 1, "name": "zsh", "path": "/bin/zsh\nsecret"}]},
    {**SESSION, "processes": [{"pid": 1, "name": "x", "path": "/x"}] * 21},
    {**SESSION, "user": "a b"},
    {**SESSION, "remote_ip": "not-an-ip"},
])
def test_a_bad_session_refuses_the_whole_report_and_nothing_is_kept(bad):
    with pytest.raises(ShieldApiError) as refused:
        enforcement.record_report(_report(_remote(sessions=[bad])), now=NOW)
    assert refused.value.status == 400
    assert remote_access.live_sessions(NOW) == [] and enforcement.read_state() == {}


def test_a_bad_event_refuses_the_report():
    with pytest.raises(ShieldApiError):
        enforcement.record_report(_report(_remote(events=[{"kind": "remote-session-new", "ts": int(NOW), "session_id": "x"}])), now=NOW)


def test_a_valid_report_shows_who_is_in_and_how():
    enforcement.record_report(_report(_remote(events=[{"kind": "remote-session-new", "ts": int(NOW), **{k: SESSION[k] for k in (
        "how", "method", "user", "remote_ip", "remote_port")}, "session_id": SESSION["id"], "reason": ""}])), now=NOW)
    view = remote_access.view(NOW)
    session = view["sessions"][0]
    assert (session["how_label"], session["user"], session["who"]["ip"], session["duration"]) == ("SSH", "admin", "192.168.64.1", 90)
    assert session["processes"][0]["path"] == "/bin/zsh" and view["services"]["remote_login"] is True and view["watching"]
    assert view["recent"][0]["text"] == "Someone logged in over SSH as admin from 192.168.64.1 with a key."


def test_a_report_without_the_remote_part_is_fine_and_a_stale_snapshot_shows_no_one():
    enforcement.record_report(_report(), now=NOW)
    enforcement.record_report(_report(_remote()), now=NOW)
    assert remote_access.live_sessions(NOW + records.STALE_AFTER_SECONDS + 1) == []


# ------------------------------------------------------------------ failed logins and auto-block


def test_failed_logins_count_per_source_and_auto_block_only_when_switched_on():
    events = [_failed("203.0.113.9", NOW - i) for i in range(5)] + [_failed("198.51.100.7", NOW)]
    enforcement.record_report(_report(_remote(events=events)), now=NOW)
    assert remote_lock.settings(NOW)["blocked"] == [], "off by default"
    view = remote_access.view(NOW)
    assert view["failed_logins"][0]["ip"] == "203.0.113.9" and view["failed_logins"][0]["count"] == 5
    assert sum(view["failed_timeline"]) == 6
    remote_lock.update({"brute_force": {"enabled": True, "failures": 5, "window_minutes": 10}})
    assert remote_lock.check_failures(NOW) == ["203.0.113.9"]
    assert remote_lock.check_failures(NOW) == [], "blocked once"
    assert remote_lock.plan_part(True, NOW)["block"] == ["203.0.113.9"]
    assert any(alert["kind"] == "remote-auto-blocked" for alert in remote_access.alerts())


def test_an_unblocked_address_is_blocked_again_only_for_new_failures():
    """E2E B6 (bb-e2e-1121): unblocking kept the address's failure history, so the next check
    blocked it again at once. Failures before the unblock are forgiven; new ones still count."""
    enforcement.record_report(_report(_remote(events=[_failed("203.0.113.9", NOW - i) for i in range(5)])), now=NOW)
    remote_lock.update({"brute_force": {"enabled": True, "failures": 5, "window_minutes": 10}})
    assert remote_lock.check_failures(NOW) == ["203.0.113.9"]
    remote_lock.unblock("203.0.113.9", now=NOW + 1)
    assert remote_lock.check_failures(NOW + 2) == [], "the old failures no longer count"
    later = NOW + 60
    enforcement.record_report(_report(_remote(events=[_failed("203.0.113.9", later - i) for i in range(5)])), now=later)
    # Storing the report runs the auto-block check itself.
    assert [b["ip"] for b in remote_lock.settings(later)["blocked"]] == ["203.0.113.9"], "five new failures block it again"


def test_the_gateway_is_never_auto_blocked_and_the_person_is_told(monkeypatch):
    """E2E S4 (bb-e2e-1121): behind NAT every failed login comes from the router's address;
    auto-blocking it would cut off every remote connection. It is reported, never blocked."""
    from plugins.blackbox.shields.network.monitor import gateways
    monkeypatch.setattr(gateways, "addresses", lambda now=None: frozenset({"192.168.64.1"}))
    remote_lock.update({"brute_force": {"enabled": True, "failures": 3}})
    enforcement.record_report(_report(_remote(events=[_failed("192.168.64.1", NOW - i) for i in range(6)])), now=NOW)
    assert remote_lock.check_failures(NOW) == [] and remote_lock.settings(NOW)["blocked"] == []
    assert any(alert["kind"] == "remote-gateway-not-blocked" for alert in remote_access.alerts())


def test_the_gateway_is_read_from_the_routing_table():
    from plugins.blackbox.shields.network.monitor import gateways
    table = ("Destination        Gateway            Flags  Netif\n"
             "default            192.168.1.1        UGScg  en0\n"
             "default            fe80::1%en0        UGcIg  en0\n"
             "default            link#14            UCSIg  bridge100\n"
             "127.0.0.1          127.0.0.1          UH     lo0\n")
    assert gateways.parse(table) == {"192.168.1.1", "fe80::1"}
    assert gateways.parse("") == frozenset()


def test_an_always_allowed_address_is_never_auto_blocked(monkeypatch):
    monkeypatch.setattr(network_mode, "current", lambda: network_mode.build(enabled=True, allow=("203.0.113.9",)))
    enforcement.record_report(_report(_remote(events=[_failed("203.0.113.9", NOW - i) for i in range(6)])), now=NOW)
    remote_lock.update({"brute_force": {"enabled": True, "failures": 3}})
    assert remote_lock.check_failures(NOW) == []


@pytest.mark.parametrize("bad", [{"lock": "yes"}, {"brute_force": {"failures": 1}}, {"brute_force": {"window_minutes": 999}},
                                 {"brute_force": {"enabled": "on"}}, {"brute_force": []}])
def test_invalid_settings_are_refused_and_nothing_changes(bad):
    with pytest.raises(ShieldApiError):
        remote_lock.update(bad)
    assert remote_lock.settings()["lock"] is False and remote_lock.settings()["brute_force"] == remote_lock.DEFAULT_BRUTE_FORCE


def test_blocks_validate_expire_and_unblock():
    for bad in ("127.0.0.1", "::", "nonsense"):
        with pytest.raises(ShieldApiError):
            remote_lock.block(bad)
    remote_lock.block("203.0.113.9", 5, now=NOW)
    assert remote_lock.plan_part(True, NOW)["block"] == ["203.0.113.9"]
    assert remote_lock.plan_part(True, NOW + 301)["block"] == [], "expired"
    remote_lock.block("203.0.113.9", 60, now=NOW)
    remote_lock.unblock("203.0.113.9")
    assert remote_lock.plan_part(True, NOW)["block"] == []


# ------------------------------------------------------------------ the plan: lock and undo


def test_the_remote_part_is_all_off_while_the_shield_is_off_and_the_lock_undoes():
    remote_lock.update({"lock": True})
    remote_lock.block("203.0.113.9", 60)
    off = enforcement.plan(network_mode.build(protections=(network_mode.DNS,)), None)
    assert off["remote"] == {"lock": False, "block": [], "end": []}
    on = enforcement.plan(network_mode.build(enabled=True, protections=(network_mode.DNS,)), None)
    assert on["remote"]["lock"] is True and on["remote"]["block"] == ["203.0.113.9"]
    assert "teamviewer.com" in on["dns"]["block"], "relay domains refused through DNS Shield while locked"
    without_dns = enforcement.plan(network_mode.build(enabled=True, protections=(network_mode.FIREWALL,)), None)
    assert without_dns["dns"]["block"] == [] and without_dns["remote"]["lock"] is True
    remote_lock.update({"lock": False})
    undone = enforcement.plan(network_mode.build(enabled=True, protections=(network_mode.DNS,)), None)
    assert undone["remote"]["lock"] is False and "teamviewer.com" not in undone["dns"]["block"]
    assert undone["version"] != on["version"]


# ------------------------------------------------------------------ ending a session


def test_only_a_live_session_with_its_own_process_can_be_ended_once():
    with pytest.raises(ShieldApiError) as gone:
        sessions.end_session({"session_id": SESSION["id"]})
    assert gone.value.status == 404
    tailnet = {**SESSION, "id": "tailscale-ssh-50-100.101.102.103-7000", "how": "tailscale-ssh", "pid": 50}
    enforcement.record_report(_report(_remote(sessions=[SESSION, tailnet])), now=NOW)
    with pytest.raises(ShieldApiError) as shared:
        remote_lock.request_end(tailnet, now=NOW)
    assert shared.value.status == 409
    remote_lock.request_end(SESSION, now=NOW)
    remote_lock.request_end(SESSION, now=NOW)
    assert remote_lock.plan_part(True, NOW)["end"] == [{"session_id": SESSION["id"], "pid": 812, "started": SESSION["started"]}]
    assert remote_lock.plan_part(True, NOW + remote_lock.END_EXPIRES_SECONDS + 1)["end"] == [], "a request expires"


def test_a_session_named_after_launchd_is_refused_before_it_is_queued():
    """E2E B5 (bb-e2e-1121): an SSH session attributed to launchd (pid 1) answered "requested", and
    the helper — which never ends pid 1 — silently refused. It is refused in the window now."""
    for pid in (0, 1):
        with pytest.raises(ShieldApiError) as refused:
            remote_lock.request_end({**SESSION, "pid": pid}, now=NOW)
        assert refused.value.status == 409
    assert remote_lock.plan_part(True, NOW)["end"] == []


# ------------------------------------------------------------------ apps and tunnels


def test_remote_control_apps_and_tunnels_are_recognised_by_the_program():
    found = catalog.detect([
        catalog.Running(10, "/Applications/TeamViewer.app/Contents/MacOS/TeamViewer", connected=True),
        catalog.Running(11, "/Applications/AnyDesk.app/Contents/MacOS/helper"),
        catalog.Running(12, "/opt/homebrew/bin/ngrok", connected=True),
        catalog.Running(13, "/usr/bin/ssh", listening=(1080,)),
        catalog.Running(14, "/usr/bin/ssh"),
        catalog.Running(15, "/Applications/Safari.app/Contents/MacOS/Safari", connected=True),
    ])
    apps = {app["id"]: app for app in found["apps"]}
    assert apps["teamviewer"]["active"] and not apps["anydesk"]["active"] and len(apps) == 2
    tunnels = {tunnel["id"]: tunnel for tunnel in found["tunnels"]}
    assert tunnels["ngrok"]["active"] and tunnels["ssh-forward-13"]["ports"] == [1080] and "ssh-forward-14" not in tunnels


def test_tailscale_status_names_each_machine():
    names_by_ip = names.parse_tailscale('{"Self": {"HostName": "Amos Mac 64", "TailscaleIPs": ["100.64.0.9"]},'
                                        ' "Peer": {"k": {"HostName": "Main Mac", "TailscaleIPs": ["100.101.102.103", "fd7a::1"]}}}')
    assert names_by_ip == {"100.64.0.9": "Amos Mac 64", "100.101.102.103": "Main Mac", "fd7a::1": "Main Mac"}
    assert names.parse_tailscale("not json") == {}


# ------------------------------------------------------------------ off


def test_the_remote_reads_and_writes_refuse_while_the_shield_is_off(monkeypatch):
    monkeypatch.setattr(network_mode, "current", lambda: network_mode.build())
    for call in (lambda: api.remote(None, {}), lambda: api.API.writes["end-session"](None, {"session_id": "x"}),
                 lambda: api.API.writes["remote-settings"](None, {"lock": True})):
        with pytest.raises(ShieldApiError) as refused:
            call()
        assert refused.value.status == 409


def test_the_status_says_remote_access_is_locked_only_while_the_helper_reports_it_applied():
    """Review 2026-11-21, finding 6b: enforcement.summary() had no remote_lock_active, so the
    posture check marked Remote Login "bad" while Blackbox's lock was on."""
    import time as _time
    now = _time.time()
    records.record(records.validate({"snapshot": {"sessions": [], "services": {"remote_login": True}}, "events": [],
                                     "lock_active": True}, now), now)
    assert enforcement.summary(now=now)["remote_lock_active"] is True
    stale = now + records.STALE_AFTER_SECONDS + 1
    assert enforcement.summary(now=stale)["remote_lock_active"] is False, "a helper that stopped reporting is not a lock"


def test_a_macos_system_program_is_never_taken_for_a_remote_control_app():
    """E2E 2026-11-21: Apple's Spotlight helper .../CoreParsec.framework/parsecd showed as "Parsec"."""
    found = catalog.detect([
        catalog.Running(434, "/System/Library/PrivateFrameworks/CoreParsec.framework/parsecd", connected=True),
        catalog.Running(20, "/Applications/Parsec.app/Contents/MacOS/parsecd", connected=True),
    ])
    parsec = [app for app in found["apps"] if app["id"] == "parsec"]
    assert len(parsec) == 1 and parsec[0]["pids"] == [20]
