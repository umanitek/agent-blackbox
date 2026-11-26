"""Network Shield's system watch — exposure, startup items (persistence) and tampering
(plugins/blackbox/shields/network/{monitor/system_report.py, monitor/exposure.py,
respond/system_alerts.py, system_api.py}).

Founder direction (Amos, 2026-11-21): an instant alert when any program starts listening where the
network can reach it, when something new starts by itself, and when DNS, a proxy, a VPN, the
firewall or Blackbox's own helper is changed.

Contracts: the helper's report is validated strictly (one bad item refuses the whole report);
listeners and startup items are judged by who signed their program (an unsigned startup item is
critical, one in Downloads too; macOS's own is low); first-seen times survive later reports;
events become alerts with a sentence and a severity and join the overview's alerts; DNS moved
away while DNS Shield is on is reported; every read refuses while the shield is off and the
helper's plan then watches nothing.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.shields.network import mode as network_mode
from plugins.blackbox.shields.shield_api import ShieldApiError
from plugins.blackbox.shields.network import system_api
from plugins.blackbox.shields.network.monitor import exposure, system_report
from plugins.blackbox.shields.network.monitor import signature
from plugins.blackbox.shields.network.protect import enforcement, posture_fix, tamper_guard
from plugins.blackbox.shields.network.respond import system_alerts

NOW = 1_795_300_000.0


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setattr(exposure, "_check_later", lambda paths: None)
    monkeypatch.setattr(network_mode, "current", lambda: network_mode.build(enabled=True, protections=(network_mode.DNS,)))
    return tmp_path


def _signed(kinds):
    return lambda path: signature.Signature(kind=kinds[path], signer="Vendor Inc") if path in kinds else None


def _report(**extra):
    body = {"watching": True, "exposure": [], "persistence": [], "tamper": None, "posture": None, "fixes": [], "events": []}
    body.update(extra)
    return body


WEB = {"protocol": "tcp4", "address": "0.0.0.0", "port": 8000, "program": "/usr/bin/python3", "pid": 77, "since": 1}
AGENT = {"kind": "user-agent", "id": "/Users/me/Library/LaunchAgents/com.evil.plist", "label": "com.evil", "program": "/Users/me/.local/evil"}


@pytest.mark.parametrize("bad", [
    {"exposure": [{**WEB, "protocol": "icmp"}]},
    {"exposure": [{**WEB, "address": "not-an-ip"}]},
    {"exposure": [{**WEB, "program": "/bin/x\x00"}]},
    {"persistence": [{**AGENT, "kind": "rootkit"}]},
    {"tamper": {"dns_servers": ["8.8.8.8; rm -rf /"]}},
    {"tamper": {"proxy": ["ftp"]}},
    {"posture": {"filevault": "maybe"}},
    {"fixes": ["format-disk"]},
    {"events": [{"kind": "teleported", "ts": 1}]},
    {"events": [{"kind": "listener-new", "ts": 1, "protocol": "tcp4", "address": "0.0.0.0", "port": 70000, "program": "/x"}]},
    {"events": [{"kind": "fix-applied", "fix": "rm-everything"}]},
])
def test_a_bad_report_is_refused_whole(bad):
    with pytest.raises(ShieldApiError) as refused:
        system_report.validate(_report(**bad), NOW)
    assert refused.value.status == 400


def test_listeners_and_startup_items_are_judged_by_their_signer(monkeypatch):
    monkeypatch.setattr(signature, "lookup", _signed({"/usr/bin/python3": "apple", "/Applications/Zoom.app/Contents/MacOS/zoom": "developer_id",
                                                       "/Users/me/.local/evil": "unsigned"}))
    zoom = {**WEB, "port": 19421, "program": "/Applications/Zoom.app/Contents/MacOS/zoom"}
    downloads = {**AGENT, "id": "/Library/LaunchAgents/com.dl.plist", "program": "/Users/me/Downloads/updater"}
    profile = {"kind": "profile", "id": "com.corp.mdm", "label": "com.corp.mdm", "program": ""}
    system_report.record(system_report.validate(_report(exposure=[WEB, zoom], persistence=[AGENT, downloads, profile]), NOW))
    view = exposure.view(NOW)
    risks = {row["program"]: row["risk"] for row in view["listeners"]}
    assert risks == {"/usr/bin/python3": "low", "/Applications/Zoom.app/Contents/MacOS/zoom": "medium"}
    startup = {row["id"]: (row["risk"], row["kind_name"]) for row in view["startup"]}
    assert startup[AGENT["id"]][0] == "critical", "an unsigned startup item is critical"
    assert startup[downloads["id"]][0] == "critical", "a startup program in Downloads is critical"
    assert startup["com.corp.mdm"] == ("medium", "Configuration profile")
    assert view["startup"][0]["risk"] == "critical", "worst first"


def test_a_program_with_no_signature_to_read_is_answered_never_left_checking(tmp_path):
    """E2E B8 (bb-e2e-1121): startup items whose program is a bare name (``dkg``) or a missing file
    stayed "checking" forever — there is nothing to stat, so the check never cached an answer."""
    present = tmp_path / "tool"
    present.write_text("#!/bin/sh\n", encoding="utf-8")
    assert exposure.judge("dkg", startup=True)[0] == "medium"
    assert exposure.judge(str(tmp_path / "gone"), startup=True)[0] == "medium"
    assert exposure.judge(str(present), startup=True)[0] == "checking", "a real file is still read in the background"


def test_first_seen_survives_later_reports_and_a_stale_look_is_not_shown():
    system_report.record(system_report.validate(_report(exposure=[WEB]), NOW))
    system_report.record(system_report.validate(_report(exposure=[{**WEB, "since": 5}]), NOW + 30))
    assert system_report.first_seen(WEB) == 1
    assert exposure.view(NOW + 30 + system_report.STALE_AFTER_SECONDS + 1)["watching"] is False


def test_events_become_alerts_with_sentences_and_severity(monkeypatch):
    monkeypatch.setattr(signature, "lookup", _signed({"/Users/me/.local/evil": "adhoc"}))
    events = [{"kind": "persistence-new", "ts": NOW, "item_kind": "user-agent", "id": AGENT["id"], "label": "com.evil", "program": AGENT["program"]},
              {"kind": "listener-new", "ts": NOW - 1, "protocol": "tcp4", "address": "0.0.0.0", "port": 5900, "program": "/System/screensharingd"},
              {"kind": "firewall-changed", "ts": NOW - 2, "state": "off", "was": "on"},
              {"kind": "helper-modified", "ts": NOW - 3}]
    system_report.record(system_report.validate(_report(events=events), NOW))
    alerts = system_alerts.alerts(10)
    assert [a["severity"] for a in alerts] == ["critical", "medium", "high", "critical"]
    assert "New startup item: Launch agent (your account) “com.evil” — starts evil." == alerts[0]["text"]
    assert "port 5900 (Screen Sharing)" in alerts[1]["text"]
    assert "switched off" in alerts[2]["text"]


def test_dns_moved_away_while_dns_shield_is_on_is_reported(monkeypatch):
    monkeypatch.setattr(enforcement, "summary", lambda: {"dns_active": True, "running": True})
    system_report.record(system_report.validate(_report(tamper={"dns_servers": ["8.8.8.8"], "proxy": ["socks"], "vpn_count": 1, "firewall": "on", "helper_files": 2}), NOW))
    monkeypatch.setattr(system_report, "snapshot", lambda now=None: system_report.read_json_object(system_report._path())["snapshot"])
    tamper = system_api.exposure_read(None, {})["tamper"]
    assert tamper["checked"] and tamper["dns_shield"] and not tamper["dns_ok"]
    assert tamper["proxy"] == ["socks"] and tamper["vpn_count"] == 1


def test_off_means_no_reads_and_a_plan_that_watches_nothing(monkeypatch):
    posture_fix.set_fix("firewall-on", True)
    tamper_guard.set_on(True)
    on_plan = system_api.system_plan(None, {})
    assert on_plan["watch"] and on_plan["posture_fixes"] == ["firewall-on"] and on_plan["tamper_guard"]
    monkeypatch.setattr(network_mode, "current", lambda: network_mode.build())
    assert system_api.system_plan(None, {}) == {"watch": False, "posture_fixes": [], "posture_refresh": 0, "tamper_guard": False}
    for read in (system_api.exposure_read, system_api.posture_read):
        with pytest.raises(ShieldApiError) as refused:
            read(None, {})
        assert refused.value.status == 409



def test_blackbox_recognises_itself_by_identity_and_never_by_name_alone(home, monkeypatch):
    """E2E 2026-11-21: Blackbox rated its own LaunchAgents critical (each listed twice) and its DKG
    node's peer-to-peer port high. Its own items are low and named; a look-alike is not."""
    import os
    from plugins.blackbox.kernel import constants
    monkeypatch.setattr(signature, "lookup", lambda path: signature.Signature(kind="adhoc", signer=""))
    launcher = str(constants.blackbox_home() / "bin" / "Blackbox")
    ours = {"kind": "user-agent", "id": "/Users/me/Library/LaunchAgents/ai.umanitek.blackbox-dashboard.plist",
            "label": "ai.umanitek.blackbox-dashboard", "program": launcher}
    ours_again = {**ours, "kind": "login-item", "id": "btm:ai.umanitek.blackbox-dashboard"}
    look_alike = {"kind": "user-agent", "id": "/Users/me/Library/LaunchAgents/ai.umanitek.blackbox-x.plist",
                  "label": "ai.umanitek.blackbox-x", "program": "/Users/me/.local/evil"}
    nameless = {"kind": "login-item", "id": "btm:1", "label": "(null)", "program": "/Applications/Tool.app/Contents/MacOS/tool"}
    node = constants.blackbox_dkg_home()
    node.mkdir(parents=True, exist_ok=True)
    (node / "daemon.pid").write_text("4242\n", encoding="utf-8")
    p2p = {"protocol": "tcp6", "address": "::", "port": 63333, "program": "/usr/local/bin/node", "pid": 4242, "since": 1}
    stranger = {**p2p, "port": 8000, "pid": 77}
    system_report.record(system_report.validate(_report(exposure=[p2p, stranger], persistence=[ours, ours_again, look_alike, nameless]), NOW))
    view = exposure.view(NOW)
    startup = {row["label"]: row for row in view["startup"]}
    assert len([row for row in view["startup"] if row["label"] == ours["label"]]) == 1, "listed once"
    assert startup[ours["label"]]["risk"] == "low" and startup[ours["label"]].get("own")
    assert startup[look_alike["label"]]["risk"] == "critical", "a Blackbox-looking label elsewhere is not Blackbox"
    assert "tool" in startup and "(null)" not in startup
    ports = {row["port"]: row for row in view["listeners"]}
    assert ports[63333]["risk"] == "low" and "expected" in ports[63333]["why"]
    assert ports[8000]["risk"] == "high"


def test_the_node_is_found_where_the_installer_put_it_not_in_the_fallback_folder(home, monkeypatch, tmp_path):
    """E2E recheck 2026-11-21: the installer runs the node from ``<install root>/.dkg`` and records
    that as ``dkg_home``; exposure looked for ``daemon.pid`` in the fallback ``BLACKBOX_HOME/dkg``,
    so Blackbox's own peer-to-peer port stayed "high — signed by no one"."""
    from plugins.blackbox.kernel import yaml_files
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    monkeypatch.delenv("BLACKBOX_DKG_HOME", raising=False)
    node = tmp_path / "agent-blackbox" / ".dkg"
    node.mkdir(parents=True)
    (node / "daemon.pid").write_text("90424\n", encoding="utf-8")
    (tmp_path / "hermes").mkdir()
    yaml_files.dump_yaml(tmp_path / "hermes" / "config.yaml",
                         {"plugins": {"entries": {"blackbox": {"dkg_home": str(node)}}}})
    monkeypatch.setattr(signature, "lookup", lambda path: signature.Signature(kind="adhoc", signer=""))
    p2p = {"protocol": "tcp4", "address": "0.0.0.0", "port": 55260, "program": "/opt/homebrew/bin/node", "pid": 90424, "since": 1}
    system_report.record(system_report.validate(_report(exposure=[p2p]), NOW))
    row = exposure.view(NOW)["listeners"][0]
    assert row.get("own") and row["risk"] == "low", row
