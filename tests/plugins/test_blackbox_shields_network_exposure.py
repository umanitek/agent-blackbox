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
    assert "Launch agent (your account) “com.evil” was added." == alerts[0]["text"]
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
