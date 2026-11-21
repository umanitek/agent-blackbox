"""The security posture check and its fixes (plugins/blackbox/shields/network/{monitor/posture.py,
protect/posture_fix.py, protect/tamper_guard.py, system_api.py}).

Founder direction (Amos, 2026-11-21): a posture score with one-click fixes where a fix is safe,
asked first, with Undo; tampering with DNS can be put back (opt-in).

Contracts: every fact maps to a check with a reason and a fix or a System Settings link (SIP only
says how); the score weighs known checks and counts a warning half; unknown facts do not count;
Remote Login behind Blackbox's lock is a warning, not a failure; only the helper's known fixes can
be asked for, and Undo removes one; with the shield off the plan asks for no fix (the helper then
undoes them all); the tamper guard is off by default and refuses anything but true / false.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.shields.network import mode as network_mode
from plugins.blackbox.shields.shield_api import ShieldApiError
from plugins.blackbox.shields.network import system_api
from plugins.blackbox.shields.network.monitor import posture, system_report
from plugins.blackbox.shields.network.protect import enforcement, posture_fix, tamper_guard

NOW = 1_795_300_000.0
SAFE = {"filevault": "on", "firewall": "on", "stealth": "on", "gatekeeper": "on", "sip": "on",
        "updates": {"check": "", "download": "", "security": ""}, "remote_login": False, "screen_sharing": False,
        "remote_management": False, "file_sharing": False, "airdrop": [{"user": "me", "mode": "Contacts Only"}],
        "screen_lock": "immediate", "guest": "0"}
PROTECTED = {"running": True, "dns_active": True, "firewall_active": True, "remote_locked": False}


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setattr(network_mode, "current", lambda: network_mode.build(enabled=True))
    return tmp_path


def _by_id(facts, blackbox=PROTECTED):
    return {check["id"]: check for check in posture.checks(facts, blackbox)}


def test_a_safe_mac_scores_100_and_every_check_explains_itself():
    checks = posture.checks(SAFE, PROTECTED)
    assert posture.score(checks) == 100
    assert all(check["status"] == "ok" and check["why"] for check in checks)
    assert all(check["fix"] or check["settings"] or check["id"] in ("sip", "blackbox") for check in checks)


def test_risky_settings_fail_with_their_fix():
    risky = {**SAFE, "firewall": "off", "filevault": "off", "remote_login": True, "screen_sharing": True, "guest": "1",
             "airdrop": [{"user": "me", "mode": "Everyone"}], "updates": {"check": "0", "download": "", "security": "0"}, "screen_lock": "300 seconds"}
    checks = _by_id(risky)
    assert checks["firewall"]["status"] == "bad" and checks["firewall"]["fix"] == "firewall-on"
    assert checks["remote-login"]["status"] == "bad" and checks["remote-login"]["fix"] == "remote-login-off"
    assert checks["guest"]["fix"] == "guest-off" and checks["screen-sharing"]["fix"] == "screen-sharing-off"
    assert checks["airdrop"]["status"] == "warn" and "me" in checks["airdrop"]["detail"]
    assert checks["updates"]["status"] == "bad" and checks["screen-lock"]["status"] == "warn"
    assert checks["filevault"]["settings"].startswith("x-apple.systempreferences:")
    assert posture.score(list(checks.values())) < 50


def test_remote_login_behind_blackboxs_lock_is_a_warning_and_unknowns_do_not_count():
    checks = _by_id({**SAFE, "remote_login": True}, {**PROTECTED, "remote_locked": True})
    assert checks["remote-login"]["status"] == "warn" and "lock" in checks["remote-login"]["detail"]
    unknown = posture.checks({**SAFE, "filevault": "unknown", "sip": "unknown"}, PROTECTED)
    assert posture.score(unknown) == 100, "unknown facts are left out, not counted as failures"
    assert posture.score([]) is None


def test_only_known_fixes_can_be_asked_for_and_undo_removes_one():
    with pytest.raises(ShieldApiError):
        posture_fix.set_fix("format-disk", True)
    with pytest.raises(ShieldApiError):
        posture_fix.set_fix("firewall-on", "yes")
    assert posture_fix.set_fix("guest-off", True) == ["guest-off"]
    assert posture_fix.set_fix("firewall-on", True) == ["firewall-on", "guest-off"], "the helper's order"
    assert posture_fix.set_fix("guest-off", False) == ["firewall-on"]
    assert posture_fix.plan_part(False)["posture_fixes"] == [], "off: the helper undoes every fix"
    assert posture_fix.request_refresh() == 1 and posture_fix.plan_part(True)["posture_refresh"] == 1


def test_the_tamper_guard_is_opt_in_and_strict():
    assert tamper_guard.is_on() is False
    with pytest.raises(ShieldApiError):
        tamper_guard.set_on("yes")
    tamper_guard.set_on(True)
    assert tamper_guard.plan_part(True) == {"tamper_guard": True}
    assert tamper_guard.plan_part(False) == {"tamper_guard": False}


def test_the_posture_read_scores_the_helpers_facts(monkeypatch):
    monkeypatch.setattr(enforcement, "summary", lambda: {"running": True, "dns_active": True, "firewall_active": True})
    body = {"watching": True, "exposure": [], "persistence": [], "tamper": None, "posture": {**SAFE, "firewall": "off"},
            "fixes": ["stealth-on"], "events": []}
    system_report.record(system_report.validate(body, NOW))
    monkeypatch.setattr(system_report, "snapshot", lambda now=None: system_report.read_json_object(system_report._path())["snapshot"])
    answer = system_api.posture_read(None, {})
    assert answer["checked"] and 0 < answer["score"] < 100
    assert answer["applied"] == ["stealth-on"]
    assert next(c for c in answer["checks"] if c["id"] == "firewall")["status"] == "bad"
