"""The plugin reads the Linux helper's system report: its startup-item kinds, its posture facts and
checks, and the words for each kind (Linux deep layers step 9: the Linux system watch now runs).

Before, Network Shield's report validation knew only macOS's item kinds and posture keys: the
first report of the Linux helper (``platform/linux/system_guard.rs``) — a systemd user unit, say —
was refused whole, and the posture page knew FileVault, Gatekeeper and SIP only.
"""

from __future__ import annotations

import time

from plugins.blackbox.shields.network.monitor import exposure, posture, system_report
from plugins.blackbox.shields.network.respond import startup_items

#: A report as the Linux helper sends it (system_guard.rs Watchers::report, posture.rs look).
LINUX_REPORT = {
    "watching": True, "at": 0, "exposure": [], "fixes": [],
    "persistence": [{"kind": "user-unit", "id": "/home/admin/.config/systemd/user/x.service", "label": "x", "program": "/tmp/x"},
                    {"kind": "root-config", "id": "/etc/sudoers.d/90-cloud", "label": "90-cloud", "program": ""}],
    "tamper": {"dns_servers": ["127.0.0.53"], "proxy": ["http"], "vpn_count": 1, "firewall": "on", "helper_files": 2},
    "posture": {"disk_encryption": "off", "firewall": "on", "secure_boot": "on", "updates": {"automatic": "on"},
                "remote_login": True, "screen_sharing": False, "file_sharing": False, "autologin": "off",
                "ssh_password_logins": "yes", "passwordless_sudo": "yes"},
    "events": [{"kind": "persistence-new", "ts": 0, "item_kind": "systemd-unit", "id": "/etc/systemd/system/evil.service",
                "label": "evil", "program": "/usr/local/bin/evil"}],
}


def _validated() -> dict:
    now = time.time()
    body = {**LINUX_REPORT, "at": now, "events": [{**event, "ts": now} for event in LINUX_REPORT["events"]]}
    return system_report.validate(body, now)


def test_the_linux_helpers_report_is_accepted():
    report = _validated()
    assert [item["kind"] for item in report["persistence"]] == ["user-unit", "root-config"]
    assert report["events"][0]["item_kind"] == "systemd-unit"
    assert report["posture"]["os"] == "linux" and report["posture"]["updates_automatic"] == "on"


def test_linux_posture_reads_as_linux_checks():
    checks = {check["id"]: check for check in posture.checks(_validated()["posture"], {"running": True})}
    assert checks["disk-encryption"]["status"] == "bad" and checks["linux-firewall"]["status"] == "ok"
    assert checks["ssh-passwords"]["status"] == "bad" and checks["passwordless-sudo"]["status"] == "bad"
    assert checks["remote-login"]["status"] == "bad" and checks["autologin"]["status"] == "ok"
    assert not {"filevault", "gatekeeper", "sip", "airdrop", "stealth"} & set(checks), "no macOS checks on Linux"
    assert all(not check["fix"] and not check["settings"] for check in checks.values()), "report-only on Linux (F8)"
    assert posture.score(list(checks.values())) is not None


def test_each_linux_kind_has_words_and_an_unknown_writers_change_is_high():
    for kind in ("systemd-unit", "user-unit", "autostart", "dbus-service", "session-start", "root-config"):
        assert kind in exposure.ITEM_NAMES and kind in system_report.ITEM_KINDS
        assert startup_items.grade({"kind": "persistence-new", "item_kind": kind, "program": "/usr/bin/x"}, None) == "high"


def test_macos_reports_read_as_before():
    now = time.time()
    report = system_report.validate({"watching": True, "at": now, "posture": {"filevault": "on", "sip": "on"}}, now)
    assert "os" not in report["posture"] and posture.checks(report["posture"], {})[0]["id"] == "filevault"


def test_a_linux_notice_never_calls_the_machine_a_mac(monkeypatch):
    """Linux round L8 (BB-LINUX-PENDING-b23ba7): with passwordless sudo the notice said "Any program
    on this Mac" on Ubuntu. Every notice names the machine by ``kernel.os_layout.machine_words``."""
    import importlib
    import sys

    from plugins.blackbox.shields.network import notices
    monkeypatch.setattr(sys, "platform", "linux")
    linux = importlib.reload(notices)
    try:
        monkeypatch.setattr(linux.system_report, "snapshot", lambda: {"posture": {"passwordless_sudo": "yes"}, "at": 1})
        monkeypatch.setattr(linux.api, "alerts", list)
        [sudo] = linux.shield_alerts()
        assert "this computer" in sudo.text and "this computer" in sudo.detail
        said = [sudo.text, sudo.detail] + [text for kind, (_title, text) in linux.WORDS.items() if kind != "firewall-changed"]
        assert not [text for text in said if "Mac" in text]
    finally:
        monkeypatch.undo()
        importlib.reload(notices)
