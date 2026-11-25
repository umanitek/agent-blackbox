"""macOS notification permission is asked only of a person who is there, and Blackbox never says
"shown" when macOS did not show it (KI-PENDING-411cdb, VM pass 3, 2026-11-22).

Seen on the VM: the installer, run over SSH, ran the notifier's ``request`` directly — macOS
answered "denied" with no question; a question shown in the person's session but left unanswered
was recorded as Off for good, with nothing pointing the person at System Settings; and
``blackbox notifications test`` said "shown" while screen sharing hid every banner.

Contracts: the question is asked only through LaunchServices and only when the person is at the
desktop (an installer outside their session defers it to the dashboard's card); sending never
asks; while permission is off or not asked yet the status names the way to System Settings
(``settings`` / ``settings_label``, the names a companion app reads) and a security notice still
reaches the person through the labelled script notifier; every send answers what became of it,
kept on the notice in the feed. The real macOS question is proven on the VM, never on a person's
own Mac: here the notifier, ``open`` and ``osascript`` are stand-in scripts.
"""

from __future__ import annotations

import argparse
import sys

import pytest

from plugins.blackbox import notify
from plugins.blackbox.notify import deliver, feed, policy
from plugins.blackbox.notify.model import Delivery, NotifierStatus
from plugins.blackbox.setup import notifier as notifier_cli

mac_only = pytest.mark.skipif(sys.platform != "darwin", reason="the macOS notifier")


@pytest.fixture(autouse=True)
def _fresh():
    feed.reset()
    deliver.claim("", 0)
    yield
    feed.reset()


def _script(path, body):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("#!/bin/sh\n" + body, encoding="utf-8")
    path.chmod(0o755)
    return path


@pytest.fixture
def mac(tmp_path, monkeypatch):
    """A stand-in notifier app whose permission answer is ``tmp/permission`` and whose send exit
    code follows it; ``open`` and ``osascript`` stand-ins that log what they were asked."""
    from plugins.blackbox.notify.platform import macos
    from plugins.blackbox.notify.platform.macos import session
    log = tmp_path / "log"
    log.write_text("", encoding="utf-8")
    (tmp_path / "permission").write_text("not-determined", encoding="utf-8")
    monkeypatch.setattr(macos, "home", lambda: tmp_path / "notifier")
    _script(tmp_path / "notifier" / "Blackbox.app" / "Contents" / "MacOS" / "blackbox-notify", f"""
p=$(cat {tmp_path}/permission); echo "app $*" >> {log}
case "$1" in
  status) echo "$p";;
  display) echo single;;
  request) echo authorized;;
  send) case "$p" in authorized) echo sent;; denied) echo denied; exit 3;; *) echo not-determined; exit 5;; esac;;
esac
""")
    monkeypatch.setattr(macos, "OPEN", str(_script(tmp_path / "bin" / "open", f'echo "open $*" >> {log}\n')))
    monkeypatch.setattr(macos, "OSASCRIPT", str(_script(tmp_path / "bin" / "osascript", f'echo "osascript" >> {log}\n')))
    monkeypatch.setattr(session, "screen_shared", lambda: False)
    monkeypatch.setattr(session, "console_is_ours", lambda: True)
    monkeypatch.setattr(session, "in_desktop_session", lambda: False)

    class Mac:
        module = macos
        sessions = session

        @staticmethod
        def permission(word):
            (tmp_path / "permission").write_text(word, encoding="utf-8")

        @staticmethod
        def calls():
            return log.read_text(encoding="utf-8").splitlines()
    return Mac


@mac_only
def test_the_installer_outside_the_persons_desktop_session_never_asks(mac):
    status = mac.module.request() if mac.sessions.in_desktop_session() else mac.module.status()
    assert not any(call.startswith(("app request", "open")) for call in mac.calls())
    assert status.permission == "not-determined" and status.can_ask is True
    assert "dashboard" in status.detail and "script notifier" in status.detail


@mac_only
def test_install_over_ssh_defers_the_question_and_in_the_persons_session_asks_through_launchservices(mac, tmp_path, monkeypatch):
    import hashlib
    import zipfile
    archive = tmp_path / "blackbox-notify-darwin.zip"
    with zipfile.ZipFile(archive, "w") as packed:
        packed.write(tmp_path / "notifier" / "Blackbox.app" / "Contents" / "MacOS" / "blackbox-notify",
                     "Blackbox.app/Contents/MacOS/blackbox-notify")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    mac.module.install(archive, digest)                  # over SSH: in_desktop_session() is False
    assert not any(call.startswith(("app request", "open")) for call in mac.calls())
    monkeypatch.setattr(mac.sessions, "in_desktop_session", lambda: True)
    status = mac.module.install(archive, digest)         # the person ran the installer at their Mac
    opened = [call for call in mac.calls() if call.startswith("open")]
    assert opened == [f"open -n -g {tmp_path / 'notifier' / 'Blackbox.app'} --args request"]
    assert not any(call.startswith("app request") for call in mac.calls())   # never run directly
    assert "asking now" in status.detail


@mac_only
def test_the_dashboards_allow_asks_only_while_the_person_is_logged_in_and_only_once(mac, monkeypatch):
    monkeypatch.setattr(mac.sessions, "console_is_ours", lambda: False)
    assert mac.module.request().can_ask is False
    assert not any(call.startswith("open") for call in mac.calls())
    monkeypatch.setattr(mac.sessions, "console_is_ours", lambda: True)
    mac.module.request()
    assert sum(call.startswith("open") for call in mac.calls()) == 1
    mac.permission("denied")
    status = mac.module.request()                        # asked before: macOS would not ask again
    assert sum(call.startswith("open") for call in mac.calls()) == 1
    assert status.settings == "x-apple.systempreferences:com.apple.Notifications-Settings.extension?id=ai.umanitek.blackbox.notifier"
    assert status.settings_label == "Open Notification settings for Blackbox" and "switched off" in status.detail


@mac_only
def test_sending_never_asks_and_a_security_notice_still_reaches_the_person(mac):
    critical = mac.module.send("Blackbox stopped Claude Code", "body", "critical", "finding:x")
    info = mac.module.send("Claude Code started", "body", "info", "start:x")
    assert (critical.outcome, info.outcome) == ("fallback", "not-shown")
    assert "not allowed" in critical.detail and "script notifier" in critical.detail
    assert "did not show it" in info.detail
    assert [call for call in mac.calls() if call.startswith("osascript")] == ["osascript"]
    assert not any(call.startswith(("app request", "open")) for call in mac.calls())


@mac_only
def test_delivered_says_notification_center_and_a_shared_screen_is_named(mac, monkeypatch):
    mac.permission("authorized")
    assert mac.module.send("t", "b", "info", "i") == Delivery("delivered", "Delivered to Notification Center.")
    monkeypatch.setattr(mac.sessions, "screen_shared", lambda: True)
    shared = mac.module.send("t", "b", "info", "i")
    assert shared.outcome == "delivered" and "shared or mirrored" in shared.detail and "Notification Center" in shared.detail
    assert mac.module.status().screen_hidden is True


def test_the_feed_keeps_what_became_of_each_notice():
    def finding(ts):
        return {"identifier": "escalation:x", "category": "escalation", "severity": "critical", "title": "x", "evidence": "",
                "framework": "claude-code", "workspace": "/w/p", "source": "public", "decision": "block", "ts": ts,
                "session_id": "claude-code:aaaaaaaaaaaaaaaa", "tool_call_id": "t1", "fields": {}}
    from plugins.blackbox.notify import sources
    findings: list = []
    collector = sources.Collector(read_findings=lambda: list(findings), read_alerts=list, read_live=lambda: {"products": []})
    pump = deliver.Pump(collector=collector, send=lambda notice, details: Delivery("not-shown", "macOS did not show it."),
                        read_policy=lambda: policy.parse({}))
    now = 1_795_000_000.0
    pump.step(now)
    findings.append(finding(now + 1))
    pump.step(now + 1)
    assert [row["delivery"] for row in notify.history()] == ["not-shown"]
    feed.reset()                                          # a restart reads it back
    assert [row["delivery"] for row in notify.history()] == ["not-shown"]


def _cli(*words):
    parser = argparse.ArgumentParser()
    notifier_cli.add_notifications_parser(parser.add_subparsers())
    args = parser.parse_args(["notifications", *words])
    return args.func(args)


def test_the_test_command_never_says_shown_when_macos_did_not_show_it(monkeypatch, capsys):
    off = NotifierStatus("app", True, "denied", "Notifications are switched off for Blackbox.",
                         "x-apple.systempreferences:example", "Open Notification settings for Blackbox")
    monkeypatch.setattr(notify, "notifier_status", lambda: off)
    monkeypatch.setattr(notify, "send_test", lambda: Delivery("not-shown", "macOS did not show it: notifications are off for Blackbox."))
    assert _cli("test") == 1
    out = capsys.readouterr().out
    assert "shown." not in out and "did not show it" in out and "Open Notification settings for Blackbox" in out
    monkeypatch.setattr(notify, "send_test", lambda: Delivery("delivered", "Delivered to Notification Center."))
    assert _cli("test") == 0 and "Delivered to Notification Center." in capsys.readouterr().out
    assert _cli("status") == 0 and "x-apple.systempreferences:example" in capsys.readouterr().out


def test_the_routes_ask_open_settings_and_report_the_delivery(monkeypatch):
    from fastapi.testclient import TestClient

    from plugins.blackbox.dashboard import server
    asked = []
    monkeypatch.setattr(notify, "request_permission", lambda: asked.append("ask") or NotifierStatus("app", True, "not-determined", "asking"))
    monkeypatch.setattr(notify, "open_notification_settings", lambda: asked.append("settings") or True)
    monkeypatch.setattr(notify, "send_test", lambda: Delivery("not-shown", "macOS did not show it."))
    monkeypatch.setattr(notify, "notifier_status", lambda: NotifierStatus("app", True, "denied", "off", "x-apple:s", "Open"))
    client = TestClient(server.create_app(), base_url="http://127.0.0.1:9700")
    token = client.get("/api/session").json()["token"]
    headers = {"X-Blackbox-Token": token}
    assert client.post("/api/notifications/allow", headers=headers).json()["notifier"]["detail"] == "asking"
    assert client.post("/api/notifications/settings", headers=headers).json() == {"opened": True}
    test = client.post("/api/notifications/test", headers=headers).json()
    assert test["sent"] is False and test["delivery"]["outcome"] == "not-shown"
    assert client.post("/api/notifications/allow").status_code == 403        # a web page cannot ask
    policy_view = client.get("/api/notifications/policy").json()["notifier"]
    assert (policy_view["settings"], policy_view["settings_label"]) == ("x-apple:s", "Open")
    assert asked == ["ask", "settings"]
    assert "notify-allow-root" in client.get("/").text and client.get("/notify-allow.js").status_code == 200


# ---- the notifier's icon is the dashboard's Blackbox mark (VM pass 3 NOTE) ---------------------

@pytest.mark.skipif(sys.platform != "darwin" or not __import__("shutil").which("swiftc"), reason="builds with Xcode's tools")
def test_the_notifier_icon_is_the_blackbox_mark_on_a_transparent_ground(tmp_path):
    """Pass 3 saw a white tile with a tiny "umanitek" wordmark: the build drew the wide wordmark
    SVG through a thumbnailer that paints a white ground. The icon is now the dashboard's own
    Blackbox mark — dark rounded square, light rim, orange record dot — with its corners clear."""
    import subprocess
    image = pytest.importorskip("PIL.Image")
    from plugins.blackbox.notify.platform import macos
    script = __import__("pathlib").Path(macos.__file__).with_name("icon.sh")
    icns = tmp_path / "Blackbox.icns"
    subprocess.run([str(script), str(icns)], check=True, capture_output=True, timeout=300)
    subprocess.run(["/usr/bin/sips", "-s", "format", "png", str(icns), "--out", str(tmp_path / "icon.png")], check=True,
                   capture_output=True, timeout=60)
    with image.open(tmp_path / "icon.png") as drawn:
        pixels = drawn.convert("RGBA")
        width, height = pixels.size
        centre = pixels.getpixel((width // 2, height // 2))
        corner = pixels.getpixel((2, 2))
        body = pixels.getpixel((width // 2, height // 2 + int(height * 0.25)))
    assert centre[0] > 200 and 50 < centre[1] < 120 and centre[2] < 60          # the orange record dot (#FF4F00)
    assert max(body[:3]) < 40 and body[3] == 255                                 # the dark box (#0B0B0D)
    assert corner[3] == 0                                                        # no white tile behind it


def test_the_dashboard_serves_the_blackbox_mark():
    from fastapi.testclient import TestClient

    from plugins.blackbox.dashboard import server
    client = TestClient(server.create_app(), base_url="http://127.0.0.1:9700")
    answer = client.get("/assets/blackbox-mark.svg")
    assert answer.status_code == 200 and answer.headers["content-type"].startswith("image/svg+xml")
    assert "#FF4F00" in answer.text


# ---- only an installed Blackbox reaches the screen (2026-11-22) ---------------------------------

def test_a_blackbox_that_is_not_installed_never_hands_a_notice_to_the_system(monkeypatch):
    """A developer's dashboard on a temporary home showed the founder real notifications about his
    own agents. Without the installer's mark nothing reaches the system; with it, it does."""
    from plugins.blackbox.notify import sources
    shown = []
    monkeypatch.setattr(notify.platform, "send", lambda *args: shown.append(args) or Delivery("delivered", "Delivered."))
    findings: list = []
    collector = sources.Collector(read_findings=lambda: list(findings), read_alerts=list, read_live=lambda: {"products": []})
    pump = deliver.Pump(collector=collector, read_policy=lambda: policy.parse({}))   # the real notifier path
    now = 1_795_000_000.0
    pump.step(now)
    findings.append({"identifier": "escalation:x", "category": "escalation", "severity": "critical", "title": "x", "evidence": "",
                     "framework": "codex", "workspace": "/w/p", "source": "public", "decision": "block", "ts": now + 1,
                     "session_id": "codex:aaaaaaaaaaaaaaaa", "tool_call_id": "t1", "fields": {}})
    pump.step(now + 1)
    assert shown == [] and len(notify.history()) == 1 and feed.delivered() == feed.top()
    assert notify.send_test().outcome == "not-shown" and "not an installed Blackbox" in notify.notifier_status().detail
    notify.install_notifier(None)                            # the installer's step marks this home
    findings.append({**findings[0], "identifier": "escalation:y", "ts": now + 2, "tool_call_id": "t2"})
    pump.step(now + 2)
    assert len(shown) == 1
    notify.remove_notifier()
    assert not feed.delivers_here()
