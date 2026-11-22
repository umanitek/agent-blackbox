"""``blackbox notifications setup|status|test`` (the plugin's native notifier from the command
line; the installer's step runs ``setup``). A wrong checksum installs nothing and exits 1."""

from __future__ import annotations

import argparse

from plugins.blackbox import notify
from plugins.blackbox.notify.model import Delivery, NotifierStatus
from plugins.blackbox.setup import notifier


def _parse(*words):
    parser = argparse.ArgumentParser()
    notifier.add_notifications_parser(parser.add_subparsers())
    return parser.parse_args(["notifications", *words])


def test_setup_hands_the_archive_and_checksum_to_the_notifier(monkeypatch, capsys, tmp_path):
    asked = []
    monkeypatch.setattr(notify, "install_notifier", lambda source, sha: asked.append((source, sha)) or
                        NotifierStatus("app", True, "authorized", "Notifications appear under Blackbox's own name."))
    args = _parse("setup", "--from", str(tmp_path / "n.zip"), "--sha256", "AB" * 32)
    assert args.func(args) == 0
    assert asked == [(tmp_path / "n.zip", "ab" * 32)]
    assert "under Blackbox's own name" in capsys.readouterr().out


def test_a_checksum_that_does_not_match_exits_1_and_says_why(monkeypatch, capsys):
    def refuse(source, sha):
        raise ValueError("the notifier archive's checksum does not match: nothing was installed")
    monkeypatch.setattr(notify, "install_notifier", refuse)
    args = _parse("setup", "--from", "/tmp/x.zip", "--sha256", "0" * 64)
    assert args.func(args) == 1
    assert "nothing was installed" in capsys.readouterr().out


def test_status_and_test_report_plainly(monkeypatch, capsys):
    monkeypatch.setattr(notify, "notifier_status", lambda: NotifierStatus("fallback", True, "unknown", "Through macOS's script notifier."))
    monkeypatch.setattr(notify, "send_test", lambda: Delivery("not-shown", "macOS did not show it."))
    args = _parse("status")
    assert args.func(args) == 0 and "fallback" in capsys.readouterr().out
    args = _parse("test")
    assert args.func(args) == 1 and "did not show it" in capsys.readouterr().out
