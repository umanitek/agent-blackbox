"""Shell startup files are judged apart from the other places something starts from
(``detection.persistence_writes``; design "Sandbox permissions", 2026-11-27): a write to
``~/.zshrc``, ``~/.bashrc``, ``~/.profile`` or fish's start files is ``shell-startup`` with its own
words, so the person's ``shell-startup`` permission decides it apart from ``startup-items``. It is
still refused in every mode by default, still counted as startup tamper and still worded as
something that starts by itself.
"""

from __future__ import annotations

import pytest

from plugins.blackbox import detection
from plugins.blackbox.audit import tamper
from plugins.blackbox.kernel import persistence_places

SHELL_STARTUP, STARTUP_ITEM = "shell-startup", "startup-item"


@pytest.fixture(autouse=True)
def home(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    return tmp_path


def _matched(tool: str, args: dict) -> list[str]:
    return [finding.matched for finding in detection.detect_persistence_write(tool, args)]


@pytest.mark.parametrize("command", [
    "echo 'alias x=y' >> ~/.zshrc", "printf 'export A=1\\n' >> ~/.bashrc", "echo 'true' >> ~/.profile",
    "echo true >> ~/.bash_logout", "mkdir -p ~/.config/fish && echo '# x' >> ~/.config/fish/config.fish",
    "echo true > ~/.config/fish/conf.d/x.fish", "cp evil ~/.zprofile",
])
def test_a_shell_startup_write_is_shell_startup_with_its_own_words(command):
    [finding] = detection.detect_persistence_write("terminal", {"command": command})
    assert finding.matched == SHELL_STARTUP and finding.identifier == "fileaccess:terminal:shell-startup"
    assert finding.title == detection.persistence_writes.SHELL_TITLE and "shell" in finding.advice


def test_a_file_tool_write_to_a_shell_startup_file_is_shell_startup():
    assert _matched("write_file", {"path": "~/.bashrc", "content": "export A=1\n"}) == [SHELL_STARTUP]


@pytest.mark.parametrize("command", ["echo k >> ~/.ssh/authorized_keys", "echo '<plist/>' > ~/Library/LaunchAgents/x.plist",
                                     "echo x >> ~/.xprofile", "echo '* * * * * true' | crontab -"])
def test_every_other_startup_place_stays_a_startup_item(command):
    assert _matched("terminal", {"command": command}) == [STARTUP_ITEM]


def test_reading_a_shell_startup_file_is_nothing():
    assert _matched("terminal", {"command": "cat ~/.zshrc"}) == []


def test_shell_startup_is_refused_in_every_mode_counted_as_tamper_and_worded_as_a_startup_item():
    assert SHELL_STARTUP in detection.ALWAYS_BLOCKED_MATCHES and STARTUP_ITEM in detection.ALWAYS_BLOCKED_MATCHES
    assert tamper.category({"identifier": "fileaccess:terminal:shell-startup", "matched": SHELL_STARTUP}, "pre_tool_call") == tamper.STARTUP
    assert persistence_places.is_startup_item("fileaccess:terminal:shell-startup")


def test_the_shell_places_are_a_part_of_the_startup_places(home):
    places = persistence_places.hook_places(str(home))
    assert places.shell and set(places.shell) <= set(places.starts)
    assert any(place.endswith("/.zshrc") for place in places.shell) and any("/.config/fish/" in place for place in places.shell)
    assert not any(place.endswith("authorized_keys") for place in places.shell)
