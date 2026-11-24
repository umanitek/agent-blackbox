"""An uninstall leaves no empty file or folder Blackbox made for its hooks (KI-664, Linux round L1:
~/.codex/hooks.json and ~/.gemini/settings.json were left as ``{}``, and empty
~/.config/opencode/plugin, ~/Documents/Cline/Hooks and ~/.config/systemd stayed behind). What the
person had stays exactly as it was.
"""

from __future__ import annotations

import json
from pathlib import Path

from plugins.blackbox.agent_hooks.protect import config_edit, own_files
from plugins.blackbox.kernel import agent_hosts as hosts
from plugins.blackbox.setup.platform import linux as setup_linux

COMMAND = f"/py {config_edit.MARK} x pre_tool http://127.0.0.1:9700"


def test_a_config_blackbox_made_is_removed_and_one_the_person_had_is_kept(tmp_path):
    codex = hosts.BY_ID["codex"]
    assert config_edit.install(codex, tmp_path, {"PreToolUse": COMMAND}).ok
    assert config_edit.uninstall(codex, tmp_path).ok
    assert not codex.config_path(tmp_path).exists(), "made for Blackbox's hooks alone: gone, not left as {}"
    gemini = hosts.BY_ID["gemini-cli"]
    path = gemini.config_path(tmp_path)
    path.parent.mkdir(parents=True)
    path.write_text('{"theme": "dark"}', encoding="utf-8")
    assert config_edit.install(gemini, tmp_path, {"BeforeTool": COMMAND}).ok
    assert config_edit.uninstall(gemini, tmp_path).ok
    assert json.loads(path.read_text(encoding="utf-8")) == {"theme": "dark"}


def test_an_emptied_hook_folder_goes_and_one_with_the_persons_files_stays(tmp_path):
    cline, opencode = hosts.BY_ID["cline"], hosts.BY_ID["opencode"]
    invocations = {event: (["/py", "runner.py"], COMMAND) for event in cline.events}
    assert own_files.install(cline, tmp_path, invocations).ok
    assert own_files.uninstall(cline, tmp_path).ok
    assert not cline.config_path(tmp_path).exists()
    folder = opencode.config_path(tmp_path).parent
    folder.mkdir(parents=True)
    (folder / "mine.js").write_text("// mine\n", encoding="utf-8")
    assert own_files.install(opencode, tmp_path, {event: (["/py", "runner.py"], COMMAND) for event in opencode.events}).ok
    assert own_files.uninstall(opencode, tmp_path).ok
    assert (folder / "mine.js").exists() and not opencode.config_path(tmp_path).exists()


def test_the_empty_systemd_folders_go_after_blackboxs_units(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    user = tmp_path / ".config" / "systemd" / "user"
    (user / "default.target.wants").mkdir(parents=True)
    unit = "blackbox-dashboard.service"
    (user / unit).write_text("[Unit]\n", encoding="utf-8")
    names = type("Names", (), {"systemd_units": (unit,)})()
    setup_linux.stop_login_services(names, (), lambda argv: 0, [])
    assert not (tmp_path / ".config" / "systemd").exists()
    (user / "mine.service").parent.mkdir(parents=True)
    (user / "mine.service").write_text("[Unit]\n", encoding="utf-8")
    (user / unit).write_text("[Unit]\n", encoding="utf-8")
    setup_linux.stop_login_services(names, (), lambda argv: 0, [])
    assert (user / "mine.service").exists(), "the person's own unit and its folders stay"
