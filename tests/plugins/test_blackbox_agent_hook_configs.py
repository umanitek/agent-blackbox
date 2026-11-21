"""Self-protection covers each coding agent's hook config, in the core (2026-11-21: coding-agent
protection moved from the Desktop add-on into the public plugin).

An agent may still edit its own settings file, but not Blackbox's hook in it. That means an edit
touching Blackbox's text, or a whole-file overwrite, is refused. Blackbox's own hook files are
guarded whole: OpenCode's plugin, Copilot's ``blackbox.json`` and Cline's hook scripts.
Without Desktop installed the same holds, because no add-on declares these files any more.
"""

from __future__ import annotations

import json

import pytest

from plugins.blackbox.detection import detect_guard_tamper
from plugins.blackbox.kernel import addons, agent_hosts

RUNNER = "python3 /Users/x/.blackbox/agent-hooks/runner.py claude-code pre_tool http://127.0.0.1:9700"


@pytest.fixture
def home(tmp_path, monkeypatch):
    addons.clear()   # nothing declared by an add-on: the core alone
    home = tmp_path / "home"
    settings = home / ".claude" / "settings.json"
    settings.parent.mkdir(parents=True)
    settings.write_text(json.dumps({"theme": "dark", "hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": RUNNER}]}]}}),
                        encoding="utf-8")
    monkeypatch.setenv("HOME", str(home))
    return home


def _refused(tool, args):
    findings = detect_guard_tamper(tool, args)
    return bool(findings) and all(f.severity == "critical" and f.source == "custom" for f in findings)


def test_an_agent_may_edit_its_own_settings_but_not_blackboxs_hook_in_them(home):
    settings = str(home / ".claude" / "settings.json")
    assert not _refused("patch", {"path": settings, "old_string": '"dark"', "new_string": '"light"'})
    assert _refused("patch", {"path": settings, "old_string": RUNNER, "new_string": ""})
    assert _refused("write_file", {"path": settings, "content": "{}"})
    assert _refused("terminal", {"command": f"rm '{settings}'"})


@pytest.mark.parametrize("agent", [host.id for host in agent_hosts.HOSTS])
def test_every_agents_hook_config_is_guarded(home, agent):
    path = agent_hosts.host(agent).config_path(home)
    assert _refused("write_file", {"path": str(path), "content": ""}), path


def test_blackboxs_own_hook_files_are_guarded_whole(home):
    plugin = agent_hosts.host("opencode").config_path(home)
    assert _refused("patch", {"path": str(plugin), "old_string": "a", "new_string": "b"})
    assert _refused("terminal", {"command": f"rm '{plugin}'"})
