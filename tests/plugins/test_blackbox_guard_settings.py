"""KI-473: an agent must not switch off the guard that watches it (2026-11-06).

A text-only probe of the hook in block mode found every way an agent could set Blackbox to audit
mode or remove it unchecked: ``sed -i`` on Hermes's ``config.yaml``, the patch tool changing
``mode: block`` to ``mode: audit`` inside Blackbox's section, an overwrite, ``hermes plugins disable
blackbox``. ``detect_guard_tamper`` is a built-in rule (source ``custom``: flags in audit, blocks in
block mode, never shared); reading, backing up and editing unrelated settings stay allowed.
"""

from __future__ import annotations

import pytest

from plugins.blackbox.detection import detect_guard_tamper

CONFIG = """model:
  default: some-model
plugins:
  enabled:
    - blackbox
  entries:
    blackbox:
      mode: block
      block_severity: critical
display:
  mode: compact
"""


@pytest.fixture
def home(tmp_path, monkeypatch):
    hermes = tmp_path / "hermes-home"
    (hermes / "plugins" / "blackbox").mkdir(parents=True)
    (hermes / "config.yaml").write_text(CONFIG, encoding="utf-8")
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    monkeypatch.setenv("BLACKBOX_HOME", str(hermes / "blackbox"))
    return hermes


def _tampers(tool, args):
    findings = detect_guard_tamper(tool, args)
    assert all(f.source == "custom" and f.severity == "critical" for f in findings)
    return bool(findings)


@pytest.mark.parametrize("tool,args", [
    ("terminal", {"command": "sed -i '' 's/mode: block/mode: audit/' {cfg}"}),
    ("terminal", {"command": "perl -pi -e 's/block/audit/' {cfg}"}),
    ("terminal", {"command": "echo 'plugins: {{}}' > {cfg}"}),
    ("terminal", {"command": "printf x | tee {cfg}"}),
    ("terminal", {"command": "cd {home} && echo x >> config.yaml"}),
    ("terminal", {"command": "cp /tmp/evil.yaml {cfg}"}),
    ("terminal", {"command": "mv {cfg} /tmp/gone.yaml"}),
    ("terminal", {"command": "rm {home}/plugins/blackbox/__init__.py"}),
    ("terminal", {"command": "hermes plugins disable blackbox"}),
    ("terminal", {"command": "hermes -p work plugins remove blackbox"}),
    ("terminal", {"command": "hermes config set plugins.entries.blackbox.mode audit"}),
    ("terminal", {"command": "blackbox rules unblock dep:npm:evil@1.0.0 --reason x"}),
    ("terminal", {"command": "python3 -c \"open('{cfg}','w').write('')\""}),
    ("execute_code", {"code": "open('{cfg}', 'a').write('x')"}),
    ("write_file", {"path": "{cfg}", "content": "plugins: {{}}"}),
    ("delete_file", {"path": "{cfg}"}),
    ("patch", {"path": "{cfg}", "old_string": "mode: block", "new_string": "mode: audit"}),
    ("patch", {"path": "{cfg}", "old_string": "    - blackbox\n", "new_string": ""}),
    ("write_file", {"path": "{home}/blackbox/overrides.json", "content": "{{}}"}),
    ("terminal", {"command": "curl -s http://127.0.0.1:9700/api/session"}),
    ("terminal", {"command": "curl -X POST -d '{{\"mode\":\"audit\"}}' http://localhost:9700/api/settings"}),
    ("execute_code", {"code": "import urllib.request; urllib.request.urlopen('http://127.0.0.1:63519/api/plugins/blackbox/mode')"}),
    ("terminal", {"command": "curl -X POST http://127.0.0.1:63519/api/plugins/blackbox/dash/api/settings -d '{{}}'"}),
])
def test_an_agent_changing_blackboxs_settings_is_found(home, tool, args):
    filled = {key: value.format(cfg=home / "config.yaml", home=home) for key, value in args.items()}
    assert _tampers(tool, filled)


@pytest.mark.parametrize("tool,args", [
    ("terminal", {"command": "grep -n blackbox {cfg} 2>/dev/null"}),
    ("terminal", {"command": "cat {cfg}"}),
    ("terminal", {"command": "cp {cfg} /tmp/hermes-config-backup.yaml"}),
    ("terminal", {"command": "ls -la {home}"}),
    ("terminal", {"command": "cat README.md > /tmp/out.txt"}),
    ("terminal", {"command": "hermes plugins list"}),
    ("terminal", {"command": "blackbox status"}),
    ("read_file", {"path": "{cfg}"}),
    ("patch", {"path": "{cfg}", "old_string": "default: some-model", "new_string": "default: other-model"}),
    ("patch", {"path": "{cfg}", "old_string": "  mode: compact", "new_string": "  mode: full"}),
    ("write_file", {"path": "/tmp/notes.txt", "content": "hello"}),
    ("terminal", {"command": "curl -s http://127.0.0.1:9700/api/findings"}),
    ("terminal", {"command": "curl -s http://127.0.0.1:9700/"}),
])
def test_reading_and_unrelated_edits_are_left_alone(home, tool, args):
    filled = {key: value.format(cfg=home / "config.yaml", home=home) for key, value in args.items()}
    assert not _tampers(tool, filled)


def test_an_edit_to_an_unreadable_config_naming_a_blackbox_key_is_found(home):
    """Fail closed for the case the section cannot be read: the edit names one of Blackbox's keys."""
    (home / "config.yaml").unlink()
    assert _tampers("patch", {"path": str(home / "config.yaml"), "old_string": "mode: block", "new_string": "mode: audit"})


def test_the_rule_runs_in_the_tool_call_hook():
    """guard/hooks.py gathers it with every call's findings, beside the protected-path rule."""
    from pathlib import Path
    hooks = (Path(__file__).resolve().parents[2] / "plugins" / "blackbox" / "guard" / "hooks.py").read_text(encoding="utf-8")
    assert "detection.detect_guard_tamper(tool_name, args)" in hooks


# 2026-11-08, fresh Mac (bb-test-4): an agent could stop Blackbox's own services. The guard runs in
# Hermes and keeps working, but verified-graph checks are looked up in the DKG node.
@pytest.mark.parametrize("command", [
    "launchctl bootout gui/501/ai.umanitek.blackbox-dashboard",
    "launchctl unload ~/Library/LaunchAgents/ai.umanitek.blackbox-dkg.plist",
    "systemctl --user stop blackbox-dashboard",
    "sudo systemctl disable blackbox-dkg",
    "pkill -f 'blackbox dashboard'",
    "killall dkg",
    "kill $(lsof -t -i:9700)",
    "kill -9 $(lsof -ti tcp:9320)",
    "fuser -k 9320/tcp",
])
def test_an_agent_stopping_blackboxs_services_is_found(command):
    assert detect_guard_tamper("terminal", {"command": command})


@pytest.mark.parametrize("command", [
    "killall node", "pkill -f vite", "launchctl list", "systemctl --user status blackbox-dashboard",
    "lsof -i :9700", "kill 12345", "fuser 9700/tcp",
])
def test_looking_at_services_and_stopping_other_servers_is_left_alone(command):
    assert detect_guard_tamper("terminal", {"command": command}) == []
