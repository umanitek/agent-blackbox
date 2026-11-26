"""An agent may not read Blackbox's keys — any tool, any spelling, in every mode.

E2E 2026-11-21 (bb-final-1121): a shell command could read the key that signs the system
protection helper's plans and reports; only a file tool's read of that path was refused, and only
by the person's own protected-path list. The rule now lives in Blackbox's self-protection
(``detection/paths/guard_secrets.py``): the helper's key folder is sealed, and the contents of
Blackbox's data folders may not be read. Listing a data folder stays ordinary work.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

import pytest

from _blackbox_loader import load_blackbox

guard = load_blackbox("guard")
hooks = load_blackbox("guard.hooks")
guard_background = load_blackbox("guard.background")
config_mod = load_blackbox("kernel.config")
ruleset_mod = load_blackbox("ruleset")
guard_secrets = load_blackbox("detection.paths.guard_secrets")
system_helper = load_blackbox("kernel.system_helper")

_HELPER_PLATFORM = Path(__file__).resolve().parents[2] / "plugins" / "blackbox" / "kernel" / "system_helper" / "platform"


def _helper_places(system: str):
    """That OS's helper places (``kernel/system_helper/platform/<os>.py``), whatever OS runs the test:
    the commands below spell the macOS key folder, so the guard is judged on a faked Mac, and the
    Linux key folder has its own test (CI runs on Linux, where the facade reads ``linux.py``)."""
    spec = importlib.util.spec_from_file_location(f"guard_secrets_helper_{system}", _HELPER_PLATFORM / f"{system}.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

KEY_FOLDER = "~/Library/Application Support/Blackbox/helper"
OWN_RULE = "blackbox-settings"


@pytest.fixture
def machine(monkeypatch, tmp_path):
    monkeypatch.setattr(system_helper, "user_key_folder", _helper_places("macos").user_key_folder)
    hermes = tmp_path / ".hermes"
    (hermes / "blackbox").mkdir(parents=True)
    (hermes / "blackbox" / "reporter.key").write_text("k", encoding="utf-8")
    key_folder = tmp_path / "Library" / "Application Support" / "Blackbox" / "helper"
    key_folder.mkdir(parents=True)
    (key_folder / "plan.key").write_bytes(b"\x07" * 32)
    (tmp_path / "projects").mkdir()
    os.symlink(key_folder, tmp_path / "projects" / "innocent")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("HERMES_HOME", str(hermes))
    monkeypatch.delenv("BLACKBOX_HOME", raising=False)
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: ruleset_mod.Ruleset())
    monkeypatch.setattr(guard_background, "_spawn_llm_review", lambda *a, **k: None)
    monkeypatch.setattr(hooks, "_config", lambda: config_mod.BlackboxConfig(mode="audit", report=False, protected_paths=()))
    return tmp_path


def _refused(tool, args) -> bool:
    verdict = guard.tool_call_verdict(tool, args)
    return verdict["decision"] == "block" and any(f["matched"] == OWN_RULE for f in verdict["findings"])


@pytest.mark.parametrize("command", [
    "cat ~/Library/Application\\ Support/Blackbox/helper/plan.key",
    'xxd "$HOME/Library/Application Support/Blackbox/helper/plan.key"',
    "base64 < ~/'Library/Application Support/Blackbox/helper/plan.key'",
    "cp ~/Library/Application\\ Support/Blackbox/helper/plan.key /tmp/k",
    "cat ~/Library/Application\\ Support/Blackbox/helper/*",
    "cat ~/library/application\\ support/blackbox/HELPER/plan.key",             # macOS folders ignore case
    "cd ~/Library/Application\\ Support/Blackbox && cat helper/plan.key",
    "cat ~/projects/innocent/plan.key",                                        # a link to the key folder
    "python3 -c \"print(open('/'.join([__import__('os').path.expanduser('~'), 'Library/Application Support', 'Blackbox', 'helper', 'plan.key'])).read())\"",
    "cat ~/.hermes/blackbox/reporter.key",
    "grep -r . ~/.hermes/blackbox",
    "tar -czf /tmp/backup.tgz ~/.hermes",       # a whole folder holding the reporter key (was ordinary before 2026-11-21)
    "grep -rn BEGIN ~/.hermes/",                # a recursive search prints the key
    "cp -r ~ /tmp/home-copy",
    "find ~/.hermes -name '*.key' -exec cat {} \\;",
    "bash -c 'cat ~/.hermes/blackbox/reporter.key'",
])
def test_a_shell_read_of_blackboxs_keys_is_refused_in_audit_mode(machine, command):
    if "HELPER" in command and sys.platform not in ("darwin", "win32"):
        pytest.skip("on a case-sensitive system the other spelling names another folder")
    assert _refused("terminal", {"command": command})


@pytest.mark.parametrize("tool,args", [
    ("read_file", {"path": f"{KEY_FOLDER}/plan.key"}),
    ("Read", {"file_path": f"{KEY_FOLDER}/plan.key"}),
    ("Grep", {"pattern": ".", "path": "~/.hermes/blackbox"}),
    ("execute_code", {"code": "import pathlib; print((pathlib.Path.home()/'Library'/'Application Support'/'Blackbox'/'helper'/'plan.key').read_bytes())"}),
    ("process", {"action": "start", "command": "cat ~/.hermes/blackbox/reporter.key"}),
])
def test_any_tool_reading_blackboxs_keys_is_refused(machine, tool, args):
    assert _refused(tool, args)


@pytest.mark.parametrize("tool,args", [
    ("terminal", {"command": "ls ~/.hermes/blackbox"}),
    ("terminal", {"command": "ls -la ~/.hermes/blackbox/*"}),
    ("terminal", {"command": "tail -n 50 ~/.hermes/blackbox/audit.jsonl"}),          # Blackbox's records stay readable
    ("read_file", {"path": "~/.hermes/blackbox/findings.jsonl"}),
    ("terminal", {"command": "find ~ -name '*.md' -exec grep -l todo {} +"}),        # picks no key file
    ("terminal", {"command": "cp ~/notes.txt ~/projects/"}),
    ("terminal", {"command": "grep -r TODO ./src"}),
    ("terminal", {"command": "tar czf /tmp/src.tgz ~/projects"}),
    ("terminal", {"command": "cat ~/Library/Application\\ Support/Code/User/settings.json"}),
    ("Glob", {"pattern": "**/*.py", "path": "~"}),
    ("read_file", {"path": "~/projects/app/README.md"}),
])
def test_ordinary_work_near_blackbox_is_not_refused(machine, tool, args):
    verdict = guard.tool_call_verdict(tool, args)
    assert not any(f["matched"] == OWN_RULE for f in verdict["findings"]), verdict


def test_the_key_folder_is_also_guarded_against_change(machine):
    assert _refused("terminal", {"command": "mv ~/Library/Application\\ Support/Blackbox/helper /tmp/x"})


@pytest.mark.parametrize("tool,args", [
    ("terminal", {"command": "cat ~/.config/blackbox/helper/plan.key"}),
    ("terminal", {"command": "cp -r ~/.config/blackbox/helper /tmp/k"}),
    ("terminal", {"command": "tar czf /tmp/c.tgz ~/.config"}),
    ("read_file", {"path": "~/.config/blackbox/helper/plan.key"}),
    ("terminal", {"command": "mv ~/.config/blackbox/helper /tmp/x"}),
])
def test_on_linux_the_key_folder_under_xdg_config_is_guarded_alike(machine, monkeypatch, tool, args):
    """Linux keeps the helper's key in ``$XDG_CONFIG_HOME/blackbox/helper`` (``platform/linux.py``):
    the same refusal, by every tool, whatever OS runs the test."""
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setattr(system_helper, "user_key_folder", _helper_places("linux").user_key_folder)
    folder = machine / ".config" / "blackbox" / "helper"
    folder.mkdir(parents=True)
    (folder / "plan.key").write_bytes(b"\x07" * 32)
    assert _refused(tool, args)


@pytest.mark.parametrize("command", ["tar -czf /tmp/b.tgz ~/.hermes", "grep -rn mode ~/.hermes/"])
def test_a_whole_folder_read_says_it_would_read_the_keys_and_what_to_do_instead(machine, command):
    """Fix wave 2, 2026-11-21: these were refused as "Change to Blackbox's own settings" with no
    reason; the refusal now says it would read Blackbox's key files and names a form that passes."""
    verdict = guard.tool_call_verdict("terminal", {"command": command})
    assert verdict["decision"] == "block"
    message = verdict["message"]
    assert "Would read Blackbox's key files" in message and "Change to Blackbox's own settings" not in message
    assert "Name only the files you need" in message
    own = [f for f in verdict["findings"] if f["matched"] == OWN_RULE]
    assert own and own[0]["advice"] == guard_secrets.ADVICE


@pytest.mark.parametrize("command", ["tar -czf /tmp/b.tgz ~/.hermes/config.yaml", "grep -rn mode ~/.hermes/config.yaml"])
def test_the_form_the_advice_names_is_allowed(machine, command):
    (machine / ".hermes" / "config.yaml").write_text("mode: block\n", encoding="utf-8")
    assert not _refused("terminal", {"command": command})
