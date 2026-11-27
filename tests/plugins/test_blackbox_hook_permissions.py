"""The HOOK-route sandbox permissions decide the findings they name, for the acting agent in its
folder (``guard.hooks._would_block`` over ``shields.hook_permissions``; design "Sandbox permissions",
2026-11-27).

* ``startup-items`` / ``shell-startup``: blocked (the default) — refused in every mode, as before;
  allowed for one agent — that agent's write is recorded as a flag naming the permission, every
  other agent is still refused.
* ``root-writes``: blocked — refused in Block mode; allowed — a flag.
* ``vulnerable-packages``: allowed (the default) — a vulnerability never blocks, as before;
  blocked — it blocks in Block mode at the threshold.
* A setting that can not be read decides every such finding BLOCK (LES-159).
* Blackbox's own PATH block in a shell startup file stays self-protection's whatever the person allows.
* A HOOK permission never opens the sandbox: the profile's allowances are unchanged.
* Allowing one is a loosening that waits for the person (``permissions.judge``).
"""

from __future__ import annotations


import pytest

from plugins.blackbox import ruleset as ruleset_mod
from plugins.blackbox import shields
from plugins.blackbox.agent_hooks.protect import events, runner
from plugins.blackbox.detection import Finding, script_files
from plugins.blackbox.guard import background as guard_background
from plugins.blackbox.guard import hooks
from plugins.blackbox.guard import reporting as guard_reporting
from plugins.blackbox.kernel import config as config_mod, shell_path
from plugins.blackbox.kernel.config import BlackboxConfig
from plugins.blackbox.ruleset import Ruleset
from plugins.blackbox.shields.files.sandbox import permissions
from plugins.blackbox.shields.files.sandbox.permissions import Mode, Rule, Scope, Settings, section

STARTUP_ITEM, SHELL_STARTUP, ROOT_WRITE, GUARD_TAMPER = "startup-item", "shell-startup", "root-write", "blackbox-settings"
LAUNCH_AGENT = "echo '<plist/>' > ~/Library/LaunchAgents/com.example.x.plist"


@pytest.fixture
def entry(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    state: dict = {"mode": "audit", "report": False}
    monkeypatch.setattr(config_mod, "_blackbox_entry", lambda: state)
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: Ruleset())
    monkeypatch.setattr(guard_background, "_spawn_osv_discovery", lambda *a, **k: None)
    monkeypatch.setattr(guard_background, "review_tool", lambda *a, **k: None)
    monkeypatch.setattr(guard_reporting, "_report_and_audit", lambda *a, **k: None)
    script_files.forget_all()
    yield state
    script_files.forget_all()


def _allow(state: dict, permission: str, agent: str = "", project: str = "") -> None:
    row = {"permission": permission, "mode": "allow", **({"agent": agent} if agent else {}), **({"project": project} if project else {})}
    state.setdefault("agent_sandbox", {"permissions": []})["permissions"].append(row)


def _verdict(command: str, agent: str = "claude-code", cwd: str = "/tmp") -> dict:
    payload = {"session_id": "perm", "cwd": cwd, "hook_event_name": "PreToolUse", "tool_name": "Bash",
               "tool_input": {"command": ["bash", "-lc", command] if agent == "codex" else command}, "tool_use_id": "t"}
    events._answered.clear()
    return events._verdict(events.validate(runner.summary(agent, "pre_tool", payload)))


def _finding(verdict: dict, matched: str) -> dict:
    return next(finding for finding in verdict["findings"] if finding["matched"] == matched)


@pytest.mark.parametrize("mode_name", ["audit", "block"])
def test_a_startup_item_stays_refused_by_default_in_every_mode(entry, mode_name):
    entry["mode"] = mode_name
    verdict = _verdict(LAUNCH_AGENT)
    assert verdict["decision"] == "block" and "allowed_by_permission" not in _finding(verdict, STARTUP_ITEM)["fields"]


def test_allowing_startup_items_for_one_agent_flags_its_write_and_names_the_permission(entry):
    entry["mode"] = "block"
    _allow(entry, "startup-items", agent="claude-code")
    verdict = _verdict(LAUNCH_AGENT)
    assert verdict["decision"] == "flag" and verdict["blocked"] == [], verdict
    assert _finding(verdict, STARTUP_ITEM)["fields"]["allowed_by_permission"] == "startup-items"   # what its audit row shows
    assert _verdict(LAUNCH_AGENT, agent="codex")["decision"] == "block"   # another agent: still refused


def test_a_project_scoped_allow_holds_only_in_that_project(entry, tmp_path):
    project = tmp_path / "work" / "shop"
    project.mkdir(parents=True)
    _allow(entry, "startup-items", project="~/work/shop")
    assert _verdict(LAUNCH_AGENT, cwd=str(project / "api"))["decision"] == "flag"
    assert _verdict(LAUNCH_AGENT, cwd=str(tmp_path))["decision"] == "block"


def test_shell_startup_is_its_own_permission(entry):
    write = "echo 'export PATH=$PATH:/opt/x' >> ~/.zshrc"
    verdict = _verdict(write)
    assert verdict["decision"] == "block" and _finding(verdict, SHELL_STARTUP)
    _allow(entry, "startup-items")   # the other permission does not open shell startup files
    assert _verdict(write)["decision"] == "block"
    _allow(entry, "shell-startup")
    allowed = _verdict(write)
    assert allowed["decision"] == "flag" and _finding(allowed, SHELL_STARTUP)["fields"]["allowed_by_permission"] == "shell-startup"


def test_blackboxs_own_path_block_stays_protected_with_shell_startup_allowed(entry, tmp_path):
    shell_path.add(tmp_path / "bb" / "sandbox" / "bin", tmp_path)
    assert shell_path.BEGIN in (tmp_path / ".zshrc").read_text(encoding="utf-8")
    _allow(entry, "shell-startup")
    for call in ({"command": "printf 'alias x=y\\n' > ~/.zshrc"}, {"command": "sed -i '' '/Blackbox agent sandbox/d' ~/.zshrc"}):
        verdict = events._verdict(events.validate(runner.summary("claude-code", "pre_tool", {
            "session_id": "perm", "cwd": "/tmp", "hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": call,
            "tool_use_id": "t"})))
        assert verdict["decision"] == "block" and GUARD_TAMPER in {f["matched"] for f in verdict["findings"]}, (call, verdict)


def test_root_writes_follow_their_permission_in_block_mode(entry):
    entry["mode"] = "block"
    command = "echo x | sudo -n tee /usr/local/lib/blackbox-test.conf"
    assert _verdict(command)["decision"] == "block"
    _allow(entry, "root-writes", agent="claude-code")
    verdict = _verdict(command)
    assert verdict["decision"] == "flag" and _finding(verdict, ROOT_WRITE)["fields"]["allowed_by_permission"] == "root-writes"
    # a sudo write to a startup place is still the startup-items permission's: refused
    assert _verdict("echo '* * * * * root true' | sudo -n tee /etc/cron.d/x")["decision"] == "block"


def _vulnerable() -> Finding:
    return Finding(identifier="dep:npm:left-pad@1.0.0", category="dependency", severity="critical", title="vulnerable",
                   matched="left-pad@1.0.0", confirmed=True, source="public", kind="vulnerability")


def test_vulnerable_packages_block_only_when_the_person_blocks_them(entry):
    cfg = BlackboxConfig(mode="block")
    assert hooks._would_block(cfg, [_vulnerable()]) == []   # the default: allowed, as before
    entry["agent_sandbox"] = {"permissions": [{"permission": "vulnerable-packages", "mode": "block"}]}
    assert [f.identifier for f in hooks._would_block(cfg, [_vulnerable()])] == ["dep:npm:left-pad@1.0.0"]
    assert hooks._would_block(BlackboxConfig(mode="audit"), [_vulnerable()]) == []   # Block mode only


def test_an_unreadable_setting_decides_every_hook_permission_block(entry, monkeypatch):
    _allow(entry, "startup-items")

    def broken() -> Settings:
        raise OSError("config.yaml could not be read")
    monkeypatch.setattr(section, "_read", lambda: broken())
    assert shields.hook_permissions("claude-code", "/tmp").unreadable
    assert _verdict(LAUNCH_AGENT)["decision"] == "block"
    assert hooks._would_block(BlackboxConfig(mode="block"), [_vulnerable()]) != []


def test_a_hook_permission_never_opens_the_sandbox(entry):
    everything = Settings(rules=tuple(Rule(each.id, Mode.ALLOW) for each in permissions.PERMISSIONS
                                      if each.route is permissions.Route.HOOK))
    assert permissions.allowances(everything, "claude-code", "/tmp") == permissions.allowances(Settings(), "claude-code", "/tmp")


@pytest.mark.parametrize("permission", ["startup-items", "shell-startup", "root-writes", "unnamed-publisher"])
def test_allowing_a_hook_permission_waits_for_the_person(entry, permission):
    after = Settings(rules=(Rule(permission, Mode.ALLOW, Scope(agent="claude-code")),))
    assert permissions.loosened(Settings(), after), permission
    assert permissions.section_weakening({"permissions": [{"permission": permission, "mode": "allow", "agent": "claude-code"}]})


def test_the_audit_row_of_the_hermes_hook_names_the_permission(entry, monkeypatch, tmp_path):
    rows: list = []
    monkeypatch.setattr(guard_reporting, "_report_and_audit", lambda cfg, event, findings, detail: rows.append((findings, detail)))
    monkeypatch.setattr(hooks.host_process, "facts", lambda *a, **k: {"cwd": str(tmp_path), "pid": 1, "launch": "interactive"})
    _allow(entry, "startup-items", agent="hermes")
    assert hooks.on_pre_tool_call(tool_name="terminal", args={"command": LAUNCH_AGENT}) is None
    [(findings, detail)] = rows
    assert detail["decision"] == "flag" and findings[0].fields["allowed_by_permission"] == "startup-items"
