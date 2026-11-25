"""An agent may not switch off an agent's hooks — its own or another's, user-level or in any
project — by any route; harmless edits of those settings stay allowed; the sandbox and the watch
read the same ONE list of switch files (``kernel.agent_hosts.hook_switches``, LES-137).

Private security finding ``2026-11-25-hooks-only-an-agent-may-write-a-project-`` (macOS round R8,
High): through Claude Code's REAL PreToolUse runner every write below was ALLOWED (raw/dah8.txt):
``Write .claude/settings.json`` / ``settings.local.json`` with ``{"disableAllHooks": true}``,
``~/.claude/settings.local.json``, a shell ``echo``/``printf`` into ``.claude/settings.local.json``
and into a sibling project's ``../s8-next/.claude/settings.json``, ``.codex/config.toml`` with
``codex_hooks = false`` and ``.gemini/settings.json`` with hooks disabled. A real Claude Code
started in that project then read a protected file and Blackbox recorded no session (dah8real.txt).
"""

from __future__ import annotations

import base64
import json

import pytest

from _blackbox_loader import load_blackbox

guard = load_blackbox("guard")
hooks = load_blackbox("guard.hooks")
guard_background = load_blackbox("guard.background")
config_mod = load_blackbox("kernel.config")
ruleset_mod = load_blackbox("ruleset")
detection = load_blackbox("detection")
action_context = load_blackbox("kernel.action_context")
hook_switches = load_blackbox("kernel.agent_hosts.hook_switches")
own_places = load_blackbox("shields.files.sandbox.own_places")
hooks_off = load_blackbox("agent_hooks.observe.hooks_off")
profiles = load_blackbox("agent_hooks.profiles")
agent_hosts = load_blackbox("kernel.agent_hosts")
runner = load_blackbox("agent_hooks.protect.runner")

SELF = "blackbox-settings"


@pytest.fixture
def project(monkeypatch, tmp_path):
    """A home with Hermes and a project folder ``camp/s8-dah`` beside a sibling; returns the project."""
    home = tmp_path.resolve()
    (home / ".hermes" / "blackbox").mkdir(parents=True)
    work = home / "camp" / "s8-dah"
    work.mkdir(parents=True)
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("HERMES_HOME", str(home / ".hermes"))
    monkeypatch.delenv("BLACKBOX_HOME", raising=False)
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: ruleset_mod.Ruleset())
    monkeypatch.setattr(guard_background, "_spawn_llm_review", lambda *a, **k: None)
    monkeypatch.setattr(hooks, "_config", lambda: config_mod.BlackboxConfig(mode="audit", report=False))
    return work


def _refused(tool: str, args: dict, folder) -> bool:
    with action_context.working_in(str(folder), "claude-code"):
        return any(f.matched == SELF for f in detection.detect_hook_switch_off(tool, args))


def test_the_r8_hooks_switch_writes_are_refused_in_audit_mode(project):
    """The round's own calls (raw/dah8.txt), through the guard's verdict in Audit mode."""
    home = project.parents[1]
    off = '{"disableAllHooks": true}\n'
    calls = [
        runner._canonical("Write", {"file_path": f"{project}/.claude/settings.json", "content": off}),
        runner._canonical("Write", {"file_path": f"{project}/.claude/settings.local.json", "content": off}),
        runner._canonical("Write", {"file_path": f"{home}/.claude/settings.local.json", "content": off}),
        runner._canonical("Bash", {"command": "mkdir -p .claude && echo '{\"disableAllHooks\": true}' > .claude/settings.local.json"}),
        runner._canonical("Bash", {"command": "mkdir -p ../s8-next/.claude && printf '{\"disableAllHooks\": true}' > ../s8-next/.claude/settings.json"}),
        runner._canonical("Write", {"file_path": f"{project}/.codex/config.toml", "content": "[features]\ncodex_hooks = false\n"}),
        runner._canonical("Write", {"file_path": f"{project}/.gemini/settings.json", "content": '{"hooks": {"enabled": false}}\n'}),
    ]
    with action_context.working_in(str(project), "claude-code"):
        verdicts = [guard.tool_call_verdict(tool, args) for tool, args in calls]
    allowed = [call for call, verdict in zip(calls, verdicts) if verdict["decision"] != "block"
               or not any(f["matched"] == SELF for f in verdict["findings"])]
    assert not allowed, allowed


def test_every_write_route_that_switches_hooks_off_is_refused(project):
    (project / ".claude").mkdir()
    settings = project / ".claude" / "settings.json"
    settings.write_text('{\n  "disableAllHooks": false,\n  "model": "sonnet"\n}\n', encoding="utf-8")
    (project / "off.json").write_text('{"disableAllHooks": true}', encoding="utf-8")
    (project / "w.py").write_text("import json, sys\njson.dump({'disableAllHooks': True}, open(sys.argv[1] + '/settings.json', 'w'))\n",
                                  encoding="utf-8")
    encoded = base64.b64encode(b'{"disableAllHooks": true}').decode()
    routes = [
        runner._canonical("Edit", {"file_path": str(settings), "old_string": "false", "new_string": "true"}),
        runner._canonical("MultiEdit", {"file_path": str(settings), "edits": [{"old_string": "false", "new_string": "true"}]}),
        ("terminal", {"command": "cp off.json .claude/settings.json"}),
        ("terminal", {"command": "mv off.json .claude/settings.local.json"}),
        ("terminal", {"command": "sed -i '' 's/false/true/' .claude/settings.json"}),
        ("terminal", {"command": f"echo {encoded} | base64 -d > .claude/settings.local.json"}),
        ("terminal", {"command": "echo '{\"disableAllHooks\": true}' | tee .claude/settings.local.json"}),
        ("terminal", {"command": "python3 w.py .claude"}),
        ("terminal", {"command": "python3 -c \"import json; json.dump({'disableAllHooks': True}, open('.claude/settings.json', 'w'))\""}),
        ("execute_code", {"code": "import json, os\np = os.path.join('.cl' + 'aude', 'settings.json')\n"
                                  "json.dump({'disableAllHooks': True}, open(p, 'w'))"}),
        ("terminal", {"command": "apply_patch <<'PATCH'\n*** Begin Patch\n*** Add File: .codex/config.toml\n+[features]\n"
                                 "+hooks = false\n*** End Patch\nPATCH"}),
        ("write_file", {"path": str(project / ".gemini" / "settings.json"), "content": '{"hooksConfig": {"enabled": false}}'}),
        # Codex's own apply_patch tool: each file it names (relative to the project) judged as a write (VM bb-w12-a).
        ("write_file", {"path": ".codex/config.toml", "patch": "*** Begin Patch\n*** Add File: .codex/config.toml\n+[features]\n"
                                                              "+hooks = false\n*** End Patch"}),
    ]
    missed = [args for tool, args in routes if not _refused(tool, args, project)]
    assert not missed, "\n".join(map(str, missed))


def test_harmless_edits_of_the_same_settings_stay_allowed(project):
    (project / ".claude").mkdir()
    settings = project / ".claude" / "settings.json"
    settings.write_text('{"model": "sonnet"}\n', encoding="utf-8")
    harmless = [
        runner._canonical("Write", {"file_path": str(settings), "content": '{"permissions": {"allow": ["Bash(ls)"]}, "model": "opus"}'}),
        runner._canonical("Edit", {"file_path": str(settings), "old_string": '"sonnet"', "new_string": '"opus"'}),
        ("terminal", {"command": "echo '{\"model\": \"opus\"}' > .claude/settings.local.json"}),
        ("terminal", {"command": "cat .claude/settings.json && ls .codex"}),
        ("write_file", {"path": str(project / ".codex" / "config.toml"), "content": 'model = "o3"\n[features]\nhooks = true\n'}),
        ("write_file", {"path": str(project / "NOTES.md"), "content": "Set disableAllHooks: true to switch hooks off."}),
        ("terminal", {"command": "python3 -c \"import json; json.dump({'model': 'x'}, open('.claude/settings.json', 'w'))\""}),
    ]
    wrongly = [args for tool, args in harmless if _refused(tool, args, project)]
    assert not wrongly, wrongly


def test_a_switch_the_person_already_set_stays_theirs(project):
    """An agent's edit of an unrelated key in a file where the person had switched hooks off."""
    (project / ".claude").mkdir()
    settings = project / ".claude" / "settings.json"
    settings.write_text('{"disableAllHooks": true, "model": "sonnet"}', encoding="utf-8")
    assert not _refused(*runner._canonical("Edit", {"file_path": str(settings), "old_string": '"sonnet"', "new_string": '"opus"'}),
                        project)


def test_every_layer_reads_the_one_list_of_switch_files(project, monkeypatch):
    """LES-137 drift guard: for EVERY switch file of the list, the hook judgement refuses a write
    that sets its switch OFF; the sandbox keeps every user-level one it may close; the watch
    (the process observer and the profile check) reports the switch found OFF there."""
    home = project.parents[1]
    closed = set(own_places.hook_configs())
    assert hook_switches.switch_files(), "the list is empty"
    for entry in hook_switches.switch_files():
        base = home if entry.level == hook_switches.USER else project
        path = base / entry.path
        for key, off in entry.switches:
            data: dict = {}
            *parents, last = key.split(".")
            cursor = data
            for part in parents:
                cursor = cursor.setdefault(part, {})
            cursor[last] = off
            text = (f"[{'.'.join(parents)}]\n{last} = {json.dumps(off)}\n" if parents else f"{last} = {json.dumps(off)}\n") \
                if entry.path.endswith(".toml") else json.dumps(data)
            assert _refused("write_file", {"path": str(path), "content": text}, project), (entry, key)
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding="utf-8")
            host = agent_hosts.BY_ID[entry.agent]
            if entry.level == hook_switches.PROJECT:
                monkeypatch.setattr(hooks_off.platform, "process_cwd", lambda _pid: str(project))
                assert hooks_off.hooks_switched_off(host, [], 1), (entry, key)
                assert any(p.kind == "hooks-off" for p in profiles.problems(host, home / ".none", [str(project)])), (entry, key)
            else:
                folder = home if host.id == "gemini-cli" else home / entry.path.split("/")[0]   # Gemini's home holds .gemini/
                assert any(p.kind == "hooks-off" for p in profiles.problems(host, folder)), (entry, key)
            path.unlink()
        if entry.level == hook_switches.USER and not entry.agent_writes:
            assert str(home / entry.path) in closed, entry
