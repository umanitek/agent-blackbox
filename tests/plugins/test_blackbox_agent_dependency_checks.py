"""Every coding agent gets the same three dependency-file checks the Hermes agent gets (KI-602).

Security round 4 (2026-11-23, bb-sec-r4, core b1406e6191, REAL agents, LOCAL test rules): Hermes
got all three of KI-595's checks, Claude Code none of them —

* ``npm install express`` whose lockfile then held the listed ``ms@2.1.3`` (express → debug →
  ms) raised NO after-install alert for Claude Code (s4-depC; Hermes s4-hmdC: a critical flag);
* Claude Code's Edit tool adding ``"left-pad": "1.3.0"`` to package.json was ALLOWED (s4-depD;
  Hermes write_file s4-hmdD: blocked) — its edit reaches the guard as ``content: new_string``;
* a 38.9 MB package-lock.json went through with no "dependencies not checked" note on the Claude
  Code session (s4-depE; Hermes s4-hmdE: noted).

The seam is the guard: ``tool_call_verdict`` answers the notes, ``after_tool_call_verdict`` the
after-install check, and ``agent_hooks.protect.events`` records both on the agent's session — so
each test below drives every agent's OWN hook payload through the real runner and recorder.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from plugins.blackbox import ruleset as ruleset_mod
from plugins.blackbox.agent_hooks.protect import events, runner
from plugins.blackbox.detection.manifests import checks, registry, verdicts
from plugins.blackbox.guard import background as guard_background
from plugins.blackbox.guard import hooks as guard_hooks
from plugins.blackbox.guard import reporting as guard_reporting
from plugins.blackbox.kernel import config as config_mod
from plugins.blackbox.ruleset import Ruleset

#: Round 4's LOCAL test rules, in the shape the compiled ruleset gives them.
RULES = {key: {"identifier": f"dep:{key}-r4test", "severity": "critical", "name": "Malicious package (round-4 TEST rule)",
               "kind": "malware", "source": "public"} for key in ("npm:ms@2.1.3", "npm:left-pad@1.3.0")}
#: What ``npm install express`` wrote (the listed ms@2.1.3 arrives through express → debug).
LOCK = {"lockfileVersion": 3, "packages": {
    "": {"dependencies": {"express": "4.21.2"}},
    "node_modules/express": {"version": "4.21.2", "dependencies": {"debug": "2.6.9"}},
    "node_modules/debug": {"version": "2.6.9", "dependencies": {"ms": "2.1.3"}},
    "node_modules/ms": {"version": "2.1.3"}}}
MANIFEST = json.dumps({"name": "s4-depD", "dependencies": {"express": "^4.18.2"}}, indent=2) + "\n"
OLD = '"express": "^4.18.2"'
NEW = '"express": "^4.18.2",\n    "left-pad": "1.3.0"'
AGENTS = ("claude-code", "codex", "cursor", "gemini-cli", "copilot-cli", "windsurf", "cline", "opencode")


@pytest.fixture
def project(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setenv("HERMES_HOME", str(tmp_path / "hermes"))
    rules = Ruleset()
    rules.dependency = dict(RULES)
    monkeypatch.setattr(guard_hooks, "_config", lambda: config_mod.BlackboxConfig(mode="block", report=False, discover=False))
    monkeypatch.setattr(ruleset_mod, "get", lambda cfg=None: rules)
    monkeypatch.setattr(guard_background, "review_tool", lambda *a, **k: None)
    monkeypatch.setattr(guard_reporting, "_report_and_audit", lambda *a, **k: None)
    for cache in (registry.PARSED, verdicts.VERDICTS, checks.SNAPSHOTS, events._answered):
        cache.clear()   # events._answered: one test's tool-call id is not another's repeat
    folder = tmp_path / "camp" / "projects" / "s4-dep"
    folder.mkdir(parents=True)
    yield folder
    for cache in (registry.PARSED, verdicts.VERDICTS, checks.SNAPSHOTS):
        cache.clear()


def _shell(agent: str, command: str, cwd: Path, output: str = "") -> dict:
    """*agent*'s own shell hook payload (*output* given: its post-tool form)."""
    folder = str(cwd)
    shapes = {
        "claude-code": {"session_id": "s", "cwd": folder, "tool_name": "Bash", "tool_input": {"command": command},
                        "tool_use_id": "t1", **({"tool_response": {"stdout": output}} if output else {})},
        "codex": {"session_id": "s", "cwd": folder, "tool_name": "Bash", "tool_input": {"command": command},
                  "tool_use_id": "t1", **({"tool_response": output} if output else {})},
        "cursor": {"conversation_id": "s", "workspace_roots": [folder], "command": command, **({"output": output} if output else {})},
        "gemini-cli": {"session_id": "s", "cwd": folder, "tool_name": "run_shell_command", "tool_input": {"command": command},
                       **({"tool_response": {"llmContent": output}} if output else {})},
        "copilot-cli": {"sessionId": "s", "cwd": folder, "toolName": "bash", "toolArgs": {"command": command},
                        **({"toolResult": {"resultType": "success", "textResultForLlm": output}} if output else {})},
        "windsurf": {"trajectory_id": "s", "agent_action_name": "post_run_command" if output else "pre_run_command",
                     "tool_info": {"command_line": command, "cwd": folder, **({"output": output} if output else {})}},
        "cline": {"taskId": "s", "workspaceRoots": [folder],
                  **({"postToolUse": {"toolName": "execute_command", "parameters": {"command": command}, "result": output}} if output
                     else {"preToolUse": {"toolName": "execute_command", "parameters": {"command": command}}})},
        "opencode": {"sessionID": "s", "cwd": folder, "tool": "bash", "args": {"command": command}, **({"output": output} if output else {})},
    }
    return shapes[agent]


def _rows(tmp_path: Path, agent: str, event: str) -> list[dict]:
    path = tmp_path / "bb" / f"audit.{agent}.jsonl"
    rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()] if path.exists() else []
    return [row for row in rows if row.get("event") == event]


@pytest.mark.parametrize("agent", AGENTS)
def test_a_listed_package_landing_through_a_named_install_is_a_critical_alert(project, tmp_path, agent):
    command = "npm install express"
    assert events.record_event(runner.summary(agent, "pre_tool", _shell(agent, command, project)))["decision"] == "allow"
    (project / "package-lock.json").write_text(json.dumps(LOCK), encoding="utf-8")   # what npm wrote
    answer = events.record_event(runner.summary(agent, "post_tool", _shell(agent, command, project, "added 69 packages")))
    assert answer["decision"] == "allow"   # it already ran: flagged, never refused
    [row] = _rows(tmp_path, agent, events.LANDED_EVENT)
    [finding] = row["findings"]
    assert finding["severity"] == "critical" and finding["identifier"] == "dep:npm:ms@2.1.3-r4test"
    assert finding["title"].startswith("Installed — ") and "via express → debug → ms@2.1.3" in finding["title"]
    assert row["detail"]["after_install"] is True and row["detail"]["session_id"].startswith(f"{agent}:")


def _writes(agent: str, file: Path) -> list[dict]:
    """*agent*'s own tools adding ``"left-pad": "1.3.0"`` to package.json (each its documented shape)."""
    path, full = str(file), MANIFEST.replace(OLD, NEW)
    patch = f'*** Begin Patch\n*** Update File: package.json\n@@\n   "dependencies": {{\n-    {OLD}\n+    {NEW.replace(chr(10), chr(10) + "+")}\n*** End Patch'
    roots = {"cwd": str(file.parent)}
    shapes = {
        "claude-code": [{"tool_name": "Edit", "tool_input": {"file_path": path, "old_string": OLD, "new_string": NEW}},
                        {"tool_name": "MultiEdit", "tool_input": {"file_path": path, "edits": [{"old_string": OLD, "new_string": NEW}]}},
                        {"tool_name": "Write", "tool_input": {"file_path": path, "content": full}}],
        "codex": [{"tool_name": "apply_patch", "tool_input": {"input": patch}},
                  {"tool_name": "Bash", "tool_input": {"command": f"bash -lc 'apply_patch <<\"PATCH\"\n{patch}\nPATCH'"}}],
        "cursor": [{"tool_name": "Write", "tool_input": {"file_path": path, "content": full}}],
        "gemini-cli": [{"tool_name": "replace", "tool_input": {"file_path": path, "old_string": OLD, "new_string": NEW}}],
        "copilot-cli": [{"toolName": "edit", "toolArgs": {"path": path, "old_str": OLD, "new_str": NEW}}],
        "windsurf": [{"agent_action_name": "pre_write_code", "tool_info": {"file_path": path, "edits": [{"old_string": OLD, "new_string": NEW}]}}],
        "cline": [{"preToolUse": {"toolName": "write_to_file", "parameters": {"path": path, "content": full}}}],
        "opencode": [{"tool": "edit", "args": {"filePath": path, "oldString": OLD, "newString": NEW}}],
    }
    return [{**roots, "session_id": "s", **shape} for shape in shapes[agent]]


@pytest.mark.parametrize("agent", AGENTS)
def test_an_agents_edit_adding_a_listed_package_to_package_json_is_refused(project, agent):
    manifest = project / "package.json"
    for payload in _writes(agent, manifest):
        manifest.write_text(MANIFEST, encoding="utf-8")
        answer = events.record_event(runner.summary(agent, "pre_tool", payload))
        assert answer["decision"] == "block", (agent, payload)
        assert "left-pad@1.3.0" in answer["message"]


@pytest.mark.parametrize("agent", ["claude-code", "opencode"])
def test_an_edit_that_keeps_the_dependencies_is_not_judged_as_adding_one(project, agent):
    manifest = project / "package.json"
    manifest.write_text(MANIFEST, encoding="utf-8")
    payload = _writes(agent, manifest)[0]
    key = "tool_input" if "tool_input" in payload else "args"
    swap = {"old_string": OLD, "new_string": '"express": "^4.19.0"'} if key == "tool_input" else \
        {"oldString": OLD, "newString": '"express": "^4.19.0"'}
    payload[key] = {**payload[key], **swap}
    assert events.record_event(runner.summary(agent, "pre_tool", payload))["decision"] == "allow"


@pytest.mark.parametrize("agent", AGENTS)
def test_what_could_not_be_checked_is_noted_on_the_agents_session(project, tmp_path, monkeypatch, agent):
    monkeypatch.setattr(registry, "MAX_FILE_BYTES", 100)   # round 4's 38.9 MB lockfile, in miniature
    (project / "package-lock.json").write_text(json.dumps(LOCK), encoding="utf-8")
    assert events.record_event(runner.summary(agent, "pre_tool", _shell(agent, "npm ci --dry-run", project)))["decision"] == "allow"
    [row] = _rows(tmp_path, agent, events.NOTES_EVENT)
    assert row["detail"]["session_id"].startswith(f"{agent}:")
    assert any(note.startswith("dependencies not checked: package-lock.json is larger than") for note in row["detail"]["notes"])


def test_a_runtime_asking_the_verdict_gets_the_notes_and_the_after_check():
    """The OpenClaw route's answers carry the same: ``notes`` beside the verdict, and the after-call verdict."""
    from plugins.blackbox import guard
    assert set(guard.ToolCallVerdict.__annotations__) >= {"findings", "blocked", "decision", "message", "notes"}
    assert callable(guard.after_tool_call_verdict)


def test_an_ordinary_post_tool_call_is_not_judged_as_an_install(project, tmp_path):
    answer = events.record_event(runner.summary("claude-code", "post_tool", _shell("claude-code", "ls -la", project, "x")))
    assert answer["decision"] == "allow"
    assert _rows(tmp_path, "claude-code", events.LANDED_EVENT) == []
    assert _rows(tmp_path, "claude-code", events.NOTES_EVENT) == []


#: KI-616 (round 5, REAL Codex 0.171.0, s5-cxap2 / s5-cxdD): Codex's own patch tool reached the hook
#: as a shell call with the patch as apply_patch's ARGUMENT — quoted, or its argv joined — and the
#: patch's ``***`` lines were read as wildcards: every package.json patch was refused as "Change to
#: Blackbox's own settings", a harmless one too.
def _codex_patch_calls(added: str) -> list[dict]:
    patch = f'*** Begin Patch\n*** Update File: package.json\n@@\n   "dependencies": {{\n-    {OLD}\n+    {OLD},\n+    {added}\n   }}\n*** End Patch'
    return [{"tool_name": "Bash", "tool_input": {"command": f"apply_patch '{patch}'"}},
            {"tool_name": "Bash", "tool_input": {"command": ["apply_patch", patch]}}]


def test_a_codex_patch_argument_adding_a_harmless_dependency_is_allowed(project):
    manifest = project / "package.json"
    for payload in _codex_patch_calls('"lodash": "4.17.21"'):
        manifest.write_text(MANIFEST, encoding="utf-8")
        answer = events.record_event(runner.summary("codex", "pre_tool", {"session_id": "s", "cwd": str(project), **payload}))
        assert answer["decision"] == "allow", answer


def test_a_codex_patch_argument_adding_a_listed_dependency_is_refused_for_that_reason(project):
    manifest = project / "package.json"
    for payload in _codex_patch_calls('"left-pad": "1.3.0"'):
        manifest.write_text(MANIFEST, encoding="utf-8")
        answer = events.record_event(runner.summary("codex", "pre_tool", {"session_id": "s", "cwd": str(project), **payload}))
        assert answer["decision"] == "block" and "left-pad@1.3.0" in answer["message"], answer
        assert "self-protection" not in answer["message"] and "own settings" not in answer["message"], answer["message"]


#: KI-640 (security round 6, REAL Codex 0.171.0 gpt-5.4-nano, sandboxed; k616.sh): the round's two
#: patches, byte for byte, on the package.json ``npm init -y`` writes. On the VM the harmless one
#: (s6-k616c) was refused as "Change to Blackbox's own settings" and the one adding the listed
#: left-pad (s6-k616d, the heredoc form) was allowed. Every shape Codex can send them in — its own
#: ``apply_patch`` tool with the patch in ``command`` (as its hooks document), a shell call with the
#: patch as apply_patch's argument (argv or joined), the heredoc, the heredoc inside ``bash -lc`` —
#: is judged the right way round here, the dashboard's working folder elsewhere or not.
K616_INIT = json.dumps({"name": "s6-k616c", "version": "1.0.0", "description": "", "main": "index.js",
                        "scripts": {"test": "echo \"Error: no test specified\" && exit 1"}, "keywords": [], "author": "",
                        "license": "ISC", "type": "commonjs"}, indent=2) + "\n"
K616_HARMLESS = ('*** Begin Patch\n*** Update File: package.json\n@@\n-  "description": "",\n+  "description": "round six",\n'
                 '*** End Patch')
K616_LISTED = ('*** Begin Patch\n*** Update File: package.json\n@@\n   "license": "ISC",\n'
               '+  "dependencies": { "left-pad": "1.3.0" },\n   "type": "commonjs"\n*** End Patch')


def _k616_shapes(patch: str) -> list[dict]:
    return [{"tool_name": "apply_patch", "tool_input": {"command": patch}},
            {"tool_name": "apply_patch", "tool_input": {"command": patch + "\n"}},
            {"tool_name": "Bash", "tool_input": {"command": ["apply_patch", patch]}},
            {"tool_name": "Bash", "tool_input": {"command": "apply_patch " + patch}},
            {"tool_name": "Bash", "tool_input": {"command": f"apply_patch <<'PATCH'\n{patch}\nPATCH"}},
            {"tool_name": "Bash", "tool_input": {"command": ["bash", "-lc", f"apply_patch <<'PATCH'\n{patch}\nPATCH"]}}]


@pytest.mark.parametrize("shape", range(6))
def test_the_round6_codex_patches_are_judged_the_right_way_round(project, monkeypatch, shape):
    monkeypatch.chdir(project.parent)   # the dashboard runs elsewhere than the agent's folder
    manifest = project / "package.json"
    harmless, listed = _k616_shapes(K616_HARMLESS)[shape], _k616_shapes(K616_LISTED)[shape]
    for payload, refused in ((harmless, False), (listed, True)):
        manifest.write_text(K616_INIT, encoding="utf-8")
        events._answered.clear()
        answer = events.record_event(runner.summary("codex", "pre_tool", {"session_id": "s6-k616", "cwd": str(project),
                                                                         "tool_use_id": f"call_{shape}_{refused}", **payload}))
        assert (answer["decision"] == "block") is refused, (shape, payload, answer)
        assert "own settings" not in answer["message"] and "self-protection" not in answer["message"], answer["message"]
        if refused:
            assert "left-pad@1.3.0" in answer["message"]
