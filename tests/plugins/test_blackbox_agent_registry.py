"""The platform map and test registry of the coding agents (dashboard/docs_routes/agent_registry.json)
and each profile's detail from the real files (Amos, 2026-11-22: "kept safely and up to date";
"nothing made up").

Contracts: the registry and the code's catalogue agree — every agent, every hooked event, every
home-moving variable (no drift); the generated coverage-matrix.md equals the registry; a tested
row carries its date, Blackbox version, how and result; an installed agent newer than the last
tested version is said so; a profile's detail shows the files that exist, redacted, and derives
its risk notes only from them; a caller cannot make it read a path Blackbox does not know.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from plugins.blackbox.agent_hooks import profile_detail, versions
from plugins.blackbox.agent_hooks.instances import store
from plugins.blackbox.agent_hooks.instances.model import Instance
from plugins.blackbox.dashboard import server
from plugins.blackbox.dashboard.docs_routes import agent_registry
from plugins.blackbox.kernel import agent_hosts as hosts

REGISTRY = agent_registry.load()
BY_ID = {agent["id"]: agent for agent in REGISTRY["agents"]}
MATRIX = Path(agent_registry.PATH).parents[2] / "docs" / "agent-compat" / "coverage-matrix.md"


def test_the_registry_and_the_catalogue_name_the_same_agents():
    assert sorted(BY_ID) == sorted(hosts.BY_ID)


@pytest.mark.parametrize("host", hosts.HOSTS, ids=lambda host: host.id)
def test_every_event_the_code_hooks_is_in_the_registry_with_the_same_meaning(host):
    listed = {row["event"]: row["kind"] for row in BY_ID[host.id]["events"] if row["hooked"]}
    assert listed == dict(host.events)
    assert BY_ID[host.id]["home_env"] == host.home_env and BY_ID[host.id]["name"] == host.name


def test_every_coverage_row_is_complete():
    for agent in REGISTRY["agents"]:
        assert {row["layer"] for row in agent["coverage"]} <= set(agent_registry.LAYERS) and agent["coverage"]
        for row in agent["coverage"]:
            assert row["status"] in REGISTRY["statuses"]
            if row["status"] == "tested":
                assert row["date"] and row["blackbox"] and row["how"] and row["result"]
            if row["status"] == "not-covered":
                assert row["why"]
        assert all(source["url"].startswith("https://") and source["read"] for source in agent["sources"])


def test_the_coverage_page_is_the_registry_rendered():
    assert MATRIX.read_text(encoding="utf-8") == agent_registry.render_markdown()


def test_a_newer_installed_version_than_tested_is_said_so():
    agent = {"coverage": [{"status": "tested", "agent_version": "2.1.330"}, {"status": "tested", "agent_version": "2.1.9"}]}
    assert "newer than the last tested version (2.1.330)" in agent_registry.version_notice(agent, "2.2.0")
    assert agent_registry.version_notice(agent, "2.1.330") == "" and agent_registry.version_notice(agent, "2.1.10") == ""
    assert "No test run recorded" in agent_registry.version_notice({"coverage": [{"status": "tested", "agent_version": ""}]}, "1.0")
    assert versions.parse("codex-cli 0.171.0") == "0.171.0" and versions.parse("2.1.330 (Claude Code)") == "2.1.330"


def test_the_docs_page_serves_what_blackbox_protects(monkeypatch):
    monkeypatch.setattr(versions, "installed", lambda home=None: {"claude-code": versions.Installed("/usr/local/bin/claude", "9.9.9")})
    client = TestClient(server.create_app(), base_url="http://127.0.0.1")
    claude = next(agent for agent in client.get("/api/docs/agents").json()["agents"] if agent["id"] == "claude-code")
    assert claude["installed"] == {"path": "/usr/local/bin/claude", "version": "9.9.9"} and claude["version_notice"]
    assert "agent-cards" in client.get("/docs").text and client.get("/docs/assets/agents.js").status_code == 200


# ---------------------------------------------------------------- a profile's detail

@pytest.fixture
def claude_home(tmp_path, monkeypatch):
    store.reset()
    monkeypatch.setattr(versions, "installed", lambda home=None: {"claude-code": versions.Installed("/usr/local/bin/claude", "2.1.330")})
    home = tmp_path / ".claude"
    project = tmp_path / "work" / "app"
    (home / "agents").mkdir(parents=True)
    (project / ".claude").mkdir(parents=True)
    (home / "CLAUDE.md").write_text("Always run tests.\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n", encoding="utf-8")
    (home / "agents" / "reviewer.md").write_text("---\nname: reviewer\n---\n", encoding="utf-8")
    (home / "settings.json").write_text(json.dumps({
        "permissions": {"defaultMode": "bypassPermissions", "allow": ["Bash(git:*)"], "deny": ["Read(./.env)"]},
        "env": {"MY_TOKEN": "do-not-show"}, "model": "claude-opus-5-5",
        "hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "/x/agent-hooks/python /x/agent-hooks/runner.py claude-code pre_tool"}]},
                                 {"hooks": [{"type": "command", "command": "my-own-hook"}]}]}}), encoding="utf-8")
    (project / "CLAUDE.md").write_text("Project rules.", encoding="utf-8")
    (tmp_path / "work" / "CLAUDE.md").write_text("Workspace rules.", encoding="utf-8")
    (project / ".claude" / "settings.json").write_text('{"disableAllHooks": true}', encoding="utf-8")
    (project / ".mcp.json").write_text(json.dumps({"mcpServers": {"runner": {"command": "bash", "args": ["-c", "serve"]}}}), encoding="utf-8")
    store.replace_all([Instance(key="claude-code:1", agent="claude-code", kind="session", started=1.0, last=1.0, cwd=str(project))])
    yield tmp_path, home, project
    store.reset()


def test_a_profile_shows_the_real_files_and_only_them(claude_home):
    user_home, home, project = claude_home
    detail = profile_detail.read("claude-code", str(home), str(project), user_home=user_home)
    by_scope = {(doc.scope, Path(doc.path).parent.name): doc for doc in detail.instructions}
    assert set(by_scope) == {("user", ".claude"), ("project", "app"), ("above the project", "work")}
    shown = by_scope[("user", ".claude")].text
    assert "Always run tests." in shown and "wJalrXUtnFEMI" not in shown          # a secret is redacted for display
    user = next(scope for scope in detail.settings if scope.scope == "user")
    assert (user.permission_mode, user.allowed, user.denied, user.model) == ("bypassPermissions", ("Bash(git:*)",), ("Read(./.env)",), "claude-opus-5-5")
    assert user.env_names == ("MY_TOKEN",) and (user.blackbox_hooks, user.other_hooks) == (1, 1)
    assert "do-not-show" not in json.dumps(detail, default=lambda item: item.__dict__)   # an env VALUE is never read out
    assert [(server.name, server.launch) for server in detail.mcp_servers] == [("runner", "bash -c serve")]
    assert any(path.endswith("agents/reviewer.md") for path in detail.definitions)
    assert (detail.program, detail.version) == ("/usr/local/bin/claude", "2.1.330")


def test_risk_notes_follow_from_the_facts(claude_home):
    user_home, home, project = claude_home
    risks = profile_detail.read("claude-code", str(home), str(project), user_home=user_home).risks
    assert any("permission prompts skipped" in risk for risk in risks)
    assert any("Hooks are switched off" in risk and str(project) in risk for risk in risks)
    assert any('MCP server "runner" starts a shell' in risk for risk in risks)
    (home / "settings.json").write_text("{}", encoding="utf-8")
    (project / ".claude" / "settings.json").write_text("{}", encoding="utf-8")
    (project / ".mcp.json").write_text("{}", encoding="utf-8")
    calm = profile_detail.read("claude-code", str(home), str(project), user_home=user_home).risks
    assert calm == [f"Blackbox's hooks are not in {home / 'settings.json'}."]


def test_a_caller_cannot_make_it_read_another_path(claude_home, tmp_path):
    user_home, home, _project = claude_home
    assert profile_detail.read("claude-code", "/etc", user_home=user_home) is None
    assert profile_detail.read("nobody", str(home), user_home=user_home) is None
    secret = tmp_path / "elsewhere"
    secret.mkdir()
    (secret / "CLAUDE.md").write_text("not yours", encoding="utf-8")
    detail = profile_detail.read("claude-code", str(home), str(secret), user_home=user_home)
    assert detail.project == "" and all("elsewhere" not in doc.path for doc in detail.instructions)


# ---------------------------------------------------------------- a test run records itself

RUN = agent_registry.TestRun(agent="codex", os="macos", launch="interactive", layer="hooks", agent_version="0.200.0",
                             os_version="macOS 26.6.2", blackbox="1.5.0", date="2026-12-01",
                             how="test VM: its own hook command with its documented payloads", result="pass")


def test_a_recorded_run_replaces_the_row_for_its_os_launch_and_layer():
    before = agent_registry.load()
    rows = len(next(agent for agent in before["agents"] if agent["id"] == "codex")["coverage"])
    after = agent_registry.record_test(before, RUN)
    codex = next(agent for agent in after["agents"] if agent["id"] == "codex")
    row = next(row for row in codex["coverage"] if (row["launch"], row["layer"]) == ("interactive", "hooks"))
    assert (row["status"], row["agent_version"], row["os_version"], row["date"]) == ("tested", "0.200.0", "macOS 26.6.2", "2026-12-01")
    assert len(codex["coverage"]) == rows and after["updated"] == "2026-12-01"
    assert agent_registry.version_notice(codex, "0.200.0") == ""


def test_a_run_on_a_new_launch_mode_adds_a_row_and_a_vague_run_is_refused():
    import dataclasses

    registry = agent_registry.record_test(agent_registry.load(), dataclasses.replace(RUN, launch="headless, ci"))
    codex = next(agent for agent in registry["agents"] if agent["id"] == "codex")
    assert any(row["launch"] == "headless, ci" and row["status"] == "tested" for row in codex["coverage"])
    for bad in (dataclasses.replace(RUN, agent="nobody"), dataclasses.replace(RUN, how=" "), dataclasses.replace(RUN, result="fine")):
        with pytest.raises(ValueError):
            agent_registry.record_test(agent_registry.load(), bad)


def test_the_command_writes_the_registry_and_the_page_together(tmp_path, monkeypatch):
    from plugins.blackbox.dashboard.docs_routes import record_test

    registry, matrix = tmp_path / "agent_registry.json", tmp_path / "coverage-matrix.md"
    registry.write_text(agent_registry.PATH.read_text(encoding="utf-8"), encoding="utf-8")
    monkeypatch.setattr(agent_registry, "PATH", registry)
    monkeypatch.setattr(agent_registry, "MATRIX", matrix)
    code = record_test.main(["--agent", "gemini-cli", "--os", "macos", "--os-version", "macOS 26.6.2", "--launch", "interactive",
                             "--layer", "hooks", "--agent-version", "0.71.0", "--result", "pass", "--how", "test VM run", "--date", "2026-12-02"])
    assert code == 0 and "agent 0.71.0, macOS 26.6.2" in matrix.read_text(encoding="utf-8")
    assert matrix.read_text(encoding="utf-8") == agent_registry.render_markdown()
    assert record_test.main(["--agent", "nobody", "--os", "macos", "--launch", "x", "--layer", "hooks", "--result", "pass", "--how", "y"]) == 2


def test_every_tested_row_says_which_agent_version_ran():
    """Amos, 2026-11-22: keep track of what was tested, in which version, on which OS."""
    for agent in REGISTRY["agents"]:
        for row in agent["coverage"]:
            if row["status"] == "tested":
                assert row.get("agent_version") and row.get("os_version"), (agent["id"], row["launch"], row["layer"])
