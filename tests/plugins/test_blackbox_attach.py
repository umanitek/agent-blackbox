"""Tests for ``blackbox attach`` / ``blackbox detach`` discovery + merge logic."""

import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from _blackbox_loader import load_blackbox


attach = load_blackbox("attach")
constants = load_blackbox("constants")
hooks = load_blackbox("hooks")
config_mod = load_blackbox("config")
cli = load_blackbox("cli")


def test_openclaw_package_declares_enforced_minimum_host_version():
    package = json.loads(
        (Path(__file__).parents[2] / "integrations" / "openclaw" / "package.json").read_text(encoding="utf-8")
    )
    assert package["openclaw"]["install"]["minHostVersion"] == ">=2026.6.11"


# ---------------------------------------------------------------------------
# Fixtures — fake Hermes homes + OpenClaw workspace under tmp_path
# ---------------------------------------------------------------------------


@pytest.fixture
def fake_env(tmp_path, monkeypatch):
    """A fake $HOME with two Hermes homes (default + a profile) and an OpenClaw ws.

    Returns a dict of the interesting paths. ``HERMES_HOME`` points at the
    default home so ``discover_hermes_homes`` resolves it.
    """
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr("pathlib.Path.home", lambda: home)
    monkeypatch.setattr(attach, "_claude_binary", lambda: None)
    monkeypatch.setattr(attach, "_codex_binary", lambda: None)

    # Default hermes home with an existing config.yaml.
    hermes_default = home / ".hermes"
    hermes_default.mkdir()
    (hermes_default / "config.yaml").write_text(
        yaml.safe_dump({"providers": {"openai": {}}, "plugins": {"enabled": []}}),
        encoding="utf-8",
    )
    monkeypatch.setenv("HERMES_HOME", str(hermes_default))

    # A profile home (no config yet — attach must create it).
    profile = hermes_default / "profiles" / "work"
    profile.mkdir(parents=True)

    # A home with NO config file at all.
    bare_home = hermes_default  # default already has config; use profile as the bare one

    # An OpenClaw workspace (existing install → has openclaw.json).
    openclaw_ws = home / ".openclaw"
    openclaw_ws.mkdir()
    (openclaw_ws / "openclaw.json").write_text(
        json.dumps({"someKey": "keepme", "plugins": {"enabled": ["other"]}}, indent=2),
        encoding="utf-8",
    )

    # A non-openclaw dir that must NOT be discovered (no openclaw.json).
    (home / ".openclaw-dev").mkdir()

    return {
        "home": home,
        "hermes_default": hermes_default,
        "profile": profile,
        "bare_home": bare_home,
        "openclaw_ws": openclaw_ws,
    }


# ---------------------------------------------------------------------------
# Discovery
# ---------------------------------------------------------------------------


def test_discover_hermes_homes_finds_default_and_profile(fake_env):
    homes = attach.discover_hermes_homes()
    assert fake_env["hermes_default"] in homes
    assert fake_env["profile"] in homes


def test_discover_external_agents_before_first_launch(fake_env, monkeypatch):
    monkeypatch.setattr(attach, "_claude_binary", lambda: "/usr/local/bin/claude")
    monkeypatch.setattr(attach, "_codex_binary", lambda: "/usr/local/bin/codex")

    assert attach.discover_claude_homes() == [fake_env["home"] / ".claude"]
    assert attach.discover_codex_homes() == [fake_env["home"] / ".codex"]


def test_discover_hermes_homes_skips_managed_blackbox_chat_profile(fake_env):
    blackbox = fake_env["hermes_default"] / "profiles" / "blackbox"
    blackbox.mkdir(parents=True)
    (blackbox / "SOUL.md").write_text(
        "<!-- managed-by: hermes-blackbox-chat -->\n# Agent Blackbox\n",
        encoding="utf-8",
    )

    homes = attach.discover_hermes_homes()
    assert fake_env["profile"] in homes
    assert blackbox not in homes


def test_discover_hermes_homes_deduplicates(fake_env):
    homes = attach.discover_hermes_homes()
    assert len(homes) == len(set(homes))


def test_discover_openclaw_only_existing_installs(fake_env):
    workspaces = attach.discover_openclaw_workspaces()
    assert fake_env["openclaw_ws"] in workspaces
    # .openclaw-dev exists but has no openclaw.json → excluded.
    assert (fake_env["home"] / ".openclaw-dev") not in workspaces


def test_discover_openclaw_honors_custom_config_path(fake_env, monkeypatch):
    config = fake_env["home"] / "service" / "custom-openclaw.json5"
    config.parent.mkdir()
    config.write_text("{ plugins: {}, }\n", encoding="utf-8")
    monkeypatch.setenv("OPENCLAW_CONFIG_PATH", str(config))

    workspaces = attach.discover_openclaw_workspaces()

    assert config in workspaces
    assert workspaces.count(config) == 1


# ---------------------------------------------------------------------------
# attach_hermes — copies plugin + enables idempotently
# ---------------------------------------------------------------------------


def test_attach_hermes_copies_plugin_and_enables(fake_env):
    home = fake_env["hermes_default"]
    report = attach.attach_hermes(home)
    assert report["ok"]
    # Plugin copied into the home.
    assert (home / "plugins" / "blackbox" / "__init__.py").exists()
    # __pycache__/tests excluded.
    assert not (home / "plugins" / "blackbox" / "__pycache__").exists()
    assert not (home / "plugins" / "blackbox" / "tests").exists()
    # blackbox added to plugins.enabled.
    data = yaml.safe_load((home / "config.yaml").read_text())
    assert "blackbox" in data["plugins"]["enabled"]
    # Other keys preserved.
    assert "providers" in data


def test_copy_plugin_tree_records_source_checkout(tmp_path, monkeypatch):
    repo = tmp_path / "repo"
    src = repo / "plugins" / "blackbox"
    src.mkdir(parents=True)
    (repo / ".git").mkdir()
    (src / "__init__.py").write_text("", encoding="utf-8")
    (src / "cli.py").write_text("", encoding="utf-8")
    dest = tmp_path / "dest"

    monkeypatch.setattr(attach, "_bundle_openclaw_plugin", lambda _src, _dest: None)
    attach._copy_plugin_tree(src, dest)

    assert (dest / ".blackbox-source-root").read_text(encoding="utf-8") == str(repo)


def test_attach_hermes_is_idempotent(fake_env):
    home = fake_env["hermes_default"]
    attach.attach_hermes(home)
    before = (home / "config.yaml").read_text()
    second = attach.attach_hermes(home)
    after = (home / "config.yaml").read_text()
    # Second run reports "already" and makes no config change.
    assert second["already"] is True
    assert second["enabled"] is False
    assert before == after
    # No duplicate list entry.
    data = yaml.safe_load(after)
    assert data["plugins"]["enabled"].count("blackbox") == 1


def test_attach_hermes_creates_config_for_bare_home(fake_env):
    profile = fake_env["profile"]  # no config.yaml yet
    report = attach.attach_hermes(profile)
    assert report["ok"] and report["enabled"]
    cfg = profile / "config.yaml"
    assert cfg.exists()
    data = yaml.safe_load(cfg.read_text())
    assert data["plugins"]["enabled"] == ["blackbox"]


def test_attach_hermes_dry_run_writes_nothing(fake_env):
    home = fake_env["hermes_default"]
    before = (home / "config.yaml").read_text()
    report = attach.attach_hermes(home, dry_run=True)
    assert report["ok"] and report["dry_run"]
    # No plugin dir, no config change.
    assert not (home / "plugins" / "blackbox").exists()
    assert (home / "config.yaml").read_text() == before


def test_attach_hermes_dry_run_does_not_claim_missing_plugin_is_protected(fake_env):
    home = fake_env["hermes_default"]
    data = yaml.safe_load((home / "config.yaml").read_text())
    data["plugins"]["enabled"] = ["blackbox"]
    (home / "config.yaml").write_text(yaml.safe_dump(data), encoding="utf-8")

    report = attach.attach_hermes(home, dry_run=True)

    assert report["ok"] is True
    assert report["protected"] is False
    assert report["already"] is False
    assert report["copied"] is True


# ---------------------------------------------------------------------------
# detach_hermes
# ---------------------------------------------------------------------------


def test_detach_hermes_disables_and_optionally_removes(fake_env):
    home = fake_env["hermes_default"]
    attach.attach_hermes(home)
    assert (home / "plugins" / "blackbox").exists()

    report = attach.detach_hermes(home, remove_files=True)
    assert report["ok"] and report["disabled"] and report["removed"]
    data = yaml.safe_load((home / "config.yaml").read_text())
    assert "blackbox" not in data["plugins"]["enabled"]
    assert not (home / "plugins" / "blackbox").exists()


def test_detach_hermes_idempotent(fake_env):
    home = fake_env["hermes_default"]
    report = attach.detach_hermes(home)
    assert report["ok"] and report["already"]


def test_detach_hermes_dry_run_writes_nothing(fake_env):
    home = fake_env["hermes_default"]
    attach.attach_hermes(home)
    before = (home / "config.yaml").read_text()
    report = attach.detach_hermes(home, remove_files=True, dry_run=True)
    assert report["ok"]
    assert (home / "config.yaml").read_text() == before
    assert (home / "plugins" / "blackbox").exists()  # not removed in dry-run


# ---------------------------------------------------------------------------
# attach_openclaw — writes the blackbox entry block, idempotent
# ---------------------------------------------------------------------------


def test_attach_openclaw_writes_blackbox_block(fake_env):
    ws = fake_env["openclaw_ws"]
    report = attach.attach_openclaw(ws)
    assert report["ok"] and report["changed"]

    data = json.loads((ws / "openclaw.json").read_text())
    plugins = data["plugins"]
    assert "blackbox" in plugins["allow"]
    entry = plugins["entries"]["blackbox"]
    assert entry["enabled"] is True
    assert entry["hooks"]["allowConversationAccess"] is True
    assert entry["config"]["mode"]
    assert entry["config"]["dkgUrl"] == constants.DEFAULT_DKG_URL
    assert "daemonUrl" not in entry["config"]
    assert entry["config"]["dkgHome"] == str(constants.blackbox_dkg_home())
    assert entry["config"]["contextGraphId"]
    # blackboxHome points OpenClaw's local findings log at the Hermes blackbox
    # home so the one dashboard surfaces OpenClaw detections too.
    assert entry["config"]["blackboxHome"] == str(constants.blackbox_home())
    # Unrelated keys preserved.
    assert data["someKey"] == "keepme"
    # A backup was made.
    assert (ws / "openclaw.json.blackbox.bak").exists()


def test_attach_openclaw_is_idempotent(fake_env):
    ws = fake_env["openclaw_ws"]
    attach.attach_openclaw(ws)
    before = (ws / "openclaw.json").read_text()
    second = attach.attach_openclaw(ws)
    after = (ws / "openclaw.json").read_text()
    assert second["already"] is True
    assert second["changed"] is False
    assert before == after
    data = json.loads(after)
    assert data["plugins"]["allow"].count("blackbox") == 1


def test_attach_openclaw_dry_run_writes_nothing(fake_env):
    ws = fake_env["openclaw_ws"]
    before = (ws / "openclaw.json").read_text()
    report = attach.attach_openclaw(ws, dry_run=True)
    assert report["ok"] and report["changed"] and report["dry_run"]
    assert (ws / "openclaw.json").read_text() == before


def test_attach_openclaw_supports_json5_without_losing_other_config(fake_env):
    ws = fake_env["openclaw_ws"]
    (ws / "openclaw.json").write_text(
        """{
          // OpenClaw accepts JSON5.
          gateway: { url: 'http://127.0.0.1:18789', },
          plugins: { allow: ['other',], },
          customFlag: true,
        }\n""",
        encoding="utf-8",
    )

    report = attach.attach_openclaw(ws)
    data = json.loads((ws / "openclaw.json").read_text(encoding="utf-8"))

    assert report["ok"] is True
    assert data["gateway"]["url"] == "http://127.0.0.1:18789"
    assert data["customFlag"] is True
    assert data["plugins"]["allow"] == ["other", "blackbox"]


def test_attach_openclaw_parse_failure_never_replaces_config(fake_env):
    ws = fake_env["openclaw_ws"]
    broken = "{ gateway: { token: 0xNOT_JSON5 } }\n"
    (ws / "openclaw.json").write_text(broken, encoding="utf-8")

    report = attach.attach_openclaw(ws)

    assert report["ok"] is False
    assert report.get("error")
    assert (ws / "openclaw.json").read_text(encoding="utf-8") == broken


def test_attach_openclaw_rejects_known_unsupported_version_without_writing(fake_env):
    ws = fake_env["openclaw_ws"]
    config = ws / "openclaw.json"
    config.write_text(
        json.dumps({"meta": {"lastTouchedVersion": "2026.5.31"}, "keep": "yes"}, indent=2),
        encoding="utf-8",
    )
    before = config.read_text(encoding="utf-8")

    report = attach.attach_openclaw(ws)

    assert report["ok"] is False
    assert report["unsupported"] is True
    assert "2026.6.11+" in report["error"]
    assert config.read_text(encoding="utf-8") == before


def test_attach_openclaw_replaces_stale_blackbox_path_but_keeps_other_plugins(fake_env):
    ws = fake_env["openclaw_ws"]
    config = ws / "openclaw.json"
    pre_blackbox_plugin = fake_env["home"] / "plugins" / "guardian" / "_openclaw"
    pre_blackbox_plugin.mkdir(parents=True)
    (pre_blackbox_plugin / "openclaw.plugin.json").write_text(
        '{"id":"guardian"}\n', encoding="utf-8"
    )
    missing_pre_blackbox_plugin = "/tmp/missing/plugins/guardian/_openclaw"
    stale_canonical_checkout = "/tmp/agent-blackbox/integrations/openclaw"
    config.write_text(
        json.dumps(
            {
                "plugins": {
                    "load": {
                        "paths": [
                            "/tmp/blackbox-clean-client-old/integrations/openclaw",
                            stale_canonical_checkout,
                            str(pre_blackbox_plugin),
                            missing_pre_blackbox_plugin,
                        ]
                    }
                }
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    report = attach.attach_openclaw(ws)
    paths = json.loads(config.read_text(encoding="utf-8"))["plugins"]["load"]["paths"]

    assert report["ok"] is True
    assert "/tmp/blackbox-clean-client-old/integrations/openclaw" not in paths
    assert stale_canonical_checkout not in paths
    assert str(pre_blackbox_plugin) in paths
    assert missing_pre_blackbox_plugin not in paths
    assert any(attach._same_openclaw_load_path(path, attach._openclaw_load_paths_entry()) for path in paths)


def test_attach_openclaw_accepts_custom_config_file(fake_env):
    config = fake_env["home"] / "custom" / "agent-config.json5"
    config.parent.mkdir()
    config.write_text("{ keep: 'value', plugins: {}, }\n", encoding="utf-8")

    report = attach.attach_openclaw(config)
    data = json.loads(config.read_text(encoding="utf-8"))

    assert report["ok"] is True
    assert report["config_path"] == str(config)
    assert data["keep"] == "value"
    assert data["plugins"]["entries"]["blackbox"]["enabled"] is True


def test_copy_plugin_tree_bundles_openclaw(tmp_path):
    # An installed copy has no sibling integrations/, so the OpenClaw JS plugin
    # must be bundled INTO the copy — otherwise OpenClaw has nothing to load
    # (the "Attach failed" root cause). _copy_plugin_tree pulls it from the repo.
    dest = tmp_path / "plugins" / "blackbox"
    attach._copy_plugin_tree(attach._plugin_source_dir(), dest)
    bundle = dest / "_openclaw"
    assert (bundle / "openclaw.plugin.json").is_file()
    assert (bundle / "src" / "index.ts").is_file()
    assert not (bundle / "node_modules").exists()  # deps excluded from the bundle


def test_copy_plugin_tree_bundles_claude_and_codex_hooks(tmp_path):
    dest = tmp_path / "plugins" / "blackbox"

    attach._copy_plugin_tree(attach._plugin_source_dir(), dest)

    bundle = dest / "_agent_hooks"
    assert (bundle / ".codex-plugin" / "plugin.json").is_file()
    assert (bundle / ".claude-plugin" / "plugin.json").is_file()
    assert (bundle / "hooks" / "hooks.json").is_file()


def test_copy_plugin_tree_bundles_from_explicit_checkout_source(tmp_path, monkeypatch):
    """Fresh installed-plugin execution must not depend on its own marker yet."""
    repo = tmp_path / "checkout"
    src = repo / "plugins" / "blackbox"
    integration = repo / "integrations" / "openclaw"
    src.mkdir(parents=True)
    integration.mkdir(parents=True)
    (repo / ".git").mkdir()
    (src / "__init__.py").write_text("", encoding="utf-8")
    (src / "constants.py").write_text("__version__ = '1.0.0'\n", encoding="utf-8")
    (integration / "openclaw.plugin.json").write_text('{"id":"blackbox"}\n', encoding="utf-8")
    (integration / "index.ts").write_text("export {};\n", encoding="utf-8")
    monkeypatch.setattr(attach, "_repo_openclaw_dir", lambda: tmp_path / "missing")

    dest = tmp_path / "installed" / "plugins" / "blackbox"
    attach._copy_plugin_tree(src, dest)

    assert (dest / "_openclaw" / "openclaw.plugin.json").is_file()
    assert (dest / ".blackbox-install-stamp").is_file()


def test_openclaw_load_path_resolves_from_installed_copy(tmp_path, monkeypatch):
    # Regression for the attach failure: when Blackbox runs from an installed
    # copy (no sibling repo), the load path must resolve to the BUNDLED plugin,
    # not return None — None made attach_openclaw report ok=False ("Attach
    # failed") for every installed user.
    installed = tmp_path / "plugins" / "blackbox"
    attach._copy_plugin_tree(attach._plugin_source_dir(), installed)  # bundles _openclaw
    monkeypatch.setattr(attach, "_plugin_source_dir", lambda: installed)
    # repo_root is now tmp_path — no integrations/openclaw there.
    assert not (attach._repo_root() / "integrations" / "openclaw").exists()
    assert attach._openclaw_load_paths_entry() == str(installed / "_openclaw")


def test_openclaw_plugin_source_none_without_bundle_or_repo(tmp_path, monkeypatch):
    # A bare copy with neither a bundle nor a repo sibling resolves to None (an
    # honest "unprotected"), never a crash.
    bare = tmp_path / "plugins" / "blackbox"
    bare.mkdir(parents=True)
    monkeypatch.setattr(attach, "_plugin_source_dir", lambda: bare)
    assert attach._openclaw_load_paths_entry() is None


def test_detach_openclaw_removes_block(fake_env):
    ws = fake_env["openclaw_ws"]
    attach.attach_openclaw(ws)
    report = attach.detach_openclaw(ws)
    assert report["ok"] and report["changed"]
    data = json.loads((ws / "openclaw.json").read_text())
    assert "blackbox" not in (data["plugins"].get("allow") or [])
    assert "blackbox" not in (data["plugins"].get("entries") or {})


# ---------------------------------------------------------------------------
# attach_all / detach_all report
# ---------------------------------------------------------------------------


def test_attach_all_reports_targets(fake_env):
    report = attach.attach_all()
    assert report["count"] >= 2  # at least default home + openclaw ws
    assert all(row["ok"] for row in report["hermes"])
    assert all(row["ok"] for row in report["openclaw"])


# ---------------------------------------------------------------------------
# Claude Code + Codex zero-configuration adapters
# ---------------------------------------------------------------------------


def test_attach_claude_merges_user_hooks_and_is_idempotent(fake_env):
    home = fake_env["home"] / ".claude"
    home.mkdir()
    settings = home / "settings.json"
    settings.write_text(
        json.dumps(
            {
                "theme": "dark",
                "hooks": {
                    "PreToolUse": [
                        {
                            "matcher": "Bash",
                            "hooks": [{"type": "command", "command": "echo keep-me"}],
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    first = attach.attach_claude(home)
    after_first = settings.read_text(encoding="utf-8")
    second = attach.attach_claude(home)
    data = json.loads(settings.read_text(encoding="utf-8"))

    assert first["ok"] and first["protected"] and first["changed"]
    assert second["ok"] and second["already"] and not second["changed"]
    assert settings.read_text(encoding="utf-8") == after_first
    assert data["theme"] == "dark"
    assert any(
        handler.get("command") == "echo keep-me"
        for group in data["hooks"]["PreToolUse"]
        for handler in group.get("hooks", [])
    )
    for event in ("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop"):
        assert any(
            "external_hook.py" in " ".join(str(arg) for arg in handler.get("args") or [])
            and "claude-code" in " ".join(str(arg) for arg in handler.get("args") or [])
            and handler.get("command") == sys.executable
            for group in data["hooks"][event]
            for handler in group.get("hooks", [])
        )


def test_claude_exec_hook_uses_immutable_runtime_and_survives_space_in_path(
    fake_env, monkeypatch
):
    blackbox_home = fake_env["home"] / "blackbox home with spaces"
    monkeypatch.setenv("BLACKBOX_HOME", str(blackbox_home))
    home = fake_env["home"] / ".claude"
    home.mkdir()

    report = attach.attach_claude(home)
    data = json.loads((home / "settings.json").read_text(encoding="utf-8"))
    handler = data["hooks"]["PreToolUse"][0]["hooks"][0]
    runtime = Path(handler["args"][0])

    assert report["ok"] and report["protected"]
    assert handler["command"] == sys.executable
    assert handler["args"] == [str(runtime), "--framework", "claude-code"]
    assert runtime.is_file()
    assert blackbox_home in runtime.parents
    assert attach._plugin_source_dir() not in runtime.parents
    assert not (runtime.parent / ".blackbox-source-root").exists()

    completed = subprocess.run(
        [handler["command"], *handler["args"]],
        input="{malformed hook input",
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stdout == ""
    assert completed.stderr == ""


def test_claude_dry_run_does_not_claim_missing_runtime_is_protected(fake_env):
    home = fake_env["home"] / ".claude"
    home.mkdir()
    broken = {
        "type": "command",
        "command": sys.executable,
        "args": ["/missing/blackbox/external_hook.py", "--framework", "claude-code"],
    }
    (home / "settings.json").write_text(
        json.dumps(
            {
                "hooks": {
                    event: [{"hooks": [broken]}]
                    for event in ("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop")
                }
            }
        ),
        encoding="utf-8",
    )

    report = attach.attach_claude(home, dry_run=True)

    assert report["ok"] is True
    assert report["protected"] is False
    assert report["changed"] is True


def test_claude_dry_run_does_not_claim_checkout_runtime_is_durable(fake_env):
    home = fake_env["home"] / ".claude"
    home.mkdir()
    checkout_runtime = attach._plugin_source_dir() / "external_hook.py"
    handler = {
        "type": "command",
        "command": sys.executable,
        "args": [str(checkout_runtime), "--framework", "claude-code"],
    }
    events = ("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop")
    (home / "settings.json").write_text(
        json.dumps({"hooks": {event: [{"hooks": [handler]}] for event in events}}),
        encoding="utf-8",
    )

    report = attach.attach_claude(home, dry_run=True)

    assert checkout_runtime.is_file()
    assert report["ok"] is True
    assert report["protected"] is False
    assert report["changed"] is True


def test_detach_claude_removes_only_blackbox_hooks(fake_env):
    home = fake_env["home"] / ".claude"
    home.mkdir()
    attach.attach_claude(home)
    settings = home / "settings.json"
    data = json.loads(settings.read_text(encoding="utf-8"))
    data["hooks"]["PreToolUse"].append(
        {"matcher": "Bash", "hooks": [{"type": "command", "command": "echo keep"}]}
    )
    settings.write_text(json.dumps(data), encoding="utf-8")

    report = attach.detach_claude(home)
    detached = json.loads(settings.read_text(encoding="utf-8"))

    assert report["ok"] and report["changed"]
    assert not attach._claude_has_blackbox_hooks(detached)
    assert detached["hooks"]["PreToolUse"][0]["hooks"][0]["command"] == "echo keep"


def test_attach_codex_installs_plugin_without_bypassing_hook_trust(fake_env, monkeypatch):
    home = fake_env["home"] / ".codex"
    home.mkdir()
    monkeypatch.setenv("BLACKBOX_HOME", str(fake_env["home"] / "blackbox home with spaces"))
    calls = []

    def run(_binary, _home, *args):
        calls.append(args)
        if args == ("plugin", "marketplace", "list", "--json"):
            return {"marketplaces": []}
        if args == ("plugin", "list", "--available", "--json"):
            return {
                "installed": [],
                "available": [
                    {
                        "pluginId": "blackbox@agent-blackbox",
                        "installed": False,
                        "enabled": False,
                    }
                ],
            }
        return {}

    monkeypatch.setattr(attach, "_run_codex_json", run)
    report = attach.attach_codex(home, binary="/fake/codex")

    assert report["ok"] and report["installed"]
    assert report["protected"] is False
    assert report["trust_required"] is True
    assert any(args[:4] == ("plugin", "marketplace", "add", report["marketplace"]) for args in calls)
    assert ("plugin", "add", "blackbox@agent-blackbox", "--json") in calls
    assert not any("dangerously-bypass-hook-trust" in args for args in calls)
    marketplace = Path(report["marketplace"])
    manifest = json.loads(
        (marketplace / "plugins" / "blackbox" / ".codex-plugin" / "plugin.json").read_text(
            encoding="utf-8"
        )
    )
    hooks_json = json.loads(
        (marketplace / "plugins" / "blackbox" / "hooks" / "hooks.json").read_text(
            encoding="utf-8"
        )
    )
    assert manifest["version"].startswith(f"{constants.__version__}+codex.")
    assert set(hooks_json["hooks"]) == {
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PostToolUse",
        "Stop",
    }
    command = hooks_json["hooks"]["PreToolUse"][0]["hooks"][0]["command"]
    assert "external_hook.py" in command and "--framework codex" in command
    assert str(attach._plugin_source_dir()) not in command
    completed = subprocess.run(
        command,
        input="{malformed hook input",
        capture_output=True,
        text=True,
        shell=True,
        check=False,
    )
    assert completed.returncode == 0
    assert completed.stdout == ""
    assert completed.stderr == ""


def test_attach_codex_recovers_its_deleted_marketplace(fake_env, monkeypatch):
    home = fake_env["home"] / ".codex"
    home.mkdir()
    calls = []
    list_attempts = 0

    def run(_binary, _home, *args):
        nonlocal list_attempts
        calls.append(args)
        if args == ("plugin", "marketplace", "list", "--json"):
            list_attempts += 1
            if list_attempts == 1:
                raise RuntimeError(
                    "failed to load marketplace(s): agent-blackbox at /tmp/deleted"
                )
            return {"marketplaces": []}
        if args == ("plugin", "list", "--available", "--json"):
            return {"installed": [], "available": []}
        return {}

    monkeypatch.setattr(attach, "_run_codex_json", run)

    report = attach.attach_codex(home, binary="/fake/codex")

    assert report["ok"] is True
    assert list_attempts == 2
    assert (
        "plugin",
        "marketplace",
        "remove",
        "agent-blackbox",
        "--json",
    ) in calls
    assert any(args[:3] == ("plugin", "marketplace", "add") for args in calls)


def test_attach_codex_changed_plugin_requires_fresh_trust(fake_env, monkeypatch):
    home = fake_env["home"] / ".codex"
    home.mkdir()
    lines = ["[hooks.state]"]
    for event in ("session_start", "user_prompt_submit", "pre_tool_use", "post_tool_use", "stop"):
        key = f"blackbox@agent-blackbox:hooks/hooks.json:{event}:0:0"
        lines.extend([f'[hooks.state."{key}"]', 'trusted_hash = "sha256:stale"'])
    (home / "config.toml").write_text("\n".join(lines) + "\n", encoding="utf-8")

    def run(_binary, _home, *args):
        if args == ("plugin", "marketplace", "list", "--json"):
            return {"marketplaces": []}
        if args == ("plugin", "list", "--available", "--json"):
            return {"installed": [], "available": []}
        return {}

    monkeypatch.setattr(attach, "_run_codex_json", run)

    report = attach.attach_codex(home, binary="/fake/codex")

    assert report["ok"] is True
    assert report["changed"] is True
    assert report["protected"] is False
    assert report["trust_required"] is True


def test_cli_attach_defaults_to_every_supported_agent(monkeypatch, capsys):
    seen = {}

    def attach_all(**kwargs):
        seen.update(kwargs)
        return {
            "hermes": [],
            "openclaw": [],
            "claude-code": [],
            "codex": [
                {
                    "target": "/tmp/.codex",
                    "kind": "codex",
                    "ok": True,
                    "installed": True,
                    "trust_required": True,
                }
            ],
            "count": 0,
        }

    monkeypatch.setattr(cli.attach, "attach_all", attach_all)
    args = cli.argparse.Namespace(
        dry_run=False,
        hermes_only=False,
        openclaw_only=False,
        claude_only=False,
        codex_only=False,
    )

    assert cli._cmd_attach(args) == 0
    assert seen == {
        "hermes": True,
        "openclaw": True,
        "claude": True,
        "codex": True,
        "dry_run": False,
    }
    output = capsys.readouterr().out
    assert "/hooks trust pending" in output
    assert "Codex security review required" in output


def test_cli_attach_only_flag_selects_one_external_agent(monkeypatch):
    seen = {}
    monkeypatch.setattr(
        cli.attach,
        "attach_all",
        lambda **kwargs: (seen.update(kwargs), {"codex": [], "count": 0})[1],
    )
    args = cli.argparse.Namespace(
        dry_run=True,
        hermes_only=False,
        openclaw_only=False,
        claude_only=False,
        codex_only=True,
    )

    assert cli._cmd_attach(args) == 0
    assert seen == {
        "hermes": False,
        "openclaw": False,
        "claude": False,
        "codex": True,
        "dry_run": True,
    }


def test_codex_trust_status_requires_every_blackbox_hook(fake_env):
    home = fake_env["home"] / ".codex"
    home.mkdir()
    marketplace = fake_env["home"] / "blackbox-marketplace"
    manifest = marketplace / "plugins" / "blackbox" / "hooks" / "hooks.json"
    manifest.parent.mkdir(parents=True)
    command = "/opt/blackbox/python /opt/blackbox/external_hook.py --framework codex"
    manifest.write_text(
        json.dumps(
            {
                "hooks": {
                    event: [
                        {
                            **({"matcher": "*"} if event in {"SessionStart", "PreToolUse", "PostToolUse"} else {}),
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": command,
                                    "commandWindows": command,
                                    "timeout": 30,
                                }
                            ],
                        }
                    ]
                    for event in (
                        "SessionStart",
                        "UserPromptSubmit",
                        "PreToolUse",
                        "PostToolUse",
                        "Stop",
                    )
                }
            }
        ),
        encoding="utf-8",
    )
    config = home / "config.toml"
    base = [
        "[marketplaces.agent-blackbox]",
        f'source = "{marketplace}"',
        "",
        "[hooks.state]",
    ]
    config.write_text("\n".join(base) + "\n", encoding="utf-8")
    current = attach._codex_current_hook_hashes(home)
    assert set(current) == {
        "session_start",
        "user_prompt_submit",
        "pre_tool_use",
        "post_tool_use",
        "stop",
    }

    lines = list(base)
    for event in ("session_start", "user_prompt_submit", "pre_tool_use", "post_tool_use", "stop"):
        key = f"/tmp/plugins/cache/agent-blackbox/blackbox/local/hooks/hooks.json:{event}:0:0"
        lines.extend([f'[hooks.state."{key}"]', f'trusted_hash = "{current[event]}"'])
    config.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert attach._codex_hooks_trusted(home) is True

    config.write_text("\n".join(lines[:-2]) + "\n", encoding="utf-8")
    assert attach._codex_hooks_trusted(home) is False

    config.write_text("\n".join(lines) + "\n", encoding="utf-8")
    payload = json.loads(manifest.read_text(encoding="utf-8"))
    payload["hooks"]["PreToolUse"][0]["hooks"][0]["command"] += " --changed"
    manifest.write_text(json.dumps(payload), encoding="utf-8")
    assert attach._codex_hooks_trusted(home) is False


def test_codex_trust_status_rejects_disabled_hook(fake_env):
    home = fake_env["home"] / ".codex"
    home.mkdir()
    marketplace = fake_env["home"] / "blackbox-marketplace"
    manifest = marketplace / "plugins" / "blackbox" / "hooks" / "hooks.json"
    manifest.parent.mkdir(parents=True)
    events = ("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop")
    manifest.write_text(
        json.dumps(
            {
                "hooks": {
                    event: [
                        {
                            "hooks": [
                                {
                                    "type": "command",
                                    "command": "blackbox-hook",
                                    "timeout": 30,
                                }
                            ]
                        }
                    ]
                    for event in events
                }
            }
        ),
        encoding="utf-8",
    )
    config = home / "config.toml"
    base = [
        "[marketplaces.agent-blackbox]",
        f'source = "{marketplace}"',
        "",
        "[hooks.state]",
    ]
    config.write_text("\n".join(base) + "\n", encoding="utf-8")
    current = attach._codex_current_hook_hashes(home)
    lines = list(base)
    for event, digest in current.items():
        key = f"blackbox@agent-blackbox:hooks/hooks.json:{event}:0:0"
        lines.extend(
            [
                f'[hooks.state."{key}"]',
                f'trusted_hash = "{digest}"',
                *(["enabled = false"] if event == "stop" else []),
            ]
        )
    config.write_text("\n".join(lines) + "\n", encoding="utf-8")

    assert attach._codex_hooks_trusted(home) is False


# ---------------------------------------------------------------------------
# Session-start auto-attach (hooks) — keeps later-installed agents protected
# ---------------------------------------------------------------------------


def test_auto_attach_due_stamps_and_throttles(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "ghome"))
    assert hooks._auto_attach_due() is True
    assert hooks._auto_attach_due() is False  # inside the interval


def test_auto_attach_due_runs_immediately_when_target_set_changes(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "ghome"))
    targets = [tmp_path / ".hermes"]
    monkeypatch.setattr(attach, "discover_hermes_homes", lambda: list(targets))
    monkeypatch.setattr(attach, "discover_openclaw_workspaces", lambda: [])
    monkeypatch.setattr(attach, "discover_claude_homes", lambda: [])
    monkeypatch.setattr(attach, "discover_codex_homes", lambda: [])

    assert hooks._auto_attach_due() is True
    assert hooks._auto_attach_due() is False

    targets.append(tmp_path / ".hermes" / "profiles" / "new")
    assert hooks._auto_attach_due() is True


def test_auto_attach_due_detects_new_external_agent(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "ghome"))
    codex_homes = []
    monkeypatch.setattr(attach, "discover_hermes_homes", lambda: [])
    monkeypatch.setattr(attach, "discover_openclaw_workspaces", lambda: [])
    monkeypatch.setattr(attach, "discover_claude_homes", lambda: [])
    monkeypatch.setattr(attach, "discover_codex_homes", lambda: list(codex_homes))

    assert hooks._auto_attach_due() is True
    assert hooks._auto_attach_due() is False

    codex_homes.append(tmp_path / ".codex")
    assert hooks._auto_attach_due() is True


def test_session_start_spawns_attach_sweep_once(tmp_path, monkeypatch):
    import threading

    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "ghome"))
    ran = threading.Event()
    monkeypatch.setattr(
        attach, "attach_all", lambda **kw: (ran.set(), {"hermes": [], "openclaw": []})[1]
    )
    monkeypatch.setattr(hooks, "_config", lambda: config_mod.BlackboxConfig())

    hooks.on_session_start(session_id="s1")
    assert ran.wait(5), "auto-attach sweep did not run"

    ran.clear()
    hooks.on_session_start(session_id="s2")  # throttled — same interval
    assert not ran.wait(0.5)


def test_auto_attach_disabled_via_config(tmp_path, monkeypatch):
    import threading

    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "ghome"))
    ran = threading.Event()
    monkeypatch.setattr(attach, "attach_all", lambda **kw: ran.set())
    monkeypatch.setattr(hooks, "_config", lambda: config_mod.BlackboxConfig(auto_attach=False))

    hooks.on_session_start(session_id="s1")
    assert not ran.wait(0.5)
    # Disabled runs must not stamp the throttle file either.
    assert not (tmp_path / "ghome" / "auto_attach.json").exists()


def test_auto_attach_env_override(monkeypatch):
    monkeypatch.setenv("BLACKBOX_AUTO_ATTACH", "0")
    assert config_mod.load_blackbox_config().auto_attach is False
    monkeypatch.setenv("BLACKBOX_AUTO_ATTACH", "1")
    assert config_mod.load_blackbox_config().auto_attach is True
