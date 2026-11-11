"""Tests for ``blackbox attach`` / ``blackbox detach`` discovery + merge logic."""

import json
from pathlib import Path

import pytest
try:
    import hermes_yaml as yaml  # Hermes 0.21.7+ reads YAML through ruamel
except ImportError:  # older Hermes
    import yaml

from _blackbox_loader import load_blackbox


attach = load_blackbox("attach")
attach_openclaw_bridge = load_blackbox("attach.openclaw_bridge")
attach_plugin_copy = load_blackbox("attach.plugin_copy")
constants = load_blackbox("kernel.constants")
hooks = load_blackbox("guard.hooks")
guard_background = load_blackbox("guard.background")
config_mod = load_blackbox("kernel.config")


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


@pytest.mark.parametrize("name", ["agent-blackbox", "blackbox"])
def test_discover_hermes_homes_skips_managed_blackbox_chat_profile(fake_env, name):
    """KI-479: the assistant's profile is ``agent-blackbox``; the list looked only for ``blackbox``."""
    blackbox = fake_env["hermes_default"] / "profiles" / name
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

    monkeypatch.setattr(attach_plugin_copy, "_bundle_openclaw_plugin", lambda _src, _dest: None)
    attach_plugin_copy.copy_plugin_tree(src, dest)

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
    # KI-182 port: the bridge shares with the same community under the same gates — the
    # switch and the cap travel with the attach. The community lives in contextGraphId's
    # shared memory (one graph since 2026-10-16), so no second graph travels with it.
    for key in ("report", "dailyReportLimit", "reportMinSeverity"):
        assert key in entry["config"], key
    assert not {"communityGraphId", "communityGraphPeerId"} & set(entry["config"])
    assert entry["config"]["report"] is False and entry["config"]["dailyReportLimit"] >= 1   # opt-in (2026-10-16)
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
    # The comments cannot survive a JSON rewrite: the operator is told, and the copy keeps them.
    assert "comments" in report["note"] and "openclaw.json.blackbox.bak" in report["note"]
    assert "// OpenClaw accepts JSON5." in (ws / "openclaw.json.blackbox.bak").read_text(encoding="utf-8")


def test_detach_openclaw_keeps_a_copy_and_never_overwrites_the_attach_copy(fake_env):
    """Detach rewrote the operator's config with no copy at all (attach keeps one); a JSON5
    config's comments were then gone for good. Detach now keeps its own copy, under a name
    that never replaces the copy attach kept of the config from before Blackbox."""
    ws = fake_env["openclaw_ws"]
    (ws / "openclaw.json").write_text("{\n  // mine\n  customFlag: true,\n}\n", encoding="utf-8")
    attach.attach_openclaw(ws)
    before_blackbox = (ws / "openclaw.json.blackbox.bak").read_text(encoding="utf-8")
    attached = (ws / "openclaw.json").read_text(encoding="utf-8")

    report = attach.detach_openclaw(ws)

    assert report["ok"] and report["backed_up"]
    assert (ws / "openclaw.json.before-blackbox-detach.bak").read_text(encoding="utf-8") == attached
    assert (ws / "openclaw.json.blackbox.bak").read_text(encoding="utf-8") == before_blackbox
    assert "note" not in report   # the attached file was plain JSON: nothing was lost this time


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
    assert any(attach_openclaw_bridge._same_openclaw_load_path(path, attach_openclaw_bridge._openclaw_load_paths_entry()) for path in paths)


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
    attach_plugin_copy.copy_plugin_tree(attach_plugin_copy._plugin_source_dir(), dest)
    bundle = dest / "_openclaw"
    assert (bundle / "openclaw.plugin.json").is_file()
    assert (bundle / "src" / "index.ts").is_file()
    assert not (bundle / "node_modules").exists()  # deps excluded from the bundle


def test_copy_plugin_tree_bundles_from_explicit_checkout_source(tmp_path, monkeypatch):
    """Fresh installed-plugin execution must not depend on its own marker yet."""
    repo = tmp_path / "checkout"
    src = repo / "plugins" / "blackbox"
    integration = repo / "integrations" / "openclaw"
    src.mkdir(parents=True)
    integration.mkdir(parents=True)
    (repo / ".git").mkdir()
    (src / "__init__.py").write_text("", encoding="utf-8")
    (src / "kernel").mkdir()
    (src / "kernel" / "constants.py").write_text("__version__ = '1.0.0'\n", encoding="utf-8")
    (integration / "openclaw.plugin.json").write_text('{"id":"blackbox"}\n', encoding="utf-8")
    (integration / "index.ts").write_text("export {};\n", encoding="utf-8")
    monkeypatch.setattr(attach_plugin_copy, "_repo_openclaw_dir", lambda: tmp_path / "missing")

    dest = tmp_path / "installed" / "plugins" / "blackbox"
    attach_plugin_copy.copy_plugin_tree(src, dest)

    assert (dest / "_openclaw" / "openclaw.plugin.json").is_file()
    assert (dest / ".blackbox-install-stamp").is_file()


def test_openclaw_load_path_resolves_from_installed_copy(tmp_path, monkeypatch):
    # Regression for the attach failure: when Blackbox runs from an installed
    # copy (no sibling repo), the load path must resolve to the BUNDLED plugin,
    # not return None — None made attach_openclaw report ok=False ("Attach
    # failed") for every installed user.
    installed = tmp_path / "plugins" / "blackbox"
    attach_plugin_copy.copy_plugin_tree(attach_plugin_copy._plugin_source_dir(), installed)  # bundles _openclaw
    monkeypatch.setattr(attach_plugin_copy, "_plugin_source_dir", lambda: installed)
    # repo_root is now tmp_path — no integrations/openclaw there.
    assert not (attach_plugin_copy.repo_root() / "integrations" / "openclaw").exists()
    assert attach_openclaw_bridge._openclaw_load_paths_entry() == str(installed / "_openclaw")


def test_openclaw_plugin_source_none_without_bundle_or_repo(tmp_path, monkeypatch):
    # A bare copy with neither a bundle nor a repo sibling resolves to None (an
    # honest "unprotected"), never a crash.
    bare = tmp_path / "plugins" / "blackbox"
    bare.mkdir(parents=True)
    monkeypatch.setattr(attach_plugin_copy, "_plugin_source_dir", lambda: bare)
    assert attach_openclaw_bridge._openclaw_load_paths_entry() is None


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
    report = attach.attach_all(auto_attach=True)   # the opted-in sweep joins every target
    assert report["count"] >= 2  # at least default home + openclaw ws
    assert all(row["ok"] for row in report["hermes"])
    assert all(row["ok"] for row in report["openclaw"])


# ---------------------------------------------------------------------------
# Session-start auto-attach (hooks) — keeps later-installed agents protected
# ---------------------------------------------------------------------------


def test_auto_attach_due_stamps_and_throttles(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "ghome"))
    assert guard_background._auto_attach_due() is True
    assert guard_background._auto_attach_due() is False  # inside the interval


def test_auto_attach_due_runs_immediately_when_target_set_changes(tmp_path, monkeypatch):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "ghome"))
    targets = [tmp_path / ".hermes"]
    monkeypatch.setattr(attach, "discover_hermes_homes", lambda: list(targets))
    monkeypatch.setattr(attach, "discover_openclaw_workspaces", list)

    assert guard_background._auto_attach_due() is True
    assert guard_background._auto_attach_due() is False

    targets.append(tmp_path / ".hermes" / "profiles" / "new")
    assert guard_background._auto_attach_due() is True


def test_session_start_spawns_attach_sweep_once(tmp_path, monkeypatch):
    import threading

    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "ghome"))
    ran = threading.Event()
    monkeypatch.setattr(
        attach, "attach_all", lambda **kw: (ran.set(), {"hermes": [], "openclaw": []})[1]
    )
    monkeypatch.setattr(hooks, "_config", lambda: config_mod.BlackboxConfig(auto_attach=True))   # opted in

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


@pytest.fixture
def installed_copy(tmp_path, monkeypatch):
    """A source plugin tree and an installed copy stamped at t=1000."""
    import os

    src = tmp_path / "src"
    (src / "dashboard" / "static").mkdir(parents=True)
    (src / "__init__.py").write_text("", encoding="utf-8")
    (src / "dashboard" / "static" / "index.html").write_text("<html>", encoding="utf-8")
    (src / "__pycache__").mkdir()
    (src / "__pycache__" / "x.pyc").write_bytes(b"")
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "__init__.py").write_text("", encoding="utf-8")
    (dest / ".blackbox-install-stamp").write_text("v", encoding="utf-8")
    for path in [*src.rglob("*"), *dest.rglob("*")]:
        if path.is_file():
            os.utime(path, (1000, 1000))
    monkeypatch.setattr(attach_plugin_copy, "_plugin_source_dir", lambda: src)
    monkeypatch.setattr(attach_plugin_copy, "_installed_plugin_version", lambda _dest: constants.__version__)
    monkeypatch.setattr(attach_plugin_copy, "_is_openclaw_plugin_dir", lambda _path: True)
    return src, dest


def test_installed_copy_is_current_when_nothing_changed(installed_copy):
    _src, dest = installed_copy

    assert attach_plugin_copy._needs_copy(dest) is False


def test_dashboard_only_change_refreshes_installed_copy(installed_copy):
    """Regression: only *.py mtimes were compared, so an index.html-only fix
    never reached existing installs (the served dashboard stayed stale)."""
    import os

    src, dest = installed_copy
    os.utime(src / "dashboard" / "static" / "index.html", (2000, 2000))

    assert attach_plugin_copy._needs_copy(dest) is True


def test_excluded_build_artifacts_do_not_trigger_refresh(installed_copy):
    import os

    src, dest = installed_copy
    os.utime(src / "__pycache__" / "x.pyc", (2000, 2000))

    assert attach_plugin_copy._needs_copy(dest) is False


# ---------------------------------------------------------------------------
# The operator's switch-off sticks (2026-10-15 dashboard audit: unticking an
# agent in Local agents was undone by the next background rescan)
# ---------------------------------------------------------------------------


def _protected(home):
    return attach.enabled_list_has(yaml.safe_load((home / "config.yaml").read_text(encoding="utf-8")), "blackbox")


def test_a_switched_off_hermes_home_is_skipped_by_the_automatic_sweep(fake_env, monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    profile = fake_env["profile"]
    attach.attach_all(openclaw=False, auto_attach=True)
    assert _protected(profile)

    attach.detach_hermes(profile)
    assert attach.is_declined("hermes", profile)
    attach.attach_all(openclaw=False, auto_attach=True)   # the timer's sweep

    assert not _protected(profile)
    assert _protected(fake_env["hermes_default"])  # the others are still kept protected


def test_an_explicit_attach_turns_it_back_on_and_forgets_the_switch_off(fake_env, monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    profile = fake_env["profile"]
    attach.attach_hermes(profile)
    attach.detach_hermes(profile)

    attach.attach_all(openclaw=False, explicit=True)   # `blackbox attach`

    assert _protected(profile) and not attach.is_declined("hermes", profile)


def test_a_switch_off_named_through_a_symlink_is_the_same_agent(fake_env, monkeypatch, tmp_path):
    """The switch-off record keyed a target by ``~`` expansion only while the sweep matched by
    the resolved folder: a home named through a symlink was switched off under one id and
    checked under another, so the record neither held nor cleared."""
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    profile = fake_env["profile"]
    alias = tmp_path / "profile-link"
    alias.symlink_to(profile, target_is_directory=True)

    attach.detach_hermes(alias)
    assert attach.is_declined("hermes", profile)
    attach.attach_hermes(profile)
    assert not attach.is_declined("hermes", alias)


def test_a_switch_off_recorded_before_the_resolved_spelling_still_holds(fake_env, monkeypatch, tmp_path):
    """Records written before targets were keyed by their resolved folder keep working: a sweep
    must never re-attach an agent the operator switched off because its spelling changed."""
    import json
    from pathlib import Path
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    alias = tmp_path / "profile-link"
    alias.symlink_to(fake_env["profile"], target_is_directory=True)
    (tmp_path / "bb").mkdir()
    (tmp_path / "bb" / "attach_declined.json").write_text(
        json.dumps({"targets": [f"hermes:{Path(str(alias)).expanduser()}"]}), encoding="utf-8")
    assert attach.is_declined("hermes", alias)
    attach.attach_hermes(alias)
    assert not attach.is_declined("hermes", alias)


def test_a_dry_run_detach_records_nothing(fake_env, monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    attach.attach_hermes(fake_env["profile"])
    attach.detach_hermes(fake_env["profile"], dry_run=True)
    assert not attach.is_declined("hermes", fake_env["profile"])


def test_a_switched_off_openclaw_workspace_is_skipped_by_the_automatic_sweep(fake_env, monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    workspace = fake_env["openclaw_ws"]
    attach.attach_openclaw(workspace)
    attach.detach_openclaw(workspace)

    report = attach.attach_all(hermes=False)

    assert report["openclaw"] == [] and attach.is_declined("openclaw", workspace)
    assert "blackbox" not in json.loads((workspace / "openclaw.json").read_text(encoding="utf-8"))["plugins"].get("allow", [])


def test_the_dashboard_rescan_keeps_an_agent_the_operator_switched_off(fake_env, monkeypatch, tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    server = load_blackbox("dashboard.server")
    profile = fake_env["profile"]
    attach.attach_hermes(profile)
    with TestClient(server.create_app(), base_url="http://127.0.0.1:9700") as client:
        token = {"X-Blackbox-Token": client.get("/api/session").json()["token"]}
        off = client.post("/api/agents/protection", json={"targets": [{"kind": "hermes", "target": str(profile), "enabled": False}]},
                          headers=token)
        assert off.status_code == 200
        client.post("/api/agents/rescan", headers=token)   # ↻ — a forced reconcile of every agent

    assert not _protected(profile)


# ---------------------------------------------------------------------------
# Attaching is the operator's choice (Hermes catalog review of 22cb7e62):
# each Hermes profile is its own trust and credential boundary, so
# auto_attach is opt-in and `blackbox attach` joins only named homes, or
# every one after --all / a terminal "yes".
# ---------------------------------------------------------------------------

attach_command = load_blackbox("attach.command")
cli = load_blackbox("cli")


def test_auto_attach_is_off_by_default(fake_env, monkeypatch):
    monkeypatch.delenv("BLACKBOX_AUTO_ATTACH", raising=False)
    assert config_mod.BlackboxConfig().auto_attach is False
    assert config_mod.load_blackbox_config().auto_attach is False


def test_with_the_default_config_a_session_start_attaches_nothing(tmp_path, monkeypatch):
    import threading

    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "ghome"))
    ran = threading.Event()
    monkeypatch.setattr(attach, "attach_all", lambda **kw: ran.set())
    monkeypatch.setattr(hooks, "_config", lambda: config_mod.BlackboxConfig())

    hooks.on_session_start(session_id="s1")

    assert not ran.wait(0.5)


def _targets(fake_env):
    return {("hermes", str(fake_env["hermes_default"])), ("hermes", str(fake_env["profile"])),
            ("openclaw", str(fake_env["openclaw_ws"]))}


def test_opted_out_the_automatic_sweep_attaches_nothing_new(fake_env, monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    attach.attach_hermes(fake_env["hermes_default"])
    found = _targets(fake_env)

    assert attach.automatic_targets(found, set(), reconcile=False, auto_attach=False) == set()
    # A reconcile keeps only what is already attached current — never adds the profile or the workspace.
    assert attach.automatic_targets(found, found, reconcile=True, auto_attach=False) == {("hermes", str(fake_env["hermes_default"]))}


def test_opted_in_the_sweep_adds_new_agents_but_never_a_switched_off_one(fake_env, monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    attach.attach_hermes(fake_env["profile"])
    attach.detach_hermes(fake_env["profile"])
    found = _targets(fake_env)

    new = attach.automatic_targets(found, {("hermes", str(fake_env["hermes_default"]))}, reconcile=False, auto_attach=True)
    every = attach.automatic_targets(found, found, reconcile=True, auto_attach=True)

    assert new == {("openclaw", str(fake_env["openclaw_ws"]))}
    assert every == found - {("hermes", str(fake_env["profile"]))}


@pytest.mark.parametrize("auto_attach", [False, True])
def test_the_dashboard_refresh_adds_an_agent_only_when_opted_in(fake_env, monkeypatch, tmp_path, auto_attach):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setenv("BLACKBOX_AUTO_ATTACH", "1" if auto_attach else "0")
    server = load_blackbox("dashboard.server")
    attach.attach_hermes(fake_env["hermes_default"])
    with TestClient(server.create_app(), base_url="http://127.0.0.1:9700") as client:
        token = {"X-Blackbox-Token": client.get("/api/session").json()["token"]}
        assert client.post("/api/agents/rescan", headers=token).status_code == 200   # ↻ — a forced reconcile

    assert _protected(fake_env["hermes_default"])           # what the operator chose stays protected
    assert (fake_env["profile"] / "config.yaml").exists() is auto_attach
    if auto_attach:
        assert _protected(fake_env["profile"])


def test_opted_in_the_dashboard_rescan_still_keeps_a_switched_off_agent_off(fake_env, monkeypatch, tmp_path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient

    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setenv("BLACKBOX_AUTO_ATTACH", "1")
    server = load_blackbox("dashboard.server")
    attach.attach_hermes(fake_env["profile"])
    attach.detach_hermes(fake_env["profile"])
    with TestClient(server.create_app(), base_url="http://127.0.0.1:9700") as client:
        token = {"X-Blackbox-Token": client.get("/api/session").json()["token"]}
        client.post("/api/agents/rescan", headers=token)

    assert not _protected(fake_env["profile"])


def _run_attach(monkeypatch, capsys, *argv):
    import argparse

    parser = argparse.ArgumentParser(prog="blackbox")
    cli.setup_cli(parser)
    args = parser.parse_args(["attach", *argv])
    code = args.func(args)
    return code, capsys.readouterr().out


def test_attach_with_a_named_home_protects_only_that_home(fake_env, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    code, _ = _run_attach(monkeypatch, capsys, str(fake_env["profile"]))

    assert code == 0 and _protected(fake_env["profile"])
    assert not _protected(fake_env["hermes_default"])
    assert "blackbox" not in json.loads((fake_env["openclaw_ws"] / "openclaw.json").read_text(encoding="utf-8"))["plugins"].get("allow", [])


def test_attach_with_a_path_that_is_no_agent_changes_nothing_and_fails(fake_env, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    stray = tmp_path / "not-an-agent"
    stray.mkdir()

    code, out = _run_attach(monkeypatch, capsys, str(stray))

    assert code == 1 and "not a Hermes home or OpenClaw workspace" in out
    assert not (stray / "config.yaml").exists() and not (stray / "plugins").exists()


def test_attach_all_protects_every_agent_found(fake_env, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    code, _ = _run_attach(monkeypatch, capsys, "--all")

    assert code == 0 and _protected(fake_env["hermes_default"]) and _protected(fake_env["profile"])


def test_a_bare_attach_with_no_terminal_lists_and_attaches_nothing(fake_env, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setattr(attach_command, "_ask_terminal", lambda prompt: None)

    code, out = _run_attach(monkeypatch, capsys)

    assert code == 1
    assert str(fake_env["profile"]) in out and "blackbox attach --all" in out
    assert not _protected(fake_env["hermes_default"]) and not (fake_env["profile"] / "config.yaml").exists()


@pytest.mark.parametrize("answer, protected", [("y\n", True), ("\n", False), ("no\n", False)])
def test_a_bare_attach_on_a_terminal_protects_every_agent_only_on_yes(fake_env, monkeypatch, tmp_path, capsys,
                                                                       answer, protected):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setattr(attach_command, "_ask_terminal", lambda prompt: answer)

    code, _ = _run_attach(monkeypatch, capsys)

    assert code == 0 and _protected(fake_env["hermes_default"]) is protected


def test_a_bare_attach_asks_nothing_when_every_agent_is_protected(fake_env, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    attach.attach_all(explicit=True)
    monkeypatch.setattr(attach_command, "_ask_terminal", lambda prompt: pytest.fail("asked although nothing waits"))

    code, out = _run_attach(monkeypatch, capsys)

    assert code == 0 and "are protected" in out


def test_with_no_tty_and_no_controlling_terminal_nothing_is_asked(monkeypatch):
    import io

    def no_tty(*args, **kwargs):
        raise OSError("no controlling terminal")

    monkeypatch.setattr("sys.stdin", io.StringIO("y\n"))   # a pipe: never read as the operator's answer
    monkeypatch.setattr(attach_command, "open", no_tty, raising=False)

    assert attach_command._ask_terminal("Protect? ") is None


def test_a_profile_named_like_blackbox_without_the_managed_soul_is_listed(fake_env):
    """Only Blackbox's own managed profile is hidden; a person's profile of that name is an agent."""
    theirs = fake_env["hermes_default"] / "profiles" / "agent-blackbox"
    theirs.mkdir(parents=True)
    (theirs / "SOUL.md").write_text("# My own agent\n", encoding="utf-8")

    assert theirs in attach.discover_hermes_homes()


def test_the_chat_command_dashboard_and_agent_list_share_one_profile_name():
    from plugins.blackbox.chat import command as chat_command
    from plugins.blackbox.dashboard import server
    from plugins.blackbox.kernel import constants

    assert chat_command._BLACKBOX_CHAT_PROFILE == constants.BLACKBOX_CHAT_PROFILE
    assert server._BLACKBOX_PROFILE == constants.BLACKBOX_CHAT_PROFILE


# --- KI-492: an automatic sweep honours auto_attach itself (default off) ---

def test_an_automatic_sweep_joins_nothing_new_by_default(fake_env, monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))

    report = attach.attach_all()   # what `blackbox dashboard` runs at every login

    assert report["hermes"] == [] and report["openclaw"] == []
    assert not (fake_env["profile"] / "config.yaml").exists() and not _protected(fake_env["hermes_default"])


def test_an_automatic_sweep_refreshes_only_what_is_already_attached(fake_env, monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    attach.attach_hermes(fake_env["hermes_default"])   # the operator named this one

    report = attach.attach_all()

    assert [row["target"] for row in report["hermes"]] == [str(fake_env["hermes_default"])]
    assert not (fake_env["profile"] / "config.yaml").exists()


def test_the_saved_auto_attach_setting_opts_the_sweep_in(fake_env, monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))
    monkeypatch.setenv("BLACKBOX_AUTO_ATTACH", "true")

    attach.attach_all(openclaw=False)

    assert _protected(fake_env["profile"]) and _protected(fake_env["hermes_default"])


def test_a_dry_run_still_lists_every_target(fake_env, monkeypatch, tmp_path):
    monkeypatch.setenv("BLACKBOX_HOME", str(tmp_path / "bb"))

    report = attach.attach_all(dry_run=True)

    assert len(report["hermes"]) >= 2 and not (fake_env["profile"] / "config.yaml").exists()


def test_status_lists_attached_agents_with_attach_own_check(monkeypatch, tmp_path, capsys):
    """`blackbox status` kept its own "is it attached?" reading: plain JSON and a fixed file
    name. An OpenClaw config with comments, or one named by $OPENCLAW_CONFIG_PATH, was attached
    and shown as not attached."""
    from plugins.blackbox import attach, cli

    commented = tmp_path / "workspace"
    commented.mkdir()
    (commented / "openclaw.json").write_text('{\n  // my agents\n  "plugins": {"allow": ["blackbox",],},\n}\n',
                                             encoding="utf-8")
    named_file = tmp_path / "custom-openclaw.json5"
    named_file.write_text('{"plugins": {"allow": ["blackbox"]}}', encoding="utf-8")
    off = tmp_path / "off"
    off.mkdir()
    (off / "openclaw.json").write_text('{"plugins": {"allow": ["other"]}}', encoding="utf-8")
    home = tmp_path / "hermes-home"
    home.mkdir()
    (home / "config.yaml").write_text("plugins:\n  enabled:\n    - blackbox\n", encoding="utf-8")
    monkeypatch.setattr(attach, "discover_hermes_homes", lambda: [home])
    monkeypatch.setattr(attach, "discover_openclaw_workspaces", lambda: [commented, named_file, off])
    cli._print_attached_targets()
    out = capsys.readouterr().out
    assert "attached (hermes): 1" in out and str(home) in out
    assert "attached (openclaw): 2" in out and str(commented) in out and str(named_file) in out
    assert str(off) not in out


def test_detach_exits_non_zero_when_a_target_failed(monkeypatch, capsys):
    """`blackbox attach` exits 1 when a target failed; `detach` said 0 whatever happened."""
    import argparse

    from plugins.blackbox import attach
    from plugins.blackbox.attach import command

    report = {"hermes": [{"target": "/h", "error": "config.yaml cannot be read"}], "openclaw": []}
    monkeypatch.setattr(attach, "detach_all", lambda **kw: report)
    args = argparse.Namespace(openclaw_only=False, hermes_only=False, remove_files=False, dry_run=False)
    assert command.cmd_detach(args) == 1
    report["hermes"] = [{"target": "/h", "disabled": True}]
    assert command.cmd_detach(args) == 0


def test_a_hermes_attach_that_changed_something_says_so_and_a_repeat_does_not(fake_env):
    """The automatic attach writes an audit record for every target whose report says `changed`.
    OpenClaw reports set it; Hermes reports never did, so attaching a Hermes home automatically
    was never recorded."""
    home = fake_env["hermes_default"]
    assert attach.attach_hermes(home)["changed"] is True
    assert attach.attach_hermes(home)["changed"] is False
    assert attach.attach_hermes(fake_env["hermes_profile"] if "hermes_profile" in fake_env else home,
                                dry_run=True)["changed"] is False
